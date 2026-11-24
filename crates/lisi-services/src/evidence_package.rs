//! Il pacchetto di evidenze (PR-11, ADR-0127).
//!
//! # Che cosa è, e che cosa non è
//!
//! Un pacchetto unico, esportabile e verificabile, con i contenuti **scelti da
//! una persona** in un workspace e tutto ciò che serve a un terzo per capire da
//! dove vengono. [`NOT_FORENSIC`] dice che cosa **non** è, ed è la sola frase del
//! modulo in cui la parola compare: una guardia lo verifica.
//!
//! # Le difese dell'uscita
//!
//! - **Nomi costanti**: nessun nome di file deriva da testo dell'operatore o
//!   della fonte; la cartella si chiama con l'istante UTC in cifre. Un
//!   attraversamento di percorso non si filtra: è irrapresentabile.
//! - **Nessuna sovrascrittura**: la cartella si crea soltanto se non esiste, ogni
//!   file soltanto se non esiste; se qualcosa fallisce si tolgono i soli file
//!   scritti.
//! - **Testi puliti**: i caratteri di controllo e quelli che invertono la
//!   direzione della scrittura si tolgono; la tabella apre con un apostrofo ogni
//!   cella che comincia come una formula.
//! - **Selezione verificata**: ogni contenuto scelto deve stare nel workspace, e
//!   nulla che non sia stato scelto entra.
//! - **Nessun percorso della macchina, nessun segreto**: i file escono da campi
//!   dichiarati, e una prova negativa lo verifica sul pacchetto prodotto.
//!
//! # Dove si produce
//!
//! Chi ha i fatti produce i documenti (TEAM-REPORT-01): la richiesta vuole la
//! prova di averli — l'autorità di acquisizione, oppure in Esercitazione il
//! testimone dell'esercitazione (PR-13) —, e su un client Team **non compila**:
//!
//! ```compile_fail
//! use lisi_core::model::reason::OperationalReason;
//! use lisi_core::text::Actor;
//! use lisi_core::{ContentId, WorkspaceId};
//! use lisi_services::evidence_package::EvidenceRequest;
//!
//! fn da_un_client(chi: Actor, perche: OperationalReason) {
//!     let _ = EvidenceRequest::new(WorkspaceId::new(1), &[ContentId::new(1)], chi, perche);
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use lisi_core::model::coverage::COVERAGE_MEANING;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::workspace::ArchiveRefKind;
use lisi_core::model::{AcquisitionMode, Content, NewAuditEntry};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{ContentId, ReportPackageId, Sha256Digest, SourceId, Timestamp, WorkspaceId};
use lisi_storage::Database;
use lisi_storage::repository::evidence_package::NewEvidencePackage;

use crate::acquisition_authority::HoldsTheFacts;
use crate::error::{ServiceError, ServiceResult};
use crate::protected_output::{CurrentUser, ProtectedFolder, REFUSED_AUDIT_ACTION, record_refusal};

/// Ciò che si dice quando il pacchetto non si scrive per i permessi.
const EVIDENCE_NOT_WRITTEN: &str = "Il pacchetto di evidenze NON è stato scritto";

/// Al più tanti contenuti per pacchetto.
pub const MAX_CONTENTS: usize = 500;

/// Che cosa il pacchetto **non** è. La sola frase del modulo con quella parola.
///
/// È il testo corrente del messaggio di sicurezza **SIC-16**: la schermata e il
/// documento di lettura dicono la stessa frase, registrata e versionata.
pub const NOT_FORENSIC: &str = lisi_core::security_messages::EVIDENCE_NOT_FORENSIC
    .current
    .text;

/// La salvaguardia interpretativa, per intero.
pub const INTERPRETIVE_SAFEGUARD: &str = "Nessun contenuto di questo pacchetto equipara di per \
     sé il dissenso politico, una manifestazione lecita, un'appartenenza o un'opinione a un \
     illecito o a una pericolosità. Ogni valutazione su una persona è di un operatore, con motivo \
     e istante, e resta nel registro delle operazioni.";

/// L'integrità, non l'autenticazione.
pub const INTEGRITY_NOT_SIGNATURE: &str = "Il manifest è un'impronta, non una firma. Dice che i \
     file sono byte per byte quelli prodotti; non dice chi li ha prodotti, e chi possiede file e \
     manifest può rifarli entrambi.";

/// L'azione d'audit di un pacchetto prodotto.
pub const EVIDENCE_AUDIT_ACTION: &str = "pacchetto_di_evidenze_prodotto";

/// Il documento di lettura.
pub const READING_FILE: &str = "LEGGIMI.txt";
/// I contenuti, per esteso.
pub const CONTENTS_FILE: &str = "contenuti.txt";
/// I contenuti, in tabella.
pub const TABLE_FILE: &str = "contenuti.csv";
/// La copertura.
pub const COVERAGE_FILE: &str = "copertura.txt";
/// I documenti riferiti.
pub const DOCUMENTS_FILE: &str = "documenti.txt";
/// Il manifest, ultimo file scritto.
pub const MANIFEST_FILE: &str = "manifest.txt";

/// Ciò che il manifest dice degli allegati, prima di elencarli (ATTACH-01).
pub const ATTACHMENTS_WARNING: &str = "Gli allegati sono i file così come Telegram li ha \
     dati. Il programma non li ha aperti né esaminati, e conservarli non vuol dire che siano \
     innocui. Il nome e il tipo li ha dichiarati chi ha pubblicato: non dicono che cosa c'è nel \
     file. Per questo ogni allegato si chiama con la sua impronta. Aprirlo, se serve, su una \
     macchina isolata.";

/// La richiesta. **Vuole la prova di avere i fatti e una ragione.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRequest {
    workspace_id: WorkspaceId,
    selected: Vec<ContentId>,
    operator: Actor,
    reason: OperationalReason,
    /// Se gli allegati conservati dei contenuti scelti escono anche loro
    /// (ATTACH-01, ADR-0177, decisione 9). Per difetto no.
    kept_attachments: bool,
}

impl EvidenceRequest {
    /// Fa uscire anche gli allegati conservati dei contenuti scelti, ciascuno
    /// come `<impronta>.bin`. Lo sceglie l'operatore: per difetto non escono.
    #[must_use]
    pub const fn with_kept_attachments(mut self) -> Self {
        self.kept_attachments = true;
        self
    }

    /// Costruisce la richiesta. La selezione si tiene nell'ordine dato, senza
    /// doppioni.
    ///
    /// # Errori
    ///
    /// Restituisce la frase del rifiuto per una selezione vuota o oltre
    /// [`MAX_CONTENTS`].
    pub fn new(
        _chi_ha_i_fatti: &impl HoldsTheFacts,
        workspace_id: WorkspaceId,
        selected: &[ContentId],
        operator: Actor,
        reason: OperationalReason,
    ) -> Result<Self, &'static str> {
        let mut visti = BTreeSet::new();
        let selected: Vec<ContentId> = selected
            .iter()
            .copied()
            .filter(|contenuto| visti.insert(contenuto.get()))
            .collect();
        if selected.is_empty() {
            return Err("Nessun contenuto scelto: il pacchetto non si produce.");
        }
        if selected.len() > MAX_CONTENTS {
            return Err("Al più cinquecento contenuti per pacchetto: la scelta va ristretta.");
        }
        Ok(Self {
            workspace_id,
            selected,
            operator,
            reason,
            kept_attachments: false,
        })
    }
}

/// Un contenuto dell'anteprima.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRow {
    /// Quale.
    pub content_id: ContentId,
    /// Da quale fonte.
    pub source_name: String,
    /// Quando pubblicato.
    pub published_at: Timestamp,
}

/// Che cosa entrerà, **prima** di produrre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    /// I contenuti scelti, nell'ordine.
    pub rows: Vec<PreviewRow>,
    /// Da quante fonti.
    pub sources: usize,
    /// Quanti contenuti del workspace restano fuori.
    pub left_out: usize,
    /// Quanti rapporti del workspace si riferiscono.
    pub reports: usize,
}

impl Preview {
    /// La frase dell'anteprima.
    #[must_use]
    ///
    /// Concordata col numero (UX-EXCELLENCE-02, SIM3-17): diceva «Entreranno 1
    /// contenuti da 1 fonti».
    pub fn sentence(&self) -> String {
        let entrano = match self.rows.len() {
            1 => String::from("Entrerà 1 contenuto"),
            quanti => format!("Entreranno {quanti} contenuti"),
        };
        let fonti = match self.sources {
            1 => String::from("da 1 fonte"),
            quante => format!("da {quante} fonti"),
        };
        let fuori = match self.left_out {
            0 => String::from("Non ne resta fuori nessuno del raccoglitore."),
            1 => String::from("Ne resta fuori 1 del raccoglitore."),
            quanti => format!("Ne restano fuori {quanti} del raccoglitore."),
        };
        let rapporti = match self.reports {
            0 => String::from("Nessun rapporto vi si riferisce."),
            1 => String::from("Si riferisce 1 rapporto, senza copiarlo."),
            quanti => format!("Si riferiscono {quanti} rapporti, senza copiarli."),
        };
        format!("{entrano} {fonti}. {fuori} {rapporti}")
    }
}

/// Che cosa il workspace riferisce: i contenuti e i rapporti.
fn workspace_refs(
    database: &Database,
    workspace_id: WorkspaceId,
) -> ServiceResult<(Vec<i64>, Vec<i64>)> {
    let mut contenuti = Vec::new();
    let mut rapporti = Vec::new();
    for elemento in database.workspace_items(workspace_id)? {
        match elemento.entry.item.kind() {
            ArchiveRefKind::Content => contenuti.push(elemento.entry.item.target_id()),
            ArchiveRefKind::Report => rapporti.push(elemento.entry.item.target_id()),
            _ => {}
        }
    }
    Ok((contenuti, rapporti))
}

/// L'anteprima: verifica che ogni contenuto scelto stia nel workspace.
///
/// # Errori
///
/// Restituisce [`ServiceError::ExportNotWritten`] se un contenuto scelto non è
/// nel workspace, e un errore se una lettura non riesce.
pub fn preview(database: &Database, richiesta: &EvidenceRequest) -> ServiceResult<Preview> {
    preview_selection(database, richiesta.workspace_id, &richiesta.selected)
}

/// La stessa anteprima, mentre la scelta si sta facendo: **non produce nulla**,
/// e per questo non chiede l'autorità.
///
/// # Errori
///
/// Come [`preview`].
pub fn preview_selection(
    database: &Database,
    workspace_id: WorkspaceId,
    scelti: &[ContentId],
) -> ServiceResult<Preview> {
    let (nel_workspace, rapporti) = workspace_refs(database, workspace_id)?;
    let ammessi: BTreeSet<i64> = nel_workspace.iter().copied().collect();
    let mut righe = Vec::new();
    let mut fonti = BTreeSet::new();
    for contenuto in scelti {
        if !ammessi.contains(&contenuto.get()) {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from(
                    "un contenuto scelto non sta nel raccoglitore: il pacchetto esce soltanto \
                     da ciò che il raccoglitore riferisce",
                ),
            });
        }
        let letto = database.content(*contenuto)?;
        fonti.insert(letto.source_id.get());
        righe.push(PreviewRow {
            content_id: *contenuto,
            source_name: source_name(database, letto.source_id),
            published_at: letto.published_at,
        });
    }
    Ok(Preview {
        left_out: ammessi.len().saturating_sub(righe.len()),
        rows: righe,
        sources: fonti.len(),
        reports: rapporti.len(),
    })
}

/// I pacchetti prodotti da un workspace, dal più recente: che cosa è uscito, e
/// quando.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn produced(
    database: &Database,
    workspace_id: WorkspaceId,
) -> ServiceResult<Vec<NewEvidencePackage>> {
    Ok(database.workspace_evidence_packages(workspace_id)?)
}

/// La cartella in cui escono i pacchetti: quella dei documenti dell'ufficio,
/// con una sottocartella propria.
///
/// # Errori
///
/// Restituisce un errore se la cartella dei documenti non è determinabile.
pub fn destination(database: &Database) -> ServiceResult<PathBuf> {
    Ok(crate::export::resolved_destination(database)?.join("pacchetti-di-evidenze"))
}

/// Il nome della fonte, o un segnaposto se non si legge più.
fn source_name(database: &Database, fonte: SourceId) -> String {
    database.source(fonte).map_or_else(
        |_| String::from("fonte non più disponibile"),
        |letta| letta.display_name.as_str().to_owned(),
    )
}

/// Un testo reso sicuro per un file: niente caratteri di controllo, niente
/// caratteri che invertono la direzione della scrittura.
fn clean(testo: &str) -> String {
    testo
        .chars()
        .filter(|carattere| {
            *carattere == '\n'
                || !(carattere.is_control()
                    || matches!(u32::from(*carattere), 0x202A..=0x202E | 0x2066..=0x2069))
        })
        .collect()
}

/// Una cella della tabella: pulita, protetta dalle formule, tra virgolette.
#[must_use]
pub fn csv_cell(testo: &str) -> String {
    let riga_sola = clean(testo).replace('\n', " ");
    let protetta = if riga_sola.starts_with(['=', '+', '-', '@']) {
        format!("'{riga_sola}")
    } else {
        riga_sola
    };
    format!("\"{}\"", protetta.replace('"', "\"\""))
}

/// Il modo di ogni contenuto scelto, per monitoraggio.
fn modes(
    database: &Database,
    contenuti: &[Content],
    now: Timestamp,
) -> ServiceResult<BTreeMap<i64, AcquisitionMode>> {
    let mut modi = BTreeMap::new();
    let sessioni: BTreeSet<i64> = contenuti
        .iter()
        .map(|contenuto| contenuto.session_id.get())
        .collect();
    for sessione in sessioni {
        modi.extend(crate::acquisition_mode::for_session(
            database,
            lisi_core::SessionId::new(sessione),
            now,
        )?);
    }
    Ok(modi)
}

/// Che cosa è uscito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceOutcome {
    /// L'identificativo del pacchetto, che è anche il nome della cartella.
    pub package_ref: String,
    /// La cartella.
    pub directory: PathBuf,
    /// I file, manifest compreso: nome, dimensione, impronta.
    pub files: Vec<(String, u64, String)>,
    /// L'utente Windows che solo può aprire la cartella del pacchetto (SEC-02).
    pub owner: CurrentUser,
}

/// L'identificativo del pacchetto: «PE-» e l'istante UTC in cifre.
#[must_use]
pub fn package_ref(now: Timestamp) -> String {
    let w3c = now.to_w3cdtf_utc();
    let cifre: String = w3c.chars().filter(char::is_ascii_digit).collect();
    let (data, ora) = cifre.split_at(cifre.len().min(8));
    format!("PE-{data}-{}", ora.get(..6).unwrap_or(ora))
}

/// Scrive un file **soltanto se non esiste**.
fn write_new(percorso: &Path, byte: &[u8]) -> ServiceResult<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(percorso)
        .map_err(|errore| ServiceError::ExportNotWritten {
            reason: format!("un file del pacchetto non si scrive: {}", errore.kind()),
        })?;
    file.write_all(byte)
        .map_err(|errore| ServiceError::ExportNotWritten {
            reason: format!("un file del pacchetto non si scrive: {}", errore.kind()),
        })
}

/// Produce il pacchetto nella cartella indicata, e lo registra.
///
/// # Errori
///
/// Restituisce un errore se la cartella non è assoluta, se il pacchetto esiste
/// già, se la selezione non sta nel workspace, se un file non si scrive o se il
/// registro non si aggiorna. In ogni caso di errore dopo la creazione della
/// cartella, i file scritti si tolgono.
pub fn produce(
    database: &mut Database,
    richiesta: &EvidenceRequest,
    parent: &Path,
    now: Timestamp,
) -> ServiceResult<EvidenceOutcome> {
    if !parent.is_absolute() {
        return Err(ServiceError::ExportNotWritten {
            reason: String::from("la cartella di destinazione deve essere un percorso completo"),
        });
    }
    let anteprima = preview(database, richiesta)?;
    let riferimento = package_ref(now);
    std::fs::create_dir_all(parent).map_err(|errore| ServiceError::ExportNotWritten {
        reason: format!("la cartella di destinazione non si crea: {}", errore.kind()),
    })?;
    // In Esercitazione la cartella porta il prefisso (PR-13, ADR-0129).
    let cartella = parent.join(crate::run_mode::file_name(&riferimento));
    // DEL SOLO UTENTE, O NIENTE (SEC-02, ADR-0157): la cartella del pacchetto si
    // restringe appena creata, prima del primo file, e si rilegge alla fine.
    let protetta = ProtectedFolder::create(&cartella, EVIDENCE_NOT_WRITTEN, |errore| {
        ServiceError::ExportNotWritten {
            reason: if errore.kind() == std::io::ErrorKind::AlreadyExists {
                format!("esiste già un pacchetto {riferimento}: non si sovrascrive")
            } else {
                format!("la cartella del pacchetto non si crea: {}", errore.kind())
            },
        }
    })
    .inspect_err(|errore| {
        record_refusal(
            database,
            &richiesta.operator,
            now,
            REFUSED_AUDIT_ACTION,
            "pacchetto_evidenze",
            errore,
        );
    })?;

    let mut scritti: Vec<PathBuf> = Vec::new();
    let esito = compose_and_write(
        database,
        richiesta,
        &anteprima,
        &riferimento,
        &cartella,
        now,
        &mut scritti,
    )
    // Prima di dichiararlo completo, la cartella si rilegge.
    .and_then(|file| protetta.seal().map(|()| file));
    match esito {
        Ok(file) => {
            let owner = protetta.owner().clone();
            protetta.release();
            Ok(EvidenceOutcome {
                package_ref: riferimento,
                directory: cartella,
                files: file,
                owner,
            })
        }
        Err(errore) => {
            for percorso in &scritti {
                let _ = std::fs::remove_file(percorso);
            }
            let _ = protetta.remove();
            record_refusal(
                database,
                &richiesta.operator,
                now,
                REFUSED_AUDIT_ACTION,
                "pacchetto_evidenze",
                &errore,
            );
            Err(errore)
        }
    }
}

/// Compone i file, li scrive, scrive il manifest per ultimo, e registra.
fn compose_and_write(
    database: &mut Database,
    richiesta: &EvidenceRequest,
    anteprima: &Preview,
    riferimento: &str,
    cartella: &Path,
    now: Timestamp,
    scritti: &mut Vec<PathBuf>,
) -> ServiceResult<Vec<(String, u64, String)>> {
    let mut contenuti = Vec::with_capacity(richiesta.selected.len());
    for id in &richiesta.selected {
        contenuti.push(database.content(*id)?);
    }
    let modi = modes(database, &contenuti, now)?;
    let workspace = database.workspace(richiesta.workspace_id)?;
    let (_, rapporti) = workspace_refs(database, richiesta.workspace_id)?;

    let file: Vec<(&str, String)> = vec![
        (
            READING_FILE,
            reading_document(
                richiesta,
                anteprima,
                riferimento,
                workspace.name.as_str(),
                now,
            ),
        ),
        (CONTENTS_FILE, contents_text(database, &contenuti, &modi)),
        (TABLE_FILE, contents_table(database, &contenuti, &modi)),
        (COVERAGE_FILE, coverage_text(database, &contenuti)?),
        (DOCUMENTS_FILE, documents_text(database, &rapporti)?),
    ];
    // In Esercitazione ogni file si apre con la frase di SIC-17, prima che se
    // ne calcoli l'impronta (PR-13, ADR-0129).
    let file: Vec<(&str, String)> = file
        .into_iter()
        .map(|(nome, testo)| (nome, crate::run_mode::marked_text(testo)))
        .collect();

    let mut elenco = Vec::with_capacity(file.len() + 1);
    for (nome, testo) in &file {
        let percorso = cartella.join(nome);
        write_new(&percorso, testo.as_bytes())?;
        scritti.push(percorso);
        elenco.push((
            (*nome).to_owned(),
            testo.len() as u64,
            Sha256Digest::of_bytes(testo.as_bytes()).as_str().to_owned(),
        ));
    }

    // GLI ALLEGATI, SE SCELTI (ATTACH-01, ADR-0177, decisione 9): i byte come
    // sono, senza la frase dell'Esercitazione, con il nome dell'impronta e mai
    // con quello dichiarato. L'impronta si ricontrolla sui byte prima di
    // scrivere: un allegato che non corrisponde ferma il pacchetto.
    let mut allegati = Vec::new();
    if richiesta.kept_attachments {
        for contenuto in &contenuti {
            let Some(conservato) = database.kept_attachment(contenuto.id)? else {
                continue;
            };
            let byte = database
                .kept_attachment_bytes(conservato.id)?
                .unwrap_or_default();
            let impronta = Sha256Digest::of_bytes(&byte);
            if byte.is_empty() || conservato.sha256.as_deref() != Some(impronta.as_str()) {
                return Err(ServiceError::ExportNotWritten {
                    reason: format!(
                        "l'allegato del contenuto {} non corrisponde alla sua impronta",
                        contenuto.id.get()
                    ),
                });
            }
            let nome = format!("{}.bin", impronta.as_str());
            let percorso = cartella.join(&nome);
            write_new(&percorso, &byte)?;
            scritti.push(percorso);
            let descrizione = database.content_attachment(contenuto.id)?;
            let dichiarato =
                |campo: Option<&str>| campo.map_or_else(|| String::from("non dichiarato"), clean);
            allegati.push(format!(
                "Allegato:   {nome}\nContenuto:  {}\nNome dichiarato: {}\nTipo dichiarato: {}\n",
                contenuto.id.get(),
                dichiarato(
                    descrizione
                        .as_ref()
                        .and_then(|d| d.declared_name.as_deref())
                ),
                dichiarato(
                    descrizione
                        .as_ref()
                        .and_then(|d| d.declared_mime.as_deref())
                ),
            ));
            elenco.push((nome, byte.len() as u64, impronta.as_str().to_owned()));
        }
    }

    // IL MANIFEST PER ULTIMO: finché non c'è, il pacchetto non è finito.
    let manifest = crate::run_mode::marked_text(manifest_text(
        riferimento,
        &richiesta.operator,
        now,
        &elenco,
        &allegati,
    ));
    let percorso = cartella.join(MANIFEST_FILE);
    write_new(&percorso, manifest.as_bytes())?;
    scritti.push(percorso);
    let impronta = Sha256Digest::of_bytes(manifest.as_bytes())
        .as_str()
        .to_owned();
    elenco.push((
        MANIFEST_FILE.to_owned(),
        manifest.len() as u64,
        impronta.clone(),
    ));

    let audit = NewAuditEntry {
        actor: richiesta.operator.clone(),
        action: AuditAction::try_new(EVIDENCE_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("pacchetto")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "{riferimento}, raccoglitore {}, {} contenuti, motivo: «{}»",
            richiesta.workspace_id.get(),
            contenuti.len(),
            richiesta.reason.as_str()
        ))?),
        recorded_at: now,
    };
    database.insert_evidence_package(
        &NewEvidencePackage {
            package_ref: riferimento.to_owned(),
            workspace_id: richiesta.workspace_id,
            produced_by: String::from(richiesta.operator.as_str()),
            reason: String::from(richiesta.reason.as_str()),
            produced_at: now,
            contents_count: u32::try_from(contenuti.len()).unwrap_or(u32::MAX),
            manifest_sha256: impronta,
        },
        &audit,
    )?;
    Ok(elenco)
}

/// Il documento di lettura, in italiano semplice.
fn reading_document(
    richiesta: &EvidenceRequest,
    anteprima: &Preview,
    riferimento: &str,
    workspace: &str,
    now: Timestamp,
) -> String {
    format!(
        "NEXUM/97 — pacchetto di evidenze {riferimento}\n\
         Ideazione e progettazione: Giuseppe LISI\n\n\
         Prodotto il {quando}, da {chi}, dal workspace «{workspace}».\n\
         Motivo: {motivo}\n\n\
         CHE COSA C'È\n\
         {n} contenuti scelti da una persona, da {fonti} fonti:\n\
         - {contenuti_txt}: ogni contenuto con la sua provenienza e il suo testo;\n\
         - {tabella}: gli stessi contenuti in forma di tabella;\n\
         - {copertura}: quando si guardavano le fonti coinvolte, e quando no;\n\
         - {documenti}: i rapporti che il workspace riferisce, con la loro impronta;\n\
         - {manifest}: l'impronta di ogni file, scritta per ultima.\n\n\
         CHE COSA NON C'È\n\
         - {fuori} contenuti del workspace che nessuno ha scelto: restano nell'archivio.\n\
         - I file dei rapporti: si riferiscono con la loro impronta, e si consegnano a parte.\n\
         - Le modifiche intermedie e le cancellazioni che il monitoraggio non ha visto.\n\
         - I dati che Telegram non ha dato all'account d'ufficio.\n\n\
         CHE COSA IL PACCHETTO NON DIMOSTRA\n\
         {negazione}\n\
         {integrita}\n\
         Il modo di acquisizione di ogni contenuto dice se è stato visto dal vivo, ritrovato \
         dopo, o se non si sa: un modo non determinabile non vuol dire dal vivo.\n\
         {limiti}\n\n\
         SALVAGUARDIA INTERPRETATIVA\n\
         {salvaguardia}\n\n\
         COME SI VERIFICA, SENZA IL PROGRAMMA\n\
         Da PowerShell, nella cartella del pacchetto: Get-FileHash -Algorithm SHA256 *\n\
         Dal prompt dei comandi, per ogni file: certutil -hashfile nome_del_file SHA256\n\
         Ogni impronta va confrontata con quella scritta in {manifest}.\n",
        quando = now.to_readable_utc(),
        chi = richiesta.operator.as_str(),
        workspace = clean(workspace),
        motivo = clean(richiesta.reason.as_str()),
        n = anteprima.rows.len(),
        fonti = anteprima.sources,
        contenuti_txt = CONTENTS_FILE,
        tabella = TABLE_FILE,
        copertura = COVERAGE_FILE,
        documenti = DOCUMENTS_FILE,
        manifest = MANIFEST_FILE,
        fuori = anteprima.left_out,
        negazione = NOT_FORENSIC,
        integrita = INTEGRITY_NOT_SIGNATURE,
        limiti = lisi_core::model::RECOVERY_LIMITS,
        salvaguardia = INTERPRETIVE_SAFEGUARD,
    )
}

/// Il modo dichiarato di un contenuto.
fn declared_mode(modi: &BTreeMap<i64, AcquisitionMode>, contenuto: &Content) -> String {
    crate::acquisition_mode::declared(
        modi.get(&contenuto.id.get())
            .unwrap_or(&AcquisitionMode::Undetermined),
    )
}

/// I contenuti, per esteso, con l'origine di ogni campo (PR-03).
fn contents_text(
    database: &Database,
    contenuti: &[Content],
    modi: &BTreeMap<i64, AcquisitionMode>,
) -> String {
    let mut testo = String::from(
        "NEXUM/97 — contenuti del pacchetto\n\
         Accanto a ogni campo, chi lo afferma: Osservato (Telegram), Calcolato (il programma), \
         Operatore (una persona).\n",
    );
    for (numero, contenuto) in contenuti.iter().enumerate() {
        let dopo = database
            .content_history(contenuto.id)
            .ok()
            .and_then(|storia| storia.summary().short_label())
            .unwrap_or_else(|| String::from("nessun cambiamento registrato"));
        testo.push_str(&format!(
            "\n[{n}] Contenuto {id}, fonte «{fonte}» (Osservato)\n\
             Pubblicato il: {pubblicato} (Osservato)\n\
             Acquisito il: {acquisito} (Calcolato)\n\
             Modo di acquisizione: {modo} (Calcolato)\n\
             Dopo l'acquisizione: {dopo} (Osservato)\n\
             Livello dell'analisi: {livello} (Calcolato)\n\
             Impronta SHA-256 del corpo: {impronta} (Calcolato)\n",
            n = numero + 1,
            id = contenuto.id.get(),
            fonte = clean(&source_name(database, contenuto.source_id)),
            pubblicato = contenuto.published_at.to_readable_utc(),
            acquisito = contenuto.acquired_at.to_readable_utc(),
            modo = declared_mode(modi, contenuto),
            dopo = clean(&dopo),
            livello = contenuto.analysis_level.label(),
            impronta = Sha256Digest::of_text(contenuto.body.as_str()).as_str(),
        ));
        // L'allegato, a parole: ciò che il mittente dichiara e, se conservato,
        // l'impronta (ATTACH-01). I byte escono soltanto se scelti.
        if let Ok(Some(allegato)) = crate::attachment_keeping::describe(database, contenuto.id) {
            testo.push_str(&format!(
                "{} (Osservato; l'impronta Calcolato)\n",
                clean(&allegato)
            ));
        }
        testo.push_str("Testo (Osservato):\n");
        for riga in clean(contenuto.body.as_str()).lines() {
            testo.push_str("    ");
            testo.push_str(riga);
            testo.push('\n');
        }
    }
    testo
}

/// I contenuti in tabella, protetti dalle formule.
fn contents_table(
    database: &Database,
    contenuti: &[Content],
    modi: &BTreeMap<i64, AcquisitionMode>,
) -> String {
    let mut tabella = String::from(
        "\"numero\",\"contenuto\",\"fonte\",\"pubblicato (UTC)\",\"acquisito (UTC)\",\
         \"modo di acquisizione\",\"impronta SHA-256 del corpo\",\"testo\"\r\n",
    );
    for (numero, contenuto) in contenuti.iter().enumerate() {
        let celle = [
            (numero + 1).to_string(),
            contenuto.id.get().to_string(),
            source_name(database, contenuto.source_id),
            contenuto.published_at.to_readable_utc(),
            contenuto.acquired_at.to_readable_utc(),
            declared_mode(modi, contenuto),
            Sha256Digest::of_text(contenuto.body.as_str())
                .as_str()
                .to_owned(),
            contenuto.body.as_str().to_owned(),
        ];
        let riga: Vec<String> = celle.iter().map(|cella| csv_cell(cella)).collect();
        tabella.push_str(&riga.join(","));
        tabella.push_str("\r\n");
    }
    tabella
}

/// La copertura delle fonti coinvolte sull'intervallo dei contenuti.
fn coverage_text(database: &Database, contenuti: &[Content]) -> ServiceResult<String> {
    let (Some(dal), Some(al)) = (
        contenuti
            .iter()
            .map(|contenuto| contenuto.published_at)
            .min(),
        contenuti
            .iter()
            .map(|contenuto| contenuto.published_at)
            .max(),
    ) else {
        return Ok(String::new());
    };
    let al = al.plus_seconds(60);
    let coinvolte: BTreeSet<i64> = contenuti
        .iter()
        .map(|contenuto| contenuto.source_id.get())
        .collect();
    let mut testo = format!(
        "NEXUM/97 — copertura delle fonti coinvolte\n\
         Dal {} al {}.\n{}\n",
        dal.to_readable_utc(),
        al.to_readable_utc(),
        COVERAGE_MEANING
    );
    for fonte in crate::coverage::for_sources(database, dal, al)? {
        if !coinvolte.contains(&fonte.source_id.get()) {
            continue;
        }
        let recuperati = crate::coverage::recovered_spans(database, fonte.source_id, dal, al)?;
        testo.push_str(&format!(
            "\n«{}»\n{}\n",
            clean(&fonte.name),
            crate::coverage::gaps_in_words(&fonte.coverage)
        ));
        let parole = crate::coverage::recovered_in_words(&recuperati);
        if !parole.is_empty() {
            testo.push_str(&parole);
            testo.push('\n');
        }
    }
    Ok(testo)
}

/// I rapporti riferiti dal workspace: nome, genere, impronta. Non si copiano.
fn documents_text(database: &Database, rapporti: &[i64]) -> ServiceResult<String> {
    let mut testo = String::from(
        "NEXUM/97 — documenti riferiti dal workspace\n\
         I file non sono nel pacchetto: stanno dove sono stati prodotti, e si verificano con \
         l'impronta qui sotto.\n",
    );
    if rapporti.is_empty() {
        testo.push_str("\nIl raccoglitore non riferisce alcun rapporto.\n");
        return Ok(testo);
    }
    for rapporto in rapporti {
        let Ok(pacchetto) = database.report_package(ReportPackageId::new(*rapporto)) else {
            testo.push_str(&format!(
                "\nRapporto {rapporto}: non è più nell'archivio.\n"
            ));
            continue;
        };
        testo.push_str(&format!("\nRapporto {}\n", pacchetto.report_id.as_str()));
        for artefatto in database.report_artifacts(pacchetto.id)? {
            testo.push_str(&format!(
                "- {} ({}), {} byte, SHA-256 {}\n",
                clean(&artefatto.file_name),
                artefatto.kind.operator_label(),
                artefatto.size_bytes,
                artefatto.sha256.as_str()
            ));
        }
    }
    Ok(testo)
}

/// Il manifest: ogni altro file, con dimensione e impronta.
fn manifest_text(
    riferimento: &str,
    chi: &Actor,
    now: Timestamp,
    file: &[(String, u64, String)],
    allegati: &[String],
) -> String {
    let mut testo = format!(
        "NEXUM/97 — manifest del pacchetto di evidenze\n\
         Ideazione e progettazione: Giuseppe LISI\n\n\
         Pacchetto:    {riferimento}\n\
         Prodotto:     {}\n\
         Richiesto da: {}\n\
         {}\
         Quanti file:  {}\n\n",
        now.to_readable_utc(),
        chi.as_str(),
        crate::report_package::program_lines(lisi_platform::launch_volume::of_current_executable()),
        file.len()
    );
    for (nome, dimensione, impronta) in file {
        testo.push_str(&format!(
            "File:       {nome}\nDimensione: {dimensione} byte\nSHA-256:    {impronta}\n\n"
        ));
    }
    if !allegati.is_empty() {
        testo.push_str(ATTACHMENTS_WARNING);
        testo.push_str("\n\n");
        for allegato in allegati {
            testo.push_str(allegato);
            testo.push('\n');
        }
    }
    testo.push_str(INTEGRITY_NOT_SIGNATURE);
    testo.push_str(
        "\n\nIl manifest è l'ultimo file scritto: se c'è, il pacchetto è completo.\n\
         Per verificare, da PowerShell, nella cartella del pacchetto:\n\
         Get-FileHash -Algorithm SHA256 *\n",
    );
    testo
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use lisi_core::model::dictionary::ConfigurationResolver;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::workspace::{ArchiveRef, ArchiveRefKind, NewWorkspace};
    use lisi_core::model::{NewSession, NewSource, SessionDuration, SessionState, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{ContentId, Sha256Digest, Timestamp, WorkspaceId};
    use lisi_storage::Database;
    use lisi_telegram::{ChatId, ConnectorEvent, IncomingMessage, MessageId};

    use super::{
        CONTENTS_FILE, EvidenceRequest, MANIFEST_FILE, NOT_FORENSIC, READING_FILE, TABLE_FILE,
        csv_cell, produce,
    };
    use crate::acquisition::AcquisitionService;
    use crate::acquisition_authority::StationAuthorityService;

    const CHAT: i64 = -1_001_000_000_003;
    const THIS_MODULE: &str = include_str!("evidence_package.rs");

    fn t(minuti: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + minuti * 60_000)
    }

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn ragione() -> OperationalReason {
        let Ok(ragione) = OperationalReason::try_new("richiesta dell'autorità procedente") else {
            panic!("la ragione di prova deve essere valida");
        };
        ragione
    }

    /// Un archivio con tre contenuti — uno ostile — e un workspace che li
    /// riferisce tutti e tre.
    fn archivio() -> (Database, WorkspaceId, Vec<ContentId>) {
        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        let (Ok(identificativo), Ok(nome), Ok(etichetta), Ok(filone)) = (
            SourceIdentifier::try_new(&CHAT.to_string()),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Monitoraggio di prova"),
            DisplayName::try_new("Filone di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: operatore(),
                active: true,
            },
            t(-1),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(sessione) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 360_000 },
                source_ids: vec![fonte],
            },
            t(-1),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let Ok(()) =
            database.save_resolved_configuration(sessione, &ConfigurationResolver::new().finish())
        else {
            panic!("la configurazione deve potersi salvare");
        };
        let Ok(()) = database.update_session_state(sessione, SessionState::Running, t(0)) else {
            panic!("il monitoraggio deve avviarsi");
        };
        let mut acquisizione = AcquisitionService::new(database);
        let Ok(contesto) = acquisizione.load_context(sessione, operatore()) else {
            panic!("il contesto deve potersi costruire");
        };
        for (id, testo) in [
            (1, "primo messaggio scelto"),
            (2, "=HYPERLINK(\"http://esempio.invalid\",\"clic\")"),
            (3, "messaggio non scelto: non deve uscire"),
        ] {
            let (Ok(chat), Ok(messaggio)) = (ChatId::try_new(CHAT), MessageId::try_new(id)) else {
                panic!("identificativi validi");
            };
            let Ok(_) = acquisizione.ingest(
                &ConnectorEvent::MessageReceived(IncomingMessage {
                    chat_id: chat,
                    message_id: messaggio,
                    author: None,
                    author_identifier: None,
                    author_username: None,
                    text: String::from(testo),
                    published_at_millis: t(id).as_millis(),
                    url: None,
                    attachment: None,
                }),
                &contesto,
                t(id),
            ) else {
                panic!("il messaggio deve entrare");
            };
        }
        let database = acquisizione.into_database();
        let Ok(contenuti) = database.session_contents(sessione) else {
            panic!("i contenuti devono leggersi");
        };
        let Ok(workspace) = database.insert_workspace(
            &NewWorkspace {
                name: filone,
                description: None,
                created_by: operatore(),
            },
            t(10),
        ) else {
            panic!("il workspace deve aprirsi");
        };
        let mut ids = Vec::new();
        for contenuto in &contenuti {
            let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, contenuto.id.get())
            else {
                panic!("riferimento valido");
            };
            let Ok(()) = database.add_workspace_item(workspace, riferimento, &operatore(), t(11))
            else {
                panic!("l'elemento deve aggiungersi");
            };
            ids.push(contenuto.id);
        }
        ids.sort_by_key(|id| id.get());
        (database, workspace, ids)
    }

    fn richiesta(workspace: WorkspaceId, scelti: &[ContentId]) -> EvidenceRequest {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = StationAuthorityService::in_directory(cartella.path())
            .acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("la domanda di autorità deve avere una risposta");
        };
        let Some(autorita) = esito.into_granted() else {
            panic!("una postazione senza Hub è autorità di sé stessa");
        };
        let Ok(richiesta) =
            EvidenceRequest::new(&autorita, workspace, scelti, operatore(), ragione())
        else {
            panic!("la richiesta deve costruirsi");
        };
        richiesta
    }

    fn leggi(cartella: &Path, nome: &str) -> String {
        let Ok(testo) = std::fs::read_to_string(cartella.join(nome)) else {
            panic!("{nome} deve esistere");
        };
        testo
    }

    /// **SEC-02: il pacchetto di evidenze del solo utente, o niente**
    /// (ADR-0157). Vista rossa il 2026-10-22 con la protezione tolta (mutazione di SEC-02).
    #[cfg(windows)]
    #[test]
    fn il_pacchetto_di_evidenze_e_del_solo_utente_o_non_si_scrive() {
        let (database, workspace, ids) = archivio();
        let database = std::cell::RefCell::new(database);
        let scelti = [ids[0], ids[1]];
        crate::permessi_di_prova::prova_un_uscita("pacchetto di evidenze", |cartella| {
            produce(
                &mut database.borrow_mut(),
                &richiesta(workspace, &scelti),
                cartella,
                t(20),
            )
            .map(|esito| vec![esito.directory])
        });
    }

    /// **Il pacchetto contiene esattamente la selezione** (controllo negativo
    /// 1), e lo si verifica ispezionando i file prodotti.
    #[test]
    fn il_pacchetto_contiene_esattamente_la_selezione() {
        let (mut database, workspace, ids) = archivio();
        let Ok(destinazione) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let scelti = [ids[0], ids[1]];
        let Ok(esito) = produce(
            &mut database,
            &richiesta(workspace, &scelti),
            destinazione.path(),
            t(20),
        ) else {
            panic!("il pacchetto deve prodursi");
        };
        let contenuti = leggi(&esito.directory, CONTENTS_FILE);
        let tabella = leggi(&esito.directory, TABLE_FILE);
        assert!(contenuti.contains("primo messaggio scelto"));
        for file in [&contenuti, &tabella] {
            assert!(
                !file.contains("non deve uscire"),
                "un contenuto non scelto è uscito"
            );
        }
        assert_eq!(tabella.lines().count(), 3, "intestazione e due righe");
        let Ok(registro) = database.workspace_evidence_packages(workspace) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(registro.len(), 1);
        assert_eq!(registro[0].contents_count, 2);
        assert_eq!(registro[0].package_ref, esito.package_ref);
    }

    /// **Le impronte del manifest corrispondono ai file** (controllo negativo
    /// 3): la verifica si rifà come la farebbe chi riceve, file per file.
    #[test]
    fn le_impronte_del_manifest_corrispondono() {
        let (mut database, workspace, ids) = archivio();
        let Ok(destinazione) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = produce(
            &mut database,
            &richiesta(workspace, &ids[..1]),
            destinazione.path(),
            t(20),
        ) else {
            panic!("il pacchetto deve prodursi");
        };
        let manifest = leggi(&esito.directory, MANIFEST_FILE);
        let mut verificati = 0;
        let mut righe = manifest.lines();
        while let Some(riga) = righe.next() {
            let Some(nome) = riga.strip_prefix("File:       ") else {
                continue;
            };
            let (Some(_), Some(impronta)) = (righe.next(), righe.next()) else {
                panic!("ogni file ha dimensione e impronta");
            };
            let Ok(byte) = std::fs::read(esito.directory.join(nome)) else {
                panic!("il file {nome} deve esistere");
            };
            assert_eq!(
                impronta.trim_start_matches("SHA-256:").trim(),
                Sha256Digest::of_bytes(&byte).as_str(),
                "l'impronta di {nome} non corrisponde"
            );
            verificati += 1;
        }
        assert_eq!(verificati, 5, "ogni file, manifest escluso, è nel manifest");
        let Ok(elenco) = std::fs::read_dir(&esito.directory) else {
            panic!("la cartella deve leggersi");
        };
        assert_eq!(elenco.count(), 6, "cinque file e il manifest, nient'altro");
    }

    /// **Un allegato conservato esce soltanto se scelto, come `<impronta>.bin`,
    /// mai con il nome dichiarato; il manifest dice nome e tipo come testo**
    /// (ATTACH-01 parte 3, ADR-0177, decisione 9). Prova negativa: senza la
    /// scelta non esce nessun byte, e nessun file porta il nome dichiarato.
    #[test]
    fn un_allegato_esce_soltanto_se_scelto_e_con_il_nome_dell_impronta() {
        let (mut database, workspace, ids) = archivio();
        let Ok(()) = database.record_content_attachment(
            ids[0],
            &lisi_storage::repository::attachment::ContentAttachment {
                kind: String::from("documento"),
                declared_name: Some(String::from("fattura.pdf.exe")),
                declared_size: Some(18),
                declared_mime: Some(String::from("application/pdf")),
            },
        ) else {
            panic!("la descrizione si registra");
        };
        let byte = b"MZ sintetico, non un programma".to_vec();
        let (Ok(azione), Ok(entita)) = (
            lisi_core::text::AuditAction::try_new("allegato_chiesto"),
            lisi_core::text::AuditEntity::try_new("allegato"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(_) = database.insert_attachment_keeping(
            &lisi_storage::repository::attachment_keeping::NewAttachmentKeeping {
                content_id: ids[0],
                account_uuid: None,
                requested_by: String::from("operatore.prova"),
                reason: String::from("Verifica del documento allegato a una minaccia"),
                requested_at: t(5),
                outcome: String::from("conservato"),
                outcome_detail: None,
                bytes: Some(byte.clone()),
            },
            &lisi_core::model::NewAuditEntry {
                actor: operatore(),
                action: azione,
                entity: entita,
                entity_id: None,
                actor_mode: None,
                detail: None,
                recorded_at: t(5),
            },
        ) else {
            panic!("la conservazione si registra");
        };
        let impronta = Sha256Digest::of_bytes(&byte);
        let nome = format!("{}.bin", impronta.as_str());

        // Senza la scelta: la descrizione sì, i byte no.
        let Ok(senza) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = produce(
            &mut database,
            &richiesta(workspace, &ids[..1]),
            senza.path(),
            t(20),
        ) else {
            panic!("il pacchetto deve prodursi");
        };
        assert!(
            !esito.directory.join(&nome).exists(),
            "senza scelta non escono byte"
        );
        assert!(leggi(&esito.directory, CONTENTS_FILE).contains("Allegato: documento"));

        // Con la scelta.
        let Ok(con) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = produce(
            &mut database,
            &richiesta(workspace, &ids[..1]).with_kept_attachments(),
            con.path(),
            t(21),
        ) else {
            panic!("il pacchetto deve prodursi");
        };
        let Ok(letti) = std::fs::read(esito.directory.join(&nome)) else {
            panic!("l'allegato esce come <impronta>.bin");
        };
        assert_eq!(letti, byte, "i byte come sono");
        let Ok(elenco) = std::fs::read_dir(&esito.directory) else {
            panic!("la cartella deve leggersi");
        };
        for voce in elenco.flatten() {
            let file = voce.file_name().to_string_lossy().to_lowercase();
            assert!(
                !file.contains("fattura") && !file.ends_with(".exe") && !file.ends_with(".pdf"),
                "nessun file porta il nome dichiarato: {file}"
            );
        }
        let manifest = leggi(&esito.directory, MANIFEST_FILE);
        assert!(manifest.contains(&format!("File:       {nome}")));
        assert!(manifest.contains(super::ATTACHMENTS_WARNING));
        assert!(manifest.contains("Nome dichiarato: fattura.pdf.exe"));
        assert!(manifest.contains("Tipo dichiarato: application/pdf"));
    }

    /// **Il documento di lettura c'è, e dice i limiti** (controllo negativo 4);
    /// **nessun percorso della macchina e nessun segreto escono** (controllo
    /// negativo 2).
    #[test]
    fn il_documento_di_lettura_c_e_e_nulla_di_riservato_esce() {
        let (mut database, workspace, ids) = archivio();
        let Ok(destinazione) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = produce(
            &mut database,
            &richiesta(workspace, &ids),
            destinazione.path(),
            t(20),
        ) else {
            panic!("il pacchetto deve prodursi");
        };
        let lettura = leggi(&esito.directory, READING_FILE);
        for dovuto in [
            NOT_FORENSIC,
            super::INTERPRETIVE_SAFEGUARD,
            "CHE COSA NON C'È",
            "certutil",
        ] {
            assert!(
                lettura.contains(dovuto),
                "il documento di lettura non dice «{dovuto}»"
            );
        }
        let percorso = destinazione.path().to_string_lossy().to_string();
        let Ok(elenco) = std::fs::read_dir(&esito.directory) else {
            panic!("la cartella deve leggersi");
        };
        for voce in elenco.flatten() {
            let Ok(testo) = std::fs::read_to_string(voce.path()) else {
                panic!("ogni file è testo");
            };
            let minuscolo = testo.to_lowercase();
            assert!(
                !testo.contains(&percorso),
                "un percorso della macchina è uscito"
            );
            for segreto in [
                "api_hash",
                "api hash",
                "database_key",
                "-----begin",
                "password",
                "otp",
            ] {
                assert!(!minuscolo.contains(segreto), "«{segreto}» è uscito");
            }
        }
    }

    /// **Una cella che comincia come una formula si disinnesca.**
    #[test]
    fn una_formula_si_disinnesca() {
        for (cella, attesa) in [
            ("=1+1", "\"'=1+1\""),
            ("+39 000", "\"'+39 000\""),
            ("-2", "\"'-2\""),
            ("@SOMMA", "\"'@SOMMA\""),
            ("detto \"così\"", "\"detto \"\"così\"\"\""),
            ("a\u{202E}b\u{0007}c", "\"abc\""),
        ] {
            assert_eq!(csv_cell(cella), attesa, "{cella}");
        }
        let (mut database, workspace, ids) = archivio();
        let Ok(destinazione) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(esito) = produce(
            &mut database,
            &richiesta(workspace, &ids[1..2]),
            destinazione.path(),
            t(20),
        ) else {
            panic!("il pacchetto deve prodursi");
        };
        let tabella = leggi(&esito.directory, TABLE_FILE);
        assert!(
            tabella.contains("\"'=HYPERLINK("),
            "la formula del contenuto è disinnescata"
        );
    }

    /// **Un pacchetto non si sovrascrive, e fuori dal workspace non si esce.**
    #[test]
    fn niente_sovrascritture_e_niente_fuori_dal_workspace() {
        let (mut database, workspace, ids) = archivio();
        let Ok(destinazione) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(_) = produce(
            &mut database,
            &richiesta(workspace, &ids[..1]),
            destinazione.path(),
            t(20),
        ) else {
            panic!("il pacchetto deve prodursi");
        };
        assert!(
            produce(
                &mut database,
                &richiesta(workspace, &ids[..1]),
                destinazione.path(),
                t(20)
            )
            .is_err(),
            "lo stesso istante non sovrascrive"
        );
        assert!(
            produce(
                &mut database,
                &richiesta(workspace, &[ContentId::new(9_999)]),
                destinazione.path(),
                t(30)
            )
            .is_err(),
            "un contenuto fuori dal workspace non esce"
        );
        assert!(
            produce(
                &mut database,
                &richiesta(workspace, &ids[..1]),
                Path::new("relativa"),
                t(40)
            )
            .is_err(),
            "una destinazione relativa si rifiuta"
        );
        let Ok(registro) = database.workspace_evidence_packages(workspace) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(
            registro.len(),
            1,
            "soltanto il pacchetto prodotto è registrato"
        );
    }

    /// **«Forense» compare soltanto per dire che il pacchetto non lo è**
    /// (controllo negativo 5).
    #[test]
    fn la_parola_forense_compare_soltanto_per_negarla() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase()
            // Il nome della costante non è una qualificazione del pacchetto.
            .replace("not_forensic", "");
        // La sola frase con quella parola è il messaggio registrato SIC-16:
        // nel codice del pacchetto la parola non compare affatto.
        assert_eq!(
            codice.matches("forens").count(),
            0,
            "«forense» compare nel codice del pacchetto fuori dalla frase registrata che lo nega"
        );
        assert!(NOT_FORENSIC.contains("non è una prova forense"));
        assert_eq!(
            lisi_core::security_messages::by_code("SIC-16").map(|messaggio| messaggio.current.text),
            Some(NOT_FORENSIC)
        );
    }

    /// **Prova di proprietà (PR-15): per ogni selezione possibile, il pacchetto
    /// contiene esattamente la selezione e il manifest si verifica file per
    /// file.** L'archivio di prova ha tre contenuti, e le selezioni non vuote
    /// sono sette: si provano tutte, invece di sceglierne alcune a caso.
    #[test]
    fn ogni_selezione_produce_un_pacchetto_che_si_verifica() {
        let (mut database, workspace, ids) = archivio();
        for maschera in 1_u32..(1 << ids.len()) {
            let scelti: Vec<ContentId> = ids
                .iter()
                .enumerate()
                .filter(|(posizione, _)| maschera & (1 << posizione) != 0)
                .map(|(_, id)| *id)
                .collect();
            let Ok(destinazione) = tempfile::tempdir() else {
                panic!("la cartella temporanea deve potersi creare");
            };
            let Ok(esito) = produce(
                &mut database,
                &richiesta(workspace, &scelti),
                destinazione.path(),
                t(100 + i64::from(maschera)),
            ) else {
                panic!("il pacchetto deve prodursi per la selezione {maschera:03b}");
            };
            let tabella = leggi(&esito.directory, TABLE_FILE);
            assert_eq!(
                tabella.lines().count(),
                scelti.len() + 1,
                "selezione {maschera:03b}: intestazione e una riga per contenuto scelto"
            );
            let manifest = leggi(&esito.directory, MANIFEST_FILE);
            let mut verificati = 0;
            let mut righe = manifest.lines();
            while let Some(riga) = righe.next() {
                let Some(nome) = riga.strip_prefix("File:       ") else {
                    continue;
                };
                let (Some(_), Some(impronta)) = (righe.next(), righe.next()) else {
                    panic!("ogni file ha dimensione e impronta");
                };
                let Ok(byte) = std::fs::read(esito.directory.join(nome)) else {
                    panic!("il file {nome} deve esistere");
                };
                assert_eq!(
                    impronta.trim_start_matches("SHA-256:").trim(),
                    Sha256Digest::of_bytes(&byte).as_str(),
                    "selezione {maschera:03b}: l'impronta di {nome} non corrisponde"
                );
                verificati += 1;
            }
            assert_eq!(
                verificati, 5,
                "selezione {maschera:03b}: ogni file è nel manifest"
            );
        }
        let Ok(registro) = database.workspace_evidence_packages(workspace) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(
            registro.len(),
            7,
            "un pacchetto per selezione, nel registro"
        );
    }
}

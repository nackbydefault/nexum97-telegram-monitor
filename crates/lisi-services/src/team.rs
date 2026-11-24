//! Il fascicolo condivisibile: come due postazioni dello stesso ufficio si
//! allineano senza mescolare due atti.
//!
//! # Che cosa viaggia, e che cosa no
//!
//! Viaggia **la configurazione**: l'elenco delle fonti, i dizionari, il profilo
//! documentale dell'ufficio. Cioè le tre cose che descrivono **come l'ufficio
//! lavora**.
//!
//! Non viaggia **l'archivio**: nessun contenuto acquisito, nessun avviso,
//! nessun documento prodotto, nessuna credenziale, nessuna sessione Telegram.
//! Cioè nulla di ciò che dice **che cosa l'ufficio ha trovato**.
//!
//! La motivazione completa è in ADR-0038; la sostanza è che un monitoraggio è un
//! atto — qualcuno lo ha avviato, con quelle fonti, in quelle ore, e ne risponde
//! — e un archivio condiviso cancella l'autore di ciò che contiene.
//!
//! # Perché un file e non una sincronizzazione
//!
//! Una sincronizzazione continua significa che il dizionario con cui un
//! operatore sta analizzando può cambiare **mentre** analizza, per una modifica
//! fatta da qualcun altro su un'altra macchina. Il documento che ne uscirebbe
//! citerebbe una versione del dizionario che non è quella che ha prodotto i
//! risultati.
//!
//! Un fascicolo si importa quando si decide di importarlo, e da quel momento
//! vale.
//!
//! # Perché è solo testo
//!
//! Il fascicolo **non porta byte binari**, e quindi nemmeno lo stemma
//! dell'ufficio, che resta una scelta locale.
//!
//! Non è una scorciatoia: un formato di scambio che non sa trasportare dati
//! binari **non può trasportare un eseguibile**. È una proprietà di sicurezza
//! che si perde nel momento in cui si aggiunge un campo «allegato», e vale più
//! della comodità di spedire un'immagine che si condivide benissimo per altre
//! vie.
//!
//! # Un fascicolo arriva da fuori
//!
//! Va trattato come ostile: dimensione limitata, campi sconosciuti rifiutati
//! invece che ignorati, ogni valore che passa dai tipi validati del dominio, e
//! l'impronta verificata prima di guardare il contenuto.

use core::str::FromStr;
use lisi_core::model::{NewAuditEntry, NewSource};
use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};
use lisi_core::{Sha256Digest, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};

use lisi_core::model::source::{Source, SourceKind};
use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
use serde::{Deserialize, Serialize};

/// Il nome del formato, scritto dentro il file.
///
/// Un file senza questo nome non è un fascicolo, e va rifiutato prima di
/// interpretarlo: interpretare un file per scoprire che cos'è significa averlo
/// già interpretato.
pub const FASCICOLO_FORMAT: &str = "nexum97/fascicolo";

/// La versione del formato.
pub const FASCICOLO_VERSION: u32 = 1;

/// La dimensione massima ammessa, in byte.
///
/// Quattro megabyte sono molti per del testo e pochi per qualunque altra cosa.
/// Il limite agisce **prima** dell'interpretazione: un file enorme non deve
/// poter consumare memoria mentre viene analizzato.
pub const MAX_FASCICOLO_BYTES: usize = 4 * 1024 * 1024;

/// Da dove viene il fascicolo.
///
/// # Che cosa dichiara davvero
///
/// Finché non esiste una firma (ADR-0037), la provenienza è **ciò che il
/// mittente ha scritto**, non ciò che è stato verificato. L'impronta dice che il
/// file non è cambiato; non dice da chi viene. È una difesa contro la
/// corruzione, non contro un avversario, e va detto così.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// La postazione che lo ha prodotto, come si è dichiarata.
    pub station: String,
    /// Chi lo ha prodotto.
    pub produced_by: String,
    /// Quando, in millisecondi.
    pub produced_at: i64,
}

/// Una fonte, come viaggia fra postazioni.
///
/// # Che cosa NON porta
///
/// Non porta l'identificatore assegnato dall'archivio di origine: è un numero
/// che significa qualcosa solo su quella macchina, e importarlo creerebbe due
/// fonti diverse con lo stesso numero su archivi diversi. Né gli istanti di
/// creazione: la fonte importata nasce **adesso**, sulla postazione che la
/// riceve, ed è la verità.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSource {
    /// Natura della fonte.
    pub kind: String,
    /// Identificativo tecnico presso la piattaforma.
    pub identifier: String,
    /// Nome leggibile.
    pub display_name: String,
    /// Chi ha autorizzato il monitoraggio **presso l'ufficio d'origine**.
    ///
    /// Viaggia perché un'autorizzazione senza autore non è un'autorizzazione.
    /// Chi importa vede da chi veniva, e decide.
    pub authorized_by: String,
}

/// Il profilo documentale, come viaggia fra postazioni.
///
/// Solo testo: lo stemma resta una scelta locale.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedProfile {
    /// Denominazione dell'organizzazione.
    pub organisation: Option<String>,
    /// Denominazione dell'ufficio.
    pub office: Option<String>,
    /// Riga di intestazione libera.
    pub header_line: Option<String>,
    /// Destinatario predefinito.
    pub recipient: Option<String>,
    /// Destinatario per conoscenza.
    pub recipient_cc: Option<String>,
    /// Luogo accanto alla data.
    pub place: Option<String>,
    /// Qualifica di chi sottoscrive.
    pub signer_role: Option<String>,
    /// Nome di chi sottoscrive.
    pub signer_name: Option<String>,
    /// Riga di piè di pagina.
    pub footer_line: Option<String>,
    /// Oggetto base.
    pub subject_base: Option<String>,
}

/// Ciò che il fascicolo contiene.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FascicoloBody {
    /// Le fonti che l'ufficio sorveglia.
    pub sources: Vec<SharedSource>,
    /// I dizionari, nel formato di scambio che già esiste (ADR-0014).
    ///
    /// Si riusa quel formato invece di inventarne un secondo: due formati per la
    /// stessa cosa divergono, e quello meno usato diverge per primo.
    pub dictionaries: Vec<String>,
    /// Il profilo documentale, quando ne viaggia uno.
    pub profile: Option<SharedProfile>,
}

/// Il fascicolo completo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fascicolo {
    /// Il nome del formato.
    pub format: String,
    /// La versione del formato.
    pub version: u32,
    /// Da dove viene.
    pub provenance: Provenance,
    /// L'impronta del contenuto.
    pub digest: String,
    /// Il contenuto.
    pub body: FascicoloBody,
}

/// Perché un fascicolo non è stato accettato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FascicoloError {
    /// Troppo grande per essere anche solo letto.
    TooLarge {
        /// Quanti byte.
        bytes: usize,
    },
    /// Non è un fascicolo.
    NotAFascicolo,
    /// È un fascicolo di una versione che questa copia non sa leggere.
    UnknownVersion {
        /// La versione trovata.
        found: u32,
    },
    /// Il contenuto non corrisponde alla propria impronta.
    DigestMismatch,
    /// Il file non è interpretabile.
    Malformed {
        /// La ragione.
        reason: String,
    },
    /// Un valore non è ammesso dal dominio.
    Invalid {
        /// Che cosa.
        what: String,
        /// Perché.
        reason: String,
    },
}

impl std::fmt::Display for FascicoloError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes } => write!(
                formatter,
                "il fascicolo occupa {bytes} byte e supera il limite di \
                 {MAX_FASCICOLO_BYTES}: non è stato nemmeno letto."
            ),
            Self::NotAFascicolo => write!(
                formatter,
                "questo file non è un fascicolo di NEXUM/97: non è stato interpretato."
            ),
            Self::UnknownVersion { found } => write!(
                formatter,
                "il fascicolo è nella versione {found}, e questa copia del programma \
                 legge fino alla {FASCICOLO_VERSION}. Aggiornare il programma prima \
                 di importarlo: leggerlo a metà sarebbe peggio che non leggerlo."
            ),
            Self::DigestMismatch => write!(
                formatter,
                "il contenuto del fascicolo non corrisponde alla propria impronta: \
                 il file è stato modificato o si è danneggiato durante il trasporto. \
                 Non è stato importato."
            ),
            Self::Malformed { reason } => {
                write!(formatter, "il fascicolo non è leggibile: {reason}")
            }
            Self::Invalid { what, reason } => {
                write!(formatter, "«{what}» non è un valore ammesso: {reason}")
            }
        }
    }
}

impl std::error::Error for FascicoloError {}

impl Fascicolo {
    /// Compone un fascicolo e ne calcola l'impronta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il contenuto non è serializzabile.
    pub fn compose(provenance: Provenance, body: FascicoloBody) -> Result<Self, FascicoloError> {
        let digest = digest_of(&body)?;
        Ok(Self {
            format: String::from(FASCICOLO_FORMAT),
            version: FASCICOLO_VERSION,
            provenance,
            digest,
            body,
        })
    }

    /// Il fascicolo come testo da consegnare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la serializzazione non riesce.
    pub fn to_document(&self) -> Result<String, FascicoloError> {
        serde_json::to_string_pretty(self).map_err(|errore| FascicoloError::Malformed {
            reason: errore.to_string(),
        })
    }

    /// Legge un fascicolo da un documento ricevuto.
    ///
    /// # L'ordine dei controlli non è arbitrario
    ///
    /// Dimensione, poi forma, poi versione, poi impronta. Ogni passo evita di
    /// fare lavoro su qualcosa che il passo precedente avrebbe scartato — e il
    /// limite di dimensione viene per primo perché è l'unico che protegge
    /// dall'analisi stessa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore per ognuno di quei controlli, e dice **quale** ha
    /// fallito: «non importato» senza ragione manda chi legge a indovinare.
    pub fn parse(document: &str) -> Result<Self, FascicoloError> {
        if document.len() > MAX_FASCICOLO_BYTES {
            return Err(FascicoloError::TooLarge {
                bytes: document.len(),
            });
        }

        // Un fascicolo salvato dal Blocco note comincia con il segno BOM: non è
        // un contenuto, e rifiutarlo per quello diceva «expected value at line 1
        // column 1», in inglese, a chi l'aveva solo aperto e richiuso (F-26).
        let document = document.strip_prefix('\u{feff}').unwrap_or(document);
        let letto: Self =
            serde_json::from_str(document).map_err(|errore| FascicoloError::Malformed {
                reason: parse_reason(&errore),
            })?;

        if letto.format != FASCICOLO_FORMAT {
            return Err(FascicoloError::NotAFascicolo);
        }
        if letto.version != FASCICOLO_VERSION {
            return Err(FascicoloError::UnknownVersion {
                found: letto.version,
            });
        }

        let atteso = digest_of(&letto.body)?;
        if atteso != letto.digest {
            return Err(FascicoloError::DigestMismatch);
        }

        Ok(letto)
    }
}

/// Perché il testo di un fascicolo non si legge, in italiano e con il punto.
///
/// Il messaggio della libreria è in inglese e pensato per chi scrive codice
/// (F-26). Qui si dice che genere di problema è e dove sta: chi ha aperto il
/// file in un editor può andare a quella riga.
fn parse_reason(errore: &serde_json::Error) -> String {
    let che_cosa = match errore.classify() {
        serde_json::error::Category::Eof => "il file finisce prima del previsto",
        serde_json::error::Category::Syntax => "il testo non è nella forma di un fascicolo",
        serde_json::error::Category::Data => {
            "il fascicolo contiene un campo inatteso, o un valore del tipo sbagliato"
        }
        serde_json::error::Category::Io => "il file non si è potuto leggere per intero",
    };
    format!(
        "{che_cosa} (riga {}, colonna {})",
        errore.line(),
        errore.column()
    )
}

/// L'impronta di un contenuto.
///
/// Si calcola sulla forma **compatta** e non su quella indentata: due fascicoli
/// con lo stesso contenuto e una spaziatura diversa devono avere la stessa
/// impronta, altrimenti un editor di testo che riformatta il file lo
/// invaliderebbe senza averne cambiato il significato.
fn digest_of(body: &FascicoloBody) -> Result<String, FascicoloError> {
    let canonico = serde_json::to_string(body).map_err(|errore| FascicoloError::Malformed {
        reason: errore.to_string(),
    })?;
    Ok(String::from(Sha256Digest::of_text(&canonico).as_str()))
}

/// Che cosa cambierebbe importando un fascicolo.
///
/// # Perché si conta prima
///
/// È la stessa regola dell'anteprima della conservazione: una modifica che non
/// si può prevedere è una modifica che si scopre quando è troppo tardi.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportPreview {
    /// Le fonti che verrebbero aggiunte.
    pub new_sources: Vec<String>,
    /// Le fonti già presenti, che resterebbero come sono.
    pub already_present: Vec<String>,
    /// Quanti dizionari verrebbero importati.
    pub dictionaries: usize,
    /// Se il profilo documentale verrebbe sostituito.
    pub replaces_profile: bool,
    /// I campi del profilo che cambierebbero valore.
    ///
    /// Sostituire un profilo senza dire **quali righe** cambiano significa
    /// chiedere a qualcuno di accettare al buio la firma che comparirà in calce
    /// ai propri atti.
    pub profile_changes: Vec<String>,
}

impl ImportPreview {
    /// Vero se importare non cambierebbe nulla.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.new_sources.is_empty() && self.dictionaries == 0 && self.profile_changes.is_empty()
    }

    /// Che cosa cambierebbe, in una frase.
    #[must_use]
    pub fn operator_message(&self) -> String {
        if self.is_empty() {
            return String::from(
                "Questo fascicolo non cambierebbe nulla: tutto ciò che contiene è già \
                 presente su questa postazione.",
            );
        }

        let mut parti = Vec::new();
        if !self.new_sources.is_empty() {
            parti.push(format!("{} fonti nuove", self.new_sources.len()));
        }
        if !self.already_present.is_empty() {
            parti.push(format!(
                "{} già presenti, che resterebbero come sono",
                self.already_present.len()
            ));
        }
        if self.dictionaries > 0 {
            parti.push(format!("{} dizionari", self.dictionaries));
        }
        if !self.profile_changes.is_empty() {
            parti.push(format!(
                "{} righe del profilo documentale: {}",
                self.profile_changes.len(),
                self.profile_changes.join(", ")
            ));
        }
        format!(
            "Importando questo fascicolo cambierebbero: {}.",
            parti.join("; ")
        )
    }
}

/// Compone la parte «fonti» di un fascicolo da ciò che la postazione ha.
#[must_use]
pub fn share_sources(sources: &[Source]) -> Vec<SharedSource> {
    sources
        .iter()
        .map(|source| SharedSource {
            kind: String::from(source.kind.as_str()),
            identifier: String::from(source.identifier.as_str()),
            display_name: String::from(source.display_name.as_str()),
            authorized_by: String::from(source.authorized_by.as_str()),
        })
        .collect()
}

/// Compone la parte «profilo» di un fascicolo.
///
/// Lo stemma resta fuori: il fascicolo non porta byte binari.
#[must_use]
pub fn share_profile(profile: &ReportTemplateProfile) -> SharedProfile {
    let testo =
        |campo: &Option<TemplateField>| campo.as_ref().map(|valore| String::from(valore.as_str()));
    SharedProfile {
        organisation: testo(&profile.organisation),
        office: testo(&profile.office),
        header_line: testo(&profile.header_line),
        recipient: testo(&profile.recipient),
        recipient_cc: testo(&profile.recipient_cc),
        place: testo(&profile.place),
        signer_role: testo(&profile.signer_role),
        signer_name: testo(&profile.signer_name),
        footer_line: testo(&profile.footer_line),
        subject_base: testo(&profile.subject_base),
    }
}

/// Che cosa cambierebbe importando il fascicolo indicato.
#[must_use]
pub fn preview(
    fascicolo: &Fascicolo,
    esistenti: &[Source],
    profilo_corrente: Option<&ReportTemplateProfile>,
) -> ImportPreview {
    let identificativi: Vec<&str> = esistenti
        .iter()
        .map(|source| source.identifier.as_str())
        .collect();

    let mut nuove = Vec::new();
    let mut presenti = Vec::new();
    for fonte in &fascicolo.body.sources {
        if identificativi.contains(&fonte.identifier.as_str()) {
            presenti.push(fonte.display_name.clone());
        } else {
            nuove.push(fonte.display_name.clone());
        }
    }

    let cambi = fascicolo
        .body
        .profile
        .as_ref()
        .map_or_else(Vec::new, |in_arrivo| {
            let corrente = profilo_corrente.map(share_profile).unwrap_or_default();
            differenze(&corrente, in_arrivo)
        });

    ImportPreview {
        new_sources: nuove,
        already_present: presenti,
        dictionaries: fascicolo.body.dictionaries.len(),
        replaces_profile: fascicolo.body.profile.is_some(),
        profile_changes: cambi,
    }
}

/// Quali righe del profilo cambierebbero valore.
fn differenze(corrente: &SharedProfile, in_arrivo: &SharedProfile) -> Vec<String> {
    let campi: [(&str, &Option<String>, &Option<String>); 10] = [
        (
            "organizzazione",
            &corrente.organisation,
            &in_arrivo.organisation,
        ),
        ("ufficio", &corrente.office, &in_arrivo.office),
        (
            "intestazione",
            &corrente.header_line,
            &in_arrivo.header_line,
        ),
        ("destinatario", &corrente.recipient, &in_arrivo.recipient),
        (
            "per conoscenza",
            &corrente.recipient_cc,
            &in_arrivo.recipient_cc,
        ),
        ("luogo", &corrente.place, &in_arrivo.place),
        (
            "qualifica di chi firma",
            &corrente.signer_role,
            &in_arrivo.signer_role,
        ),
        (
            "nome di chi firma",
            &corrente.signer_name,
            &in_arrivo.signer_name,
        ),
        (
            "piè di pagina",
            &corrente.footer_line,
            &in_arrivo.footer_line,
        ),
        ("oggetto", &corrente.subject_base, &in_arrivo.subject_base),
    ];

    campi
        .iter()
        .filter(|(_, vecchio, nuovo)| vecchio != nuovo)
        .map(|(nome, _, _)| String::from(*nome))
        .collect()
}

/// Converte una fonte condivisa nei tipi validati del dominio.
///
/// # Perché la validazione avviene qui e non all'importazione in blocco
///
/// Un fascicolo con quaranta fonti di cui una sbagliata non deve importarne
/// trentanove e fermarsi: chi guarda l'elenco troverebbe un ufficio configurato
/// a metà e non saprebbe quale metà. Si valida tutto prima, e si scrive dopo.
///
/// # Errori
///
/// Restituisce un errore che nomina **quale** valore non è ammesso e perché.
pub fn to_domain(
    fonte: &SharedSource,
) -> Result<(SourceKind, SourceIdentifier, DisplayName, Actor), FascicoloError> {
    let kind = SourceKind::from_str(&fonte.kind).map_err(|_| FascicoloError::Invalid {
        what: fonte.kind.clone(),
        reason: String::from("non è una natura di fonte che il prodotto conosce"),
    })?;
    let identifier =
        SourceIdentifier::try_new(&fonte.identifier).map_err(|errore| FascicoloError::Invalid {
            what: fonte.identifier.clone(),
            reason: errore.to_string(),
        })?;
    let display_name =
        DisplayName::try_new(&fonte.display_name).map_err(|errore| FascicoloError::Invalid {
            what: fonte.display_name.clone(),
            reason: errore.to_string(),
        })?;
    let authorized_by =
        Actor::try_new(&fonte.authorized_by).map_err(|errore| FascicoloError::Invalid {
            what: fonte.authorized_by.clone(),
            reason: errore.to_string(),
        })?;

    Ok((kind, identifier, display_name, authorized_by))
}

/// Servizio del fascicolo condivisibile.
///
/// # Perché possiede l'archivio invece di comporre altri servizi
///
/// L'importazione deve essere **tutto o niente**. Un fascicolo con quaranta
/// fonti di cui una sbagliata non deve importarne trentanove e fermarsi: chi
/// guarda l'elenco troverebbe un ufficio configurato a metà e non saprebbe quale
/// metà.
///
/// Servizi diversi hanno connessioni diverse, e connessioni diverse non
/// condividono una transazione. Qui l'archivio è uno solo.
#[derive(Debug)]
pub struct TeamService {
    database: Database,
}

/// Che cosa è stato davvero importato.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Le fonti aggiunte.
    pub sources_added: usize,
    /// Le fonti saltate perché già presenti.
    pub sources_skipped: usize,
    /// Se il profilo documentale è stato sostituito.
    pub profile_replaced: bool,
}

impl ImportOutcome {
    /// L'esito, in una frase.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let mut parti = Vec::new();
        if self.sources_added > 0 {
            parti.push(format!("{} fonti aggiunte", self.sources_added));
        }
        if self.sources_skipped > 0 {
            parti.push(format!(
                "{} già presenti e lasciate come erano",
                self.sources_skipped
            ));
        }
        if self.profile_replaced {
            parti.push(String::from("profilo documentale aggiornato"));
        }

        if parti.is_empty() {
            return String::from("Il fascicolo non conteneva nulla da importare.");
        }
        format!(
            "Fascicolo importato: {}. L'operazione è scritta nel registro delle operazioni.",
            parti.join(", ")
        )
    }
}

impl TeamService {
    /// Crea il servizio attorno all'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce l'archivio, consumando il servizio.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Compone un fascicolo con la configurazione di questa postazione.
    ///
    /// # Che cosa NON entra
    ///
    /// Nessun contenuto acquisito, nessun avviso, nessun documento prodotto,
    /// nessuna credenziale, nessuna sessione. Solo come l'ufficio lavora.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o la composizione non riescono.
    pub fn export(&self, station: &str, actor: &Actor, now: Timestamp) -> ServiceResult<Fascicolo> {
        let fascicolo = self.compose_fascicolo(station, actor, now)?;
        self.record_fascicolo(&fascicolo, actor, now)?;
        Ok(fascicolo)
    }

    /// Compone il fascicolo e lo scrive nel file scelto, del solo utente
    /// (SEC-02, ADR-0157). **L'audit segue il file**: se il file non si
    /// scrive, nessuna riga dice che il fascicolo è uscito.
    ///
    /// Il nome l'ha scelto l'operatore in una finestra che gli ha chiesto se
    /// sostituire un file esistente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la composizione non riesce, se il percorso non
    /// indica un file, se il file non si scrive o se l'audit non si aggiorna;
    /// [`ServiceError::ProtectionNotGuaranteed`] se il file non si può rendere
    /// del solo utente: in quel caso non resta nulla, e il rifiuto è
    /// nell'audit.
    pub fn export_to_file(
        &self,
        destination: &std::path::Path,
        station: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<crate::protected_output::Delivered> {
        let fascicolo = self.compose_fascicolo(station, actor, now)?;
        let documento =
            fascicolo
                .to_document()
                .map_err(|errore| ServiceError::FascicoloRefused {
                    reason: errore.to_string(),
                })?;
        let (Some(cartella), Some(nome)) = (
            destination.parent(),
            destination
                .file_name()
                .map(|nome| nome.to_string_lossy().into_owned()),
        ) else {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from("il percorso del fascicolo non indica un file"),
            });
        };
        let consegnati = crate::protected_output::Delivery::begin(
            cartella,
            &nome,
            "Il fascicolo NON è stato scritto",
        )
        .and_then(|mut consegna| {
            consegna.write(&nome, documento.as_bytes())?;
            consegna.deliver(crate::protected_output::Existing::Replace)
        })
        .inspect_err(|errore| {
            crate::protected_output::record_refusal(
                &self.database,
                actor,
                now,
                crate::protected_output::REFUSED_AUDIT_ACTION,
                "fascicolo",
                errore,
            );
        })?;
        self.record_fascicolo(&fascicolo, actor, now)?;
        Ok(consegnati)
    }

    /// Compone il fascicolo, senza registrarlo.
    fn compose_fascicolo(
        &self,
        station: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<Fascicolo> {
        let sources = self.database.sources()?;
        let profile = crate::report_profile::load(&self.database)?.map(|letto| letto.profile);

        let body = FascicoloBody {
            sources: share_sources(&sources),
            dictionaries: Vec::new(),
            profile: profile.as_ref().map(share_profile),
        };

        let provenance = Provenance {
            station: String::from(station),
            produced_by: String::from(actor.as_str()),
            produced_at: now.as_millis(),
        };

        Fascicolo::compose(provenance, body).map_err(|errore| ServiceError::FascicoloRefused {
            reason: errore.to_string(),
        })
    }

    /// Registra nell'audit che il fascicolo è uscito.
    fn record_fascicolo(
        &self,
        fascicolo: &Fascicolo,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("fascicolo_esportato")?,
            entity: AuditEntity::try_new("team")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{} fonti, profilo {}",
                fascicolo.body.sources.len(),
                if fascicolo.body.profile.is_some() {
                    "incluso"
                } else {
                    "assente"
                }
            ))?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Che cosa cambierebbe importando il documento indicato.
    ///
    /// Non scrive nulla.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il documento non è un fascicolo valido, dicendo
    /// **quale** controllo ha fallito.
    pub fn preview_import(&self, document: &str) -> ServiceResult<(Fascicolo, ImportPreview)> {
        let fascicolo =
            Fascicolo::parse(document).map_err(|errore| ServiceError::FascicoloRefused {
                reason: errore.to_string(),
            })?;
        let esistenti = self.database.sources()?;
        let profilo = crate::report_profile::load(&self.database)?.map(|letto| letto.profile);
        let anteprima = preview(&fascicolo, &esistenti, profilo.as_ref());
        Ok((fascicolo, anteprima))
    }

    /// Importa il fascicolo indicato.
    ///
    /// # Tutto o niente
    ///
    /// Ogni valore viene validato **prima** che si scriva alcunché. Se anche
    /// una sola fonte non è ammessa, non si scrive nulla: un ufficio configurato
    /// a metà è peggio di uno non configurato, perché sembra a posto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il documento non è valido, se un valore non è
    /// ammesso, o se la scrittura non riesce.
    pub fn import(
        &mut self,
        document: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<ImportOutcome> {
        let fascicolo =
            Fascicolo::parse(document).map_err(|errore| ServiceError::FascicoloRefused {
                reason: errore.to_string(),
            })?;

        let esistenti = self.database.sources()?;
        let presenti: Vec<String> = esistenti
            .iter()
            .map(|source| String::from(source.identifier.as_str()))
            .collect();

        // ==================================================================
        // PRIMA si valida tutto. POI si scrive.
        // ==================================================================
        let mut da_aggiungere = Vec::new();
        let mut saltate = 0_usize;
        for fonte in &fascicolo.body.sources {
            if presenti.contains(&fonte.identifier) {
                saltate += 1;
                continue;
            }
            let (kind, identifier, display_name, authorized_by) =
                to_domain(fonte).map_err(|errore| ServiceError::FascicoloRefused {
                    reason: errore.to_string(),
                })?;
            da_aggiungere.push(NewSource {
                kind,
                identifier,
                display_name,
                authorized_by,
                active: true,
            });
        }

        let profilo =
            match &fascicolo.body.profile {
                None => None,
                Some(condiviso) => Some(to_profile(condiviso).map_err(|errore| {
                    ServiceError::FascicoloRefused {
                        reason: errore.to_string(),
                    }
                })?),
            };

        // ==================================================================
        // Da qui in poi si scrive, e tutto ciò che si scrive è già valido.
        // ==================================================================
        let aggiunte = da_aggiungere.len();
        for nuova in &da_aggiungere {
            self.database.insert_source(nuova, now)?;
        }

        let profilo_sostituito = if let Some(profilo) = profilo {
            crate::report_profile::save(&self.database, &profilo, actor, now)?;
            true
        } else {
            false
        };

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("fascicolo_importato")?,
            entity: AuditEntity::try_new("team")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "da «{}» del {}: {aggiunte} fonti aggiunte, {saltate} già presenti",
                fascicolo.provenance.station, fascicolo.provenance.produced_at
            ))?),
            recorded_at: now,
        })?;

        Ok(ImportOutcome {
            sources_added: aggiunte,
            sources_skipped: saltate,
            profile_replaced: profilo_sostituito,
        })
    }
}

/// Converte un profilo condiviso nei tipi validati del dominio.
///
/// Lo stemma resta quello locale: il fascicolo non lo porta, e sostituirlo con
/// «nessuno stemma» toglierebbe a chi importa una cosa che aveva.
fn to_profile(condiviso: &SharedProfile) -> Result<ReportTemplateProfile, FascicoloError> {
    let campo =
        |valore: &Option<String>, nome: &str| -> Result<Option<TemplateField>, FascicoloError> {
            match valore {
                None => Ok(None),
                Some(testo) if testo.trim().is_empty() => Ok(None),
                Some(testo) => TemplateField::try_new(testo).map(Some).map_err(|errore| {
                    FascicoloError::Invalid {
                        what: String::from(nome),
                        reason: errore.to_string(),
                    }
                }),
            }
        };

    Ok(ReportTemplateProfile {
        version: 0,
        organisation: campo(&condiviso.organisation, "organizzazione")?,
        office: campo(&condiviso.office, "ufficio")?,
        header_line: campo(&condiviso.header_line, "intestazione")?,
        recipient: campo(&condiviso.recipient, "destinatario")?,
        recipient_cc: campo(&condiviso.recipient_cc, "per conoscenza")?,
        place: campo(&condiviso.place, "luogo")?,
        signer_role: campo(&condiviso.signer_role, "qualifica di chi firma")?,
        signer_name: campo(&condiviso.signer_name, "nome di chi firma")?,
        footer_line: campo(&condiviso.footer_line, "piè di pagina")?,
        subject_base: campo(&condiviso.subject_base, "oggetto")?,
        emblem: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FASCICOLO_FORMAT, FASCICOLO_VERSION, Fascicolo, FascicoloBody, FascicoloError,
        MAX_FASCICOLO_BYTES, Provenance, SharedProfile, SharedSource, preview,
    };

    fn provenienza() -> Provenance {
        Provenance {
            station: String::from("POSTAZIONE-01"),
            produced_by: String::from("operatore.prova"),
            produced_at: 1_700_000_000_000,
        }
    }

    fn fonte(identifier: &str, nome: &str) -> SharedSource {
        SharedSource {
            kind: String::from("channel"),
            identifier: String::from(identifier),
            display_name: String::from(nome),
            authorized_by: String::from("responsabile.ufficio"),
        }
    }

    fn corpo() -> FascicoloBody {
        FascicoloBody {
            sources: vec![fonte("canale_uno", "Canale Uno")],
            dictionaries: vec![String::from("{\"dizionario\":\"finto\"}")],
            profile: Some(SharedProfile {
                office: Some(String::from("Ufficio Prova")),
                ..SharedProfile::default()
            }),
        }
    }

    #[test]
    fn un_fascicolo_si_scrive_e_si_rilegge_uguale() {
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo()) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };
        let Ok(riletto) = Fascicolo::parse(&documento) else {
            panic!("il fascicolo deve potersi rileggere");
        };
        assert_eq!(riletto, fascicolo);
    }

    /// **Un contenuto modificato non passa.**
    ///
    /// È la sola cosa che l'impronta sa fare, e va verificata: senza, il campo
    /// `digest` sarebbe una decorazione.
    #[test]
    fn un_contenuto_modificato_non_passa() {
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo()) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };

        // Si cambia il nome di una fonte senza ricalcolare l'impronta: e' cio'
        // che farebbe chi modifica il file a mano.
        let manomesso = documento.replace("Canale Uno", "Canale Due");
        assert_ne!(
            manomesso, documento,
            "la manomissione deve aver toccato il file"
        );

        assert_eq!(
            Fascicolo::parse(&manomesso),
            Err(FascicoloError::DigestMismatch)
        );
    }

    #[test]
    fn una_riformattazione_non_invalida_il_fascicolo() {
        // Due fascicoli con lo stesso contenuto e una spaziatura diversa devono
        // avere la stessa impronta, altrimenti un editor che riformatta il file
        // lo invaliderebbe senza averne cambiato il significato.
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo()) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let Ok(compatto) = serde_json::to_string(&fascicolo) else {
            panic!("la forma compatta deve potersi scrivere");
        };
        assert!(Fascicolo::parse(&compatto).is_ok());
    }

    #[test]
    fn un_file_che_non_e_un_fascicolo_non_viene_interpretato() {
        let altro = r#"{"format":"qualcos'altro","version":1,"provenance":{"station":"x","produced_by":"y","produced_at":0},"digest":"","body":{"sources":[],"dictionaries":[],"profile":null}}"#;
        assert_eq!(Fascicolo::parse(altro), Err(FascicoloError::NotAFascicolo));
    }

    #[test]
    fn una_versione_futura_si_rifiuta_invece_di_leggerla_a_meta() {
        // Leggere a meta' un formato che non si conosce e' peggio che non
        // leggerlo: si importerebbe cio' che si e' capito e si perderebbe in
        // silenzio il resto.
        let futuro = format!(
            r#"{{"format":"{FASCICOLO_FORMAT}","version":{},"provenance":{{"station":"x","produced_by":"y","produced_at":0}},"digest":"","body":{{"sources":[],"dictionaries":[],"profile":null}}}}"#,
            FASCICOLO_VERSION + 1
        );
        let Err(errore) = Fascicolo::parse(&futuro) else {
            panic!("una versione futura non deve essere accettata");
        };
        assert!(matches!(errore, FascicoloError::UnknownVersion { .. }));
        assert!(
            errore.to_string().contains("Aggiornare il programma"),
            "il messaggio deve dire che cosa fare: «{errore}»"
        );
    }

    /// **Un fascicolo con il segno BOM si legge, e un testo rotto si spiega in
    /// italiano** (F-26).
    ///
    /// Vista rossa prima della correzione: «expected value at line 1 column 1».
    #[test]
    fn il_bom_non_e_un_errore_e_l_errore_si_dice_in_italiano() {
        let con_bom = format!(
            "\u{feff}{{\"format\":\"{FASCICOLO_FORMAT}\",\"version\":{},\"provenance\":{{\"station\":\"x\",\"produced_by\":\"y\",\"produced_at\":0}},\"digest\":\"\",\"body\":{{\"sources\":[],\"dictionaries\":[],\"profile\":null}}}}",
            FASCICOLO_VERSION + 1
        );
        // Letto: si arriva al controllo della versione, non a quello del testo.
        assert!(matches!(
            Fascicolo::parse(&con_bom),
            Err(FascicoloError::UnknownVersion { .. })
        ));

        let Err(rotto) = Fascicolo::parse("non è un fascicolo") else {
            panic!("un testo qualunque non è un fascicolo");
        };
        let frase = rotto.to_string();
        assert!(frase.contains("riga 1"), "«{frase}»");
        assert!(
            !frase.contains("expected"),
            "messaggio in inglese: «{frase}»"
        );
    }

    #[test]
    fn un_campo_sconosciuto_viene_rifiutato_invece_che_ignorato() {
        // Ignorare un campo sconosciuto significa importare un fascicolo
        // credendo di averlo capito tutto.
        let con_extra = r#"{"format":"nexum97/fascicolo","version":1,"provenance":{"station":"x","produced_by":"y","produced_at":0},"digest":"","body":{"sources":[],"dictionaries":[],"profile":null},"sorpresa":true}"#;
        assert!(matches!(
            Fascicolo::parse(con_extra),
            Err(FascicoloError::Malformed { .. })
        ));
    }

    #[test]
    fn un_file_enorme_non_viene_nemmeno_letto() {
        let enorme = "x".repeat(MAX_FASCICOLO_BYTES + 1);
        let Err(errore) = Fascicolo::parse(&enorme) else {
            panic!("un file oltre il limite non deve essere letto");
        };
        assert!(matches!(errore, FascicoloError::TooLarge { .. }));
        assert!(
            errore.to_string().contains("non è stato nemmeno letto"),
            "il messaggio deve dire che il file non e' stato toccato: «{errore}»"
        );
    }

    /// **Nel fascicolo non ci sono credenziali. Mai.**
    ///
    /// Non è una verifica del formato: è una verifica di ciò che il formato
    /// **può** contenere. Se un giorno qualcuno aggiungesse un campo che porta
    /// un segreto, questa prova diventerebbe rossa.
    #[test]
    fn nel_fascicolo_non_viaggia_mai_un_segreto() {
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo()) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };
        let minuscolo = documento.to_lowercase();

        for proibito in [
            "api_hash",
            "api_id",
            "password",
            "passphrase",
            "session",
            "token",
            "otp",
            "credential",
            "secret",
        ] {
            assert!(
                !minuscolo.contains(proibito),
                "il fascicolo contiene «{proibito}»: un segreto non deve mai viaggiare"
            );
        }
    }

    /// **Il fascicolo non sa trasportare dati binari.**
    ///
    /// Un formato di scambio che non puo' trasportare un eseguibile e' un
    /// formato che non puo' consegnarne uno. La proprieta' si perde nel momento
    /// in cui si aggiunge un campo «allegato»: questa prova lo impedisce.
    #[test]
    fn il_formato_non_puo_trasportare_un_eseguibile() {
        let sorgente = include_str!("team.rs");
        let produzione = sorgente.split("#[cfg(test)]").next().unwrap_or(sorgente);

        // Solo i tipi che portano davvero del binario. «bytes: usize» in un
        // errore e' un CONTEGGIO, non un carico: vietarlo sarebbe un falso
        // allarme, e un falso allarme insegna a ignorare la prova.
        for binario in ["Vec<u8>", "&[u8]", "[u8;", "base64", "serde_bytes"] {
            assert!(
                !produzione.contains(binario),
                "il formato ha acquisito un campo binario («{binario}»): da qui \
                 puo' passare un eseguibile"
            );
        }
    }

    #[test]
    fn l_anteprima_distingue_cio_che_c_e_gia_da_cio_che_e_nuovo() {
        let mut corpo = corpo();
        corpo.sources.push(fonte("canale_due", "Canale Due"));
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo) else {
            panic!("il fascicolo deve potersi comporre");
        };

        // Nessuna fonte esistente: sono tutte nuove.
        let anteprima = preview(&fascicolo, &[], None);
        assert_eq!(anteprima.new_sources.len(), 2);
        assert!(anteprima.already_present.is_empty());
        assert_eq!(anteprima.dictionaries, 1);
        assert!(!anteprima.is_empty());
    }

    #[test]
    fn l_anteprima_nomina_le_righe_del_profilo_che_cambierebbero() {
        // Sostituire un profilo senza dire QUALI righe cambiano significa
        // chiedere a qualcuno di accettare al buio la firma che comparira' in
        // calce ai propri atti.
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo()) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let anteprima = preview(&fascicolo, &[], None);
        assert!(
            anteprima.profile_changes.contains(&String::from("ufficio")),
            "l'anteprima non nomina la riga che cambierebbe: {:?}",
            anteprima.profile_changes
        );
        assert!(anteprima.operator_message().contains("ufficio"));
    }

    #[test]
    fn un_fascicolo_che_non_cambia_nulla_lo_dice() {
        let vuoto = FascicoloBody::default();
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), vuoto) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let anteprima = preview(&fascicolo, &[], None);
        assert!(anteprima.is_empty());
        assert!(
            anteprima
                .operator_message()
                .contains("non cambierebbe nulla"),
            "«{}»",
            anteprima.operator_message()
        );
    }

    fn servizio() -> super::TeamService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        super::TeamService::new(database)
    }

    fn operatore() -> lisi_core::text::Actor {
        let Ok(actor) = lisi_core::text::Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn adesso() -> lisi_core::Timestamp {
        lisi_core::Timestamp::from_millis(1_700_000_000_000)
    }

    #[test]
    fn un_fascicolo_esportato_si_reimporta_su_una_postazione_vuota() {
        // Il giro completo, con l'archivio vero: e' l'unica prova che dice che
        // le due meta' combaciano.
        let origine = servizio();
        let Ok(fascicolo) = origine.export("POSTAZIONE-01", &operatore(), adesso()) else {
            panic!("l'esportazione deve riuscire");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };

        let mut destinazione = servizio();
        let Ok(esito) = destinazione.import(&documento, &operatore(), adesso()) else {
            panic!("l'importazione deve riuscire");
        };
        assert_eq!(
            esito.sources_added, 0,
            "un archivio vuoto non ha fonti da dare"
        );
    }

    /// **Un fascicolo con una fonte sbagliata non ne importa nessuna.**
    ///
    /// E' la prova che conta. Un ufficio configurato a meta' e' peggio di uno
    /// non configurato, perche' sembra a posto: chi guarda l'elenco troverebbe
    /// trentanove fonti su quaranta e non saprebbe quale manca.
    #[test]
    fn una_sola_fonte_sbagliata_ferma_tutta_l_importazione() {
        let mut destinazione = servizio();

        let corpo = FascicoloBody {
            sources: vec![
                fonte("canale_buono_uno", "Canale Buono Uno"),
                fonte("canale_buono_due", "Canale Buono Due"),
                // Un nome vuoto non e' un nome: il dominio lo rifiuta.
                SharedSource {
                    kind: String::from("channel"),
                    identifier: String::from("canale_rotto"),
                    display_name: String::new(),
                    authorized_by: String::from("responsabile.ufficio"),
                },
            ],
            dictionaries: Vec::new(),
            profile: None,
        };
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };

        assert!(
            destinazione
                .import(&documento, &operatore(), adesso())
                .is_err(),
            "un fascicolo con un valore non ammesso non deve essere importato"
        );

        let Ok(fonti) = destinazione.database().sources() else {
            panic!("le fonti devono potersi leggere");
        };
        assert!(
            fonti.is_empty(),
            "sono state scritte {} fonti su un fascicolo rifiutato: l'ufficio \
             risulta configurato a meta'",
            fonti.len()
        );
    }

    #[test]
    fn una_fonte_gia_presente_non_viene_duplicata() {
        let mut destinazione = servizio();

        let corpo = FascicoloBody {
            sources: vec![fonte("canale_uno", "Canale Uno")],
            dictionaries: Vec::new(),
            profile: None,
        };
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };

        let Ok(primo) = destinazione.import(&documento, &operatore(), adesso()) else {
            panic!("la prima importazione deve riuscire");
        };
        assert_eq!(primo.sources_added, 1);

        let Ok(secondo) = destinazione.import(&documento, &operatore(), adesso()) else {
            panic!("la seconda importazione deve riuscire");
        };
        assert_eq!(secondo.sources_added, 0);
        assert_eq!(secondo.sources_skipped, 1);

        let Ok(fonti) = destinazione.database().sources() else {
            panic!("le fonti devono potersi leggere");
        };
        assert_eq!(fonti.len(), 1, "la fonte e' stata duplicata");
    }

    /// **SEC-02: il fascicolo del solo utente, o niente** (ADR-0157). Il file lo
    /// scrive il servizio, e l'audit segue il file. Vista rossa il
    /// 2026-10-22 con la protezione tolta (mutazione di SEC-02).
    #[cfg(windows)]
    #[test]
    fn il_fascicolo_e_del_solo_utente_o_non_si_scrive() {
        let servizio = servizio();
        crate::permessi_di_prova::prova_un_uscita("fascicolo", |cartella| {
            let file = cartella.join("fascicolo.json");
            servizio
                .export_to_file(&file, "POSTAZIONE-01", &operatore(), adesso())
                .map(|consegnati| consegnati.files)
        });
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let esportati = voci
            .iter()
            .filter(|voce| voce.action.as_str() == "fascicolo_esportato")
            .count();
        assert_eq!(
            esportati, 1,
            "l'audit dice esportato anche il fascicolo rifiutato"
        );
    }

    #[test]
    fn importare_ed_esportare_lasciano_traccia() {
        // Chi rilegge l'audit deve poter sapere che la configurazione di questa
        // postazione e' arrivata da un'altra, e da quale.
        let mut servizio = servizio();
        let Ok(fascicolo) = servizio.export("POSTAZIONE-01", &operatore(), adesso()) else {
            panic!("l'esportazione deve riuscire");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };
        let Ok(_) = servizio.import(&documento, &operatore(), adesso()) else {
            panic!("l'importazione deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let azioni: Vec<&str> = voci.iter().map(|voce| voce.action.as_str()).collect();
        assert!(azioni.contains(&"fascicolo_esportato"));
        assert!(azioni.contains(&"fascicolo_importato"));

        let Some(importazione) = voci
            .iter()
            .find(|voce| voce.action.as_str() == "fascicolo_importato")
        else {
            panic!("l'importazione deve lasciare traccia");
        };
        let Some(dettaglio) = importazione.detail.as_ref() else {
            panic!("la traccia deve dire da dove veniva");
        };
        assert!(
            dettaglio.as_str().contains("POSTAZIONE-01"),
            "la traccia non dice da quale postazione: «{}»",
            dettaglio.as_str()
        );
    }

    #[test]
    fn un_documento_manomesso_non_viene_importato() {
        let mut destinazione = servizio();
        let corpo = FascicoloBody {
            sources: vec![fonte("canale_uno", "Canale Uno")],
            dictionaries: Vec::new(),
            profile: None,
        };
        let Ok(fascicolo) = Fascicolo::compose(provenienza(), corpo) else {
            panic!("il fascicolo deve potersi comporre");
        };
        let Ok(documento) = fascicolo.to_document() else {
            panic!("il fascicolo deve potersi scrivere");
        };
        let manomesso = documento.replace("Canale Uno", "Canale Due");

        let Err(errore) = destinazione.import(&manomesso, &operatore(), adesso()) else {
            panic!("un documento manomesso non deve essere importato");
        };
        let messaggio = errore.operator_message();
        assert!(
            messaggio.contains("impronta"),
            "il rifiuto deve dire QUALE controllo ha fallito: «{messaggio}»"
        );

        let Ok(fonti) = destinazione.database().sources() else {
            panic!("le fonti devono potersi leggere");
        };
        assert!(fonti.is_empty());
    }

    #[test]
    fn ogni_rifiuto_dice_quale_controllo_ha_fallito() {
        // «non importato» senza ragione manda chi legge a indovinare.
        for errore in [
            FascicoloError::TooLarge { bytes: 1 },
            FascicoloError::NotAFascicolo,
            FascicoloError::UnknownVersion { found: 99 },
            FascicoloError::DigestMismatch,
            FascicoloError::Malformed {
                reason: String::from("x"),
            },
            FascicoloError::Invalid {
                what: String::from("x"),
                reason: String::from("y"),
            },
        ] {
            let messaggio = errore.to_string();
            assert!(
                messaggio.len() > 30,
                "{errore:?} liquida il rifiuto in una parola: «{messaggio}»"
            );
        }
    }
}

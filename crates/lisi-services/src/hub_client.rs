//! Il ciclo vivo della postazione che si collega all'Hub (TEAM-CLIENT-01,
//! ADR-0091).
//!
//! # Che cosa c'è qui dentro
//!
//! L'**unica seconda destinazione** del trasporto: `lisi-hub-transport` resta
//! la sola crate che parla TLS, e questo modulo è il solo del prodotto che la
//! chiami. Tiene insieme quattro cose già decise — il canale (ADR-0083),
//! l'handshake (ADR-0084), la sequenza (ADR-0086) e il recupero (ADR-0087) — e
//! aggiunge ciò che mancava: **quando cominciare, quando fermarsi, e che cosa
//! non fare mai da soli**.
//!
//! # L'Hub si configura, non si scopre
//!
//! L'indirizzo è un IP letterale con la sua porta, conservato sotto DPAPI in un
//! file proprio, `hub-client.protetto`. Nessuna scoperta di rete, nessun nome da
//! risolvere: il dominio lo verifica ([`lisi_core::model::hub_client`]), qui si
//! conserva.
//!
//! # Come la postazione impara il nome della storia
//!
//! La versione 1 del protocollo non ha una domanda «quale storia segui»: ha il
//! recupero. Una postazione che ha già un cursore chiede **la propria** storia;
//! una postazione nuova chiede una storia che non esiste, e l'Hub risponde
//! dicendo la propria (`NotOurStream`, ADR-0086). Inventare una domanda nuova
//! avrebbe richiesto una versione nuova del protocollo, per una cosa che il
//! protocollo sa già dire.
//!
//! # L'Hub è autenticato, non fidato
//!
//! Ogni evento arrivato sul filo riattraversa i tipi del dominio. Uno che non
//! li attraversa **ferma la pagina**: scartarlo in silenzio lascerebbe un buco
//! che nessuno vede, e il numero successivo diventerebbe un salto senza
//! spiegazione.
//!
//! # Che cosa questo modulo non fa
//!
//! **Non dorme**: dice quanto aspettare ([`SessionReport::retry_delay`]), e chi
//! aspetta può essere interrotto da una persona. **Non acquisisce**: nessun
//! TDLib, nessuna credenziale Telegram, nessuna copia dell'archivio dell'Hub.
//! **Non riappunta** un'impronta diversa da quella già appuntata.

use core::str::FromStr;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use lisi_core::ContentId;
use lisi_core::NoteId;
use lisi_core::SessionId;
use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::coverage::{Coverage, CoverageInterval, CoverageState};
use lisi_core::model::enrollment::{EnrollmentCode, EnrollmentGrant, EnrollmentRefusal};
use lisi_core::model::hub_access::HubRole;
use lisi_core::model::hub_catchup::{CATCH_UP_PAGE, CatchUpStop, NextStep};
use lisi_core::model::hub_client::{HubAddress, HubConnection, PinVerdict, SessionLimits};
use lisi_core::model::hub_cyber::{MAX_SHARED_CYBER_PAGE, SharedCyberEvent, SharedIndicator};
use lisi_core::model::hub_event::{HUB_STREAM_ID_BYTES, HubEvent, HubEventKind, HubEventStreamId};
use lisi_core::model::hub_identity::{HubExpectation, HubFingerprint, HubFingerprintPrefix};
use lisi_core::model::hub_notes::{
    MAX_SHARED_NOTES_PAGE, MAX_SHARED_WORKSPACES_PAGE, MAX_WORKSPACE_ITEMS_PAGE, SharedNote,
    SharedWorkspace, SharedWorkspaceItem, SharedWorkspaceState,
};
use lisi_core::model::hub_person::{Passphrase, PersonId, PersonState};
use lisi_core::model::hub_presence::{PresenceSnapshot, PresentStation};
use lisi_core::model::hub_report::{MAX_SHARED_REPORTS_PAGE, SharedArtifact, SharedReport};
use lisi_core::model::hub_review::{
    MAX_REVIEW_BODY_CHARS, ReviewContent, ReviewItem, ReviewQueueCursor,
};
use lisi_core::model::identity::DeviceState;
use lisi_core::model::identity::{DeviceId, OperatorId};
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::model::report::ReportGenerationStatus;
use lisi_core::model::review::ReviewState;
use lisi_core::text::Note;
use lisi_core::text::{
    Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, HubEventDetail, HubEventSubject,
    SourceIdentifier,
};
use lisi_hub_transport::protocol::events::{
    ClientRequest, HubResponse, MAX_PAGE_EVENTS, MAX_PRESENCE_PAGE, MAX_SHARED_SESSIONS_PAGE,
    MAX_WORK_QUEUE_PAGE, PAGE_TIMEOUT, WireCyberEvent, WirePresentStation, WireReviewContent,
    WireReviewItem, WireSecret, WireSharedNote, WireSharedReport, WireSharedWorkspace,
    WireWorkItem, WireWorkspaceItem, read_response, send_request,
};
use lisi_hub_transport::protocol::events::{MAX_REMOTE_REASON_CHARS, WireCoverageStretch};
use lisi_hub_transport::protocol::handshake::{
    ClientOffer, EnrollmentAnswer, EnrollmentRefusalReason, HandshakeError, RefusalReason,
    client_enroll, client_handshake,
};
use lisi_hub_transport::protocol::negotiation::VersionRange;
use lisi_hub_transport::protocol::negotiation::{
    CAPABILITY_ASSIGNMENT, CAPABILITY_PERSON, CAPABILITY_PRESENCE, CAPABILITY_SHARED_CYBER,
    CAPABILITY_SHARED_NOTES, CAPABILITY_SHARED_REPORTS, CAPABILITY_SHARED_SESSIONS,
    CAPABILITY_SHARED_WORKSPACES, CAPABILITY_WORK_QUEUE,
};
use lisi_hub_transport::protocol::negotiation::{
    CAPABILITY_REMOTE_COMMANDS, CAPABILITY_SHARED_COVERAGE,
};
use lisi_hub_transport::{ClientLimits, ConnectOutcome, HubClientStream, RetryPolicy, connect};
use lisi_security::{ProtectedStore, SecurityError};

use crate::device_identity::DeviceIdentityService;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_catchup::HubCatchUpService;
use crate::preflight::HubReachability;

/// Nome del file protetto con la configurazione dell'Hub **che questa
/// postazione segue**.
///
/// # Perché non si chiama `hub.protetto`
///
/// Perché quel nome è già della **chiave privata dell'Hub**
/// (`lisi_security::hub_key::HUB_KEY_FILE`, ADR-0083 decisione 3), e i due file
/// vivono nella stessa cartella. Con lo stesso nome, su una postazione che fa
/// da Hub la presenza della chiave si sarebbe letta come «questa postazione
/// segue un Hub»: l'Hub stesso avrebbe smesso di poter acquisire
/// (TEAM-AUTHORITY-01, ADR-0092), e la diagnosi sarebbe stata cercata
/// ovunque tranne che in un nome di file. Trovato costruendo TEAM-LIVE-01, e
/// corretto prima che una postazione vera scrivesse il file.
pub const HUB_FILE: &str = "hub-client.protetto";

/// Chiave dell'indirizzo.
const ADDRESS_KEY: &str = "hub_address";
/// Chiave della forma dell'attesa: `prefisso` oppure `impronta`.
const EXPECTATION_KIND_KEY: &str = "hub_expectation_kind";
/// Chiave del valore dell'attesa.
const EXPECTATION_KEY: &str = "hub_expectation";

/// Valore della forma «i 120 bit del foglietto».
const KIND_PREFIX: &str = "prefisso";
/// Valore della forma «i 256 bit appuntati».
const KIND_PINNED: &str = "impronta";

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "collegamento_hub";
/// Soggetto degli atti decisi dal collegamento, non da una persona.
const AUDIT_AUTHORITY: &str = "hub.collegamento";

const AUDIT_CONFIGURED: &str = "hub_configurato";
const AUDIT_PINNED: &str = "impronta_hub_appuntata";
const AUDIT_REFUSED: &str = "impronta_hub_rifiutata";
const AUDIT_MALFORMED: &str = "evento_hub_malformato";
const AUDIT_EVENT: &str = "evento_hub_applicato";
const AUDIT_TRUNCATED: &str = "sessione_hub_interrotta_da_un_tetto";
const AUDIT_ENROLLMENT_REFUSED: &str = "arruolamento_rifiutato_dall_hub";

/// Percorso predefinito del file della configurazione dell'Hub.
///
/// Accanto agli altri file protetti, sotto la stessa cartella dati protetta dal
/// profilo.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati locale non è determinabile.
pub fn default_hub_path() -> ServiceResult<PathBuf> {
    let cartella =
        crate::data_directory::mode_directory().ok_or_else(|| ServiceError::HubClient {
            reason: String::from("cartella dati locale non determinabile"),
        })?;
    Ok(cartella.join(HUB_FILE))
}

/// La configurazione dell'Hub, conservata.
#[derive(Debug)]
pub struct HubConnectionStore {
    store: ProtectedStore,
}

impl HubConnectionStore {
    /// Archivio sul file indicato.
    #[must_use]
    pub const fn at(store: ProtectedStore) -> Self {
        Self { store }
    }

    /// Archivio nella cartella indicata, accanto agli altri file protetti.
    ///
    /// Esiste perche' chi sta sopra i servizi non debba nominare
    /// `ProtectedStore`: il confine di ADR-0010 vale anche qui.
    #[must_use]
    pub fn in_directory(base: &std::path::Path) -> Self {
        Self::at(ProtectedStore::at(base.join(HUB_FILE)))
    }

    /// Archivio sul percorso predefinito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cartella dati locale non è determinabile.
    pub fn default_location() -> ServiceResult<Self> {
        Ok(Self::at(ProtectedStore::at(default_hub_path()?)))
    }

    /// Vero se questa postazione ha un Hub configurato.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.store.exists()
    }

    /// Legge la configurazione.
    ///
    /// Una postazione senza il file **non ha** un Hub, e non è un errore: è una
    /// postazione Standalone. Un file presente e illeggibile **è** un errore:
    /// leggerlo come «nessun Hub» significherebbe tornare Standalone in
    /// silenzio, cioè smettere di seguire l'Hub senza che nessuno lo abbia
    /// deciso.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il file esiste ma non è decifrabile con il
    /// profilo corrente, o se il contenuto non è interpretabile.
    pub fn load(&self) -> ServiceResult<Option<HubConnection>> {
        if !self.store.exists() {
            return Ok(None);
        }
        let voci = self.store.load().map_err(map_security_error)?;
        let indirizzo = HubAddress::parse(campo(&voci, ADDRESS_KEY)?)?;
        let attesa = match campo(&voci, EXPECTATION_KIND_KEY)? {
            KIND_PREFIX => HubExpectation::Enrollment(HubFingerprintPrefix::parse(campo(
                &voci,
                EXPECTATION_KEY,
            )?)?),
            KIND_PINNED => {
                HubExpectation::Pinned(HubFingerprint::from_hex(campo(&voci, EXPECTATION_KEY)?)?)
            }
            _ => {
                return Err(ServiceError::HubClient {
                    reason: String::from(
                        "la configurazione dell'Hub non dice quale chiave questa postazione \
                         attende",
                    ),
                });
            }
        };
        Ok(Some(HubConnection::new(indirizzo, attesa)))
    }

    /// Scrive la configurazione, sostituendo quella che c'era.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura protetta non riesce.
    pub fn save(&self, connection: &HubConnection) -> ServiceResult<()> {
        let mut voci = BTreeMap::new();
        voci.insert(String::from(ADDRESS_KEY), connection.address.to_string());
        let (forma, valore) = match connection.expectation {
            HubExpectation::Enrollment(prefisso) => (KIND_PREFIX, prefisso.to_readable()),
            HubExpectation::Pinned(impronta) => (KIND_PINNED, impronta.to_hex()),
        };
        voci.insert(String::from(EXPECTATION_KIND_KEY), String::from(forma));
        voci.insert(String::from(EXPECTATION_KEY), valore);
        self.store.save(&voci).map_err(map_security_error)
    }
}

/// Perché una sessione con l'Hub non ha portato la postazione in pari.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationReason {
    /// Il tetto delle pagine.
    PageLimit,
    /// Il tetto degli eventi.
    EventLimit,
    /// Il tetto della durata.
    TimeLimit,
    /// L'Hub dichiara di essere più avanti, ma la pagina non ha fatto avanzare
    /// nulla: chiedere di nuovo la stessa pagina sarebbe un ciclo.
    NoProgress,
}

impl TruncationReason {
    /// La frase per l'operatore: dice il fatto, e che la prossima sessione
    /// riprende da dove questa si è fermata.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::PageLimit | Self::EventLimit | Self::TimeLimit => {
                "La postazione non è arrivata in pari in questa sessione: si è fermata a un \
                 limite previsto. La prossima ripartirà dal punto raggiunto."
            }
            Self::NoProgress => {
                "L'Hub dichiara di avere altri eventi ma non ne ha consegnato alcuno: la \
                 sessione si è chiusa invece di richiedere la stessa pagina."
            }
        }
    }

    /// L'etichetta per l'audit.
    const fn label(self) -> &'static str {
        match self {
            Self::PageLimit => "tetto delle pagine",
            Self::EventLimit => "tetto degli eventi",
            Self::TimeLimit => "tetto della durata",
            Self::NoProgress => "pagina che non fa avanzare nulla",
        }
    }
}

/// Com'è finita una sessione con l'Hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutcome {
    /// La postazione è in pari con l'Hub.
    CaughtUp {
        /// L'ultimo numero che l'Hub dichiara.
        latest: u64,
    },
    /// La sessione è finita a un limite: la postazione resta indietro.
    Truncated {
        /// Quale limite.
        reason: TruncationReason,
    },
    /// Il recupero si è fermato e **non riprenderà da solo** (ADR-0087).
    Stopped {
        /// Perché.
        stop: CatchUpStop,
    },
    /// L'Hub non risponde. **È l'unico esito ripetibile.**
    Unreachable,
    /// Ha risposto qualcuno che non è l'Hub atteso, o l'impronta non è quella
    /// appuntata. **Non si riprova da soli.**
    NotTheExpectedHub,
    /// L'Hub ha rifiutato questa postazione, o l'handshake non si è concluso.
    Refused {
        /// Che cosa dire all'operatore. Una costante: nessun dato ricevuto.
        reason: &'static str,
    },
    /// L'Hub ha risposto qualcosa che il protocollo non prevede in quel punto,
    /// o un evento che non attraversa i tipi del dominio.
    UnexpectedAnswer {
        /// Che cosa dire all'operatore. Una costante.
        reason: &'static str,
    },
}

/// Che cosa una sessione ha fatto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReport {
    /// Com'è finita.
    pub outcome: SessionOutcome,
    /// Eventi applicati.
    pub applied: usize,
    /// Eventi già visti, scartati.
    pub duplicates: usize,
    /// Pagine chieste.
    pub pages: u32,
    /// Se l'impronta intera è stata appuntata in questa sessione.
    pub pinned: bool,
}

impl SessionReport {
    /// Quanto aspettare prima del tentativo numero `next_attempt`, o `None` se
    /// **non si riprova**.
    ///
    /// Si riprova soltanto il silenzio (ADR-0083, decisione 6). Questo modulo
    /// non dorme: chi aspetta è il chiamante, che una persona può interrompere.
    #[must_use]
    pub fn retry_delay(&self, policy: &RetryPolicy, next_attempt: u32) -> Option<Duration> {
        if self.outcome != SessionOutcome::Unreachable {
            return None;
        }
        policy.delay_before(
            next_attempt,
            &lisi_hub_transport::TransportError::Unreachable,
        )
    }

    /// Un rapporto senza nulla fatto, con l'esito indicato.
    const fn only(outcome: SessionOutcome) -> Self {
        Self {
            outcome,
            applied: 0,
            duplicates: 0,
            pages: 0,
            pinned: false,
        }
    }
}

/// Ciò che una persona ricopia dal foglietto, già riconosciuto (ADR-0132).
///
/// Si costruisce solo con [`Self::parse`], che dice **quale** campo non va e
/// non ripete mai il codice nel messaggio.
#[derive(Debug)]
pub struct EnrollmentForm {
    address: HubAddress,
    fingerprint: HubFingerprintPrefix,
    code: EnrollmentCode,
    label: DisplayName,
}

impl EnrollmentForm {
    /// Riconosce i quattro campi del modulo «Collega questa postazione a un
    /// Hub».
    ///
    /// # Errori
    ///
    /// Restituisce la frase da mostrare a chi compila, che nomina il campo
    /// sbagliato e dice che cosa scriverci.
    pub fn parse(
        address: &str,
        fingerprint: &str,
        code: &str,
        label: &str,
    ) -> Result<Self, String> {
        let address = HubAddress::parse(address.trim()).map_err(|_| {
            String::from(
                "L'indirizzo dell'Hub non è utilizzabile. Scrivere l'indirizzo in cifre con la \
                 sua porta, come sul foglietto, per esempio 192.168.1.10:8443.",
            )
        })?;
        let fingerprint = HubFingerprintPrefix::parse(fingerprint).map_err(|_| {
            String::from(
                "L'impronta dell'Hub non è scritta per intero. Sono 24 cifre in sei gruppi da \
                 quattro: ricopiarle tutte dal foglietto.",
            )
        })?;
        let code = EnrollmentCode::parse(code).map_err(|_| {
            String::from(
                "Il codice di arruolamento non è scritto per intero. Sono 16 cifre in quattro \
                 gruppi da quattro: ricopiarle dal foglietto.",
            )
        })?;
        let label = DisplayName::try_new(label.trim()).map_err(|_| {
            String::from(
                "Il nome della postazione manca o non è utilizzabile. Scrivere un nome che chi \
                 amministra l'Hub riconosca, per esempio il nome della stanza.",
            )
        })?;
        Ok(Self {
            address,
            fingerprint,
            code,
            label,
        })
    }
}

/// L'esito di «Collega a questo Hub» (ADR-0132).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentAttempt {
    /// L'Hub ha ammesso la postazione, e il collegamento è salvato.
    Admitted {
        /// L'Hub che l'ha ammessa.
        hub: DisplayName,
    },
    /// L'Hub conosceva già la postazione: mancava solo il collegamento, che
    /// ora è salvato.
    AlreadyAdmitted {
        /// L'Hub che l'aveva ammessa.
        hub: DisplayName,
    },
    /// L'Hub ha rifiutato.
    Refused(EnrollmentRefusal),
    /// L'Hub non è riuscito a registrare la richiesta.
    HubFault,
    /// Nessuno risponde all'indirizzo.
    Unreachable,
    /// All'indirizzo risponde una chiave diversa da quella del foglietto. **Il
    /// codice non è partito.**
    NotTheExpectedHub,
    /// L'Hub non sa ricevere un arruolamento dalla rete.
    HubDoesNotEnroll,
    /// La richiesta è partita e la risposta non è arrivata.
    NoAnswer,
    /// L'Hub ha risposto in un modo che questa postazione non sa leggere.
    UnexpectedAnswer,
}

impl EnrollmentAttempt {
    /// Vero se da ora la postazione segue l'Hub.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(self, Self::Admitted { .. } | Self::AlreadyAdmitted { .. })
    }

    /// Che cosa è successo, che cosa significa, che cosa fare.
    #[must_use]
    pub fn operator_message(&self) -> String {
        const RESTA: &str = "La postazione resta da sola, come prima.";
        match self {
            Self::Admitted { hub } => format!(
                "La postazione è collegata all'Hub «{}». Da ora segue l'Hub e non acquisisce più \
                 da sola. Premere «Aggiorna dall'Hub» per ricevere ciò che l'Hub ha visto.",
                hub.as_str()
            ),
            Self::AlreadyAdmitted { hub } => format!(
                "L'Hub «{}» conosceva già questa postazione: mancava solo il collegamento, ora \
                 salvato. Da ora la postazione segue l'Hub e non acquisisce più da sola.",
                hub.as_str()
            ),
            Self::Refused(motivo) => format!(
                "L'Hub ha rifiutato il collegamento. {} {RESTA}",
                motivo.operator_message()
            ),
            Self::HubFault => format!(
                "L'Hub non è riuscito a registrare la richiesta. {RESTA} Riprovare fra poco; se \
                 succede ancora, chi amministra l'Hub deve aprire la Diagnostica."
            ),
            Self::Unreachable => format!(
                "L'Hub non risponde all'indirizzo scritto. {RESTA} Controllare l'indirizzo sul \
                 foglietto, e chiedere a chi amministra se la modalità Hub è attiva."
            ),
            Self::NotTheExpectedHub => format!(
                "All'indirizzo scritto risponde una chiave diversa dall'impronta del foglietto. \
                 Il codice non è stato mandato. {RESTA} Ricontrollare le 24 cifre; se sono \
                 giuste, avvisare chi amministra l'Hub prima di riprovare."
            ),
            Self::HubDoesNotEnroll => format!(
                "L'Hub a questo indirizzo non sa ricevere un collegamento dalla rete: è una \
                 versione precedente del programma. {RESTA} Chi amministra l'Hub deve \
                 aggiornarlo, poi emettere un codice nuovo."
            ),
            Self::NoAnswer => format!(
                "La richiesta è partita, ma la risposta dell'Hub non è arrivata. {RESTA} Chiedere \
                 a chi amministra se l'Hub ha registrato la postazione prima di riprovare."
            ),
            Self::UnexpectedAnswer => format!(
                "L'Hub ha risposto in un modo che questa postazione non sa leggere. {RESTA} \
                 Riferirlo a chi amministra, con l'ora."
            ),
        }
    }
}

/// Il rifiuto del filo, riportato al tipo del dominio.
///
/// La ragione di un ritiro non viaggia: si scrive quella generica, perché chi
/// la legge sappia a chi chiedere.
fn rifiuto_dal_filo(
    reason: EnrollmentRefusalReason,
    retry_in_minutes: Option<i64>,
) -> ServiceResult<Option<EnrollmentRefusal>> {
    Ok(Some(match reason {
        EnrollmentRefusalReason::HubFault => return Ok(None),
        EnrollmentRefusalReason::CodeNotRecognised => EnrollmentRefusal::CodeNotRecognised,
        EnrollmentRefusalReason::CodeExpired => EnrollmentRefusal::CodeExpired,
        EnrollmentRefusalReason::CodeAlreadyUsed => EnrollmentRefusal::CodeAlreadyUsed,
        EnrollmentRefusalReason::DeviceAlreadyEnrolled => EnrollmentRefusal::DeviceAlreadyEnrolled,
        EnrollmentRefusalReason::DeviceRevoked => EnrollmentRefusal::DeviceRevoked {
            reason: Note::try_new("la ragione la conosce chi amministra l'Hub")?,
        },
        EnrollmentRefusalReason::TooManyRecentFailures => {
            EnrollmentRefusal::TooManyRecentFailures {
                retry_in_minutes: retry_in_minutes.unwrap_or(15).clamp(1, 15),
            }
        }
    }))
}

/// La postazione collegata all'Hub.
#[derive(Debug)]
pub struct HubClientService {
    catch_up: HubCatchUpService,
    identity: DeviceIdentityService,
    connection: HubConnectionStore,
    limits: ClientLimits,
    session: SessionLimits,
    /// Le reti dell'ufficio di questa postazione (HUB-SITES-01, ADR-0198).
    /// Senza, valgono gli intervalli che Internet non instrada.
    networks: Option<crate::office_networks::OfficeNetworksStore>,
}

impl HubClientService {
    /// Costruisce il servizio con i tetti predefiniti.
    #[must_use]
    pub const fn new(
        catch_up: HubCatchUpService,
        identity: DeviceIdentityService,
        connection: HubConnectionStore,
    ) -> Self {
        Self {
            catch_up,
            identity,
            connection,
            limits: ClientLimits {
                connect_timeout: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(10),
                io_timeout: Duration::from_secs(60),
            },
            session: SessionLimits {
                max_pages: 64,
                max_events: 10_000,
                max_duration: Duration::from_secs(120),
            },
            networks: None,
        }
    }

    /// Legge le reti dell'ufficio da questo archivio protetto.
    #[must_use]
    pub fn with_office_networks(
        mut self,
        networks: crate::office_networks::OfficeNetworksStore,
    ) -> Self {
        self.networks = Some(networks);
        self
    }

    /// Legge le reti dell'ufficio dal percorso predefinito della postazione.
    /// Se la cartella non si determina restano le reti predefinite.
    #[must_use]
    pub fn with_default_office_networks(self) -> Self {
        match crate::office_networks::OfficeNetworksStore::default_location() {
            Ok(archivio) => self.with_office_networks(archivio),
            Err(_) => self,
        }
    }

    /// Rifiuta un Hub fuori dalle reti dell'ufficio: un Hub che Internet
    /// raggiunge non si segue (ADR-0198, decisione 5).
    fn dentro_le_reti(&self, address: &HubAddress) -> ServiceResult<()> {
        let reti = match &self.networks {
            Some(archivio) => archivio.load()?,
            None => lisi_core::model::office_network::OfficeNetworks::default(),
        };
        if reti.admits(address.as_socket_addr().ip()) {
            return Ok(());
        }
        Err(ServiceError::HubClient {
            reason: String::from(
                "l'indirizzo dell'Hub non è nelle reti dell'ufficio di questa postazione: un \
                 Hub che Internet raggiunge non si segue. Se l'ufficio usa questo indirizzo al \
                 proprio interno, va dichiarato fra le reti dell'ufficio",
            ),
        })
    }

    /// Sostituisce i tetti. Serve alle prove, e a un ufficio che ne misuri di
    /// propri.
    #[must_use]
    pub const fn with_limits(mut self, limits: ClientLimits, session: SessionLimits) -> Self {
        self.limits = limits;
        self.session = session;
        self
    }

    /// I tetti di una sessione **chiesta da una schermata**.
    ///
    /// Una schermata chiede e aspetta: due minuti di recupero, che vanno bene
    /// per un ciclo di sottofondo, sarebbero due minuti di finestra ferma.
    /// Questa sessione è breve, e ciò che resta indietro lo recupera la
    /// richiesta successiva — il cursore è conservato, quindi nulla si perde.
    ///
    /// Esiste qui e non nell'interfaccia perché i tetti del trasporto sono tipi
    /// di `lisi-hub-transport`, che l'interfaccia non può nominare (ADR-0010).
    #[must_use]
    pub const fn with_screen_limits(mut self) -> Self {
        self.limits = ClientLimits {
            connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
        };
        self.session = SessionLimits {
            max_pages: 8,
            max_events: 2_000,
            max_duration: Duration::from_secs(10),
        };
        self
    }

    /// Il recupero sottostante, per chi deve leggere il cursore o dimenticarlo.
    #[must_use]
    pub const fn catch_up(&self) -> &HubCatchUpService {
        &self.catch_up
    }

    /// La configurazione conservata, se c'è.
    ///
    /// # Errori
    ///
    /// Gli stessi di [`HubConnectionStore::load`].
    pub fn connection(&self) -> ServiceResult<Option<HubConnection>> {
        self.connection.load()
    }

    /// Configura l'Hub di questa postazione. **Atto di una persona**, e l'audit
    /// ne porta l'identificativo.
    ///
    /// Sostituisce la configurazione precedente: è il gesto con cui un ufficio
    /// dichiara, con un foglietto nuovo in mano, che l'Hub è un altro.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura protetta o l'audit non riescono.
    pub fn configure(
        &self,
        connection: &HubConnection,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.connection.save(connection)?;
        self.scrivi(
            operator.audit_actor()?,
            AUDIT_CONFIGURED,
            &format!("Hub all'indirizzo {}", connection.address),
            now,
        )
    }

    /// **Collega questa postazione a un Hub** (ADR-0132): arruola il
    /// dispositivo presso l'Hub del foglietto e, se l'Hub accetta, salva il
    /// collegamento con l'impronta intera appena verificata.
    ///
    /// # L'ordine, e perché
    ///
    /// 1. L'identità di dispositivo esiste, o si crea (ADR-0046).
    /// 2. Il canale si apre con l'attesa del foglietto: **il codice esce solo
    ///    verso la chiave dei 120 bit**, e il confronto si ripete qui prima di
    ///    scrivere (ADR-0082 decisione 2).
    /// 3. Prima si registra l'ammissione in `device.protetto`, poi il
    ///    collegamento in `hub-client.protetto`: nell'ordine opposto un guasto
    ///    lascerebbe una postazione che segue un Hub senza sapersi presentare.
    ///
    /// Dal momento in cui il collegamento è scritto la postazione segue l'Hub:
    /// non ha più l'autorità di acquisire (ADR-0092) e non apre Telegram.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la postazione segue già un Hub, se l'identità
    /// non si crea o non si legge, se i tetti non sono utilizzabili, o se una
    /// scrittura locale non riesce. **Un Hub che rifiuta, che non risponde o
    /// che non è quello del foglietto non è un errore**: è un esito.
    pub fn enroll(
        &self,
        form: EnrollmentForm,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<EnrollmentAttempt> {
        if self.connection.exists() {
            return Err(ServiceError::HubClient {
                reason: String::from(
                    "questa postazione segue già un Hub. Per cambiarlo serve chi amministra, con un \
                     foglietto nuovo",
                ),
            });
        }
        if !self.limits.is_usable() {
            return Err(ServiceError::HubClient {
                reason: String::from(
                    "i tetti del collegamento all'Hub non sono utilizzabili: una durata nulla non \
                     è «nessun limite»",
                ),
            });
        }
        let EnrollmentForm {
            address,
            fingerprint,
            code,
            label,
        } = form;
        self.dentro_le_reti(&address)?;
        let database = self.catch_up.database();
        let identita = self.identity.ensure(database, &label, operator, now)?;
        let preparata = self.identity.prepare_enrollment(code)?;

        let mut canale = match connect(
            address.as_socket_addr(),
            HubExpectation::Enrollment(fingerprint),
            &self.limits,
        ) {
            Ok(canale) => canale,
            Err(errore) => {
                return Ok(match errore.outcome() {
                    ConnectOutcome::HubUnreachable => EnrollmentAttempt::Unreachable,
                    ConnectOutcome::NotTheExpectedHub => EnrollmentAttempt::NotTheExpectedHub,
                    ConnectOutcome::LocalFault => EnrollmentAttempt::UnexpectedAnswer,
                });
            }
        };

        // IL SECONDO CONTROLLO, prima che il codice parta: il verificatore TLS
        // ha gia' confrontato i 120 bit, e un suo difetto futuro non deve
        // diventare un codice consegnato a chiunque (ADR-0132, decisione 2).
        let impronta = canale.hub_fingerprint();
        if !fingerprint.matches(&impronta) {
            canale.close();
            return Ok(EnrollmentAttempt::NotTheExpectedHub);
        }

        let risposta = client_enroll(&mut canale, &preparata.request, VersionRange::SUPPORTED);
        canale.close();

        match risposta {
            Ok(EnrollmentAnswer::Admitted {
                hub,
                enrolled_at_ms,
            }) => {
                // Il nome viene dall'Hub: dato remoto, riattraversa il tipo.
                let Ok(hub) = DisplayName::try_new(&hub) else {
                    return Ok(EnrollmentAttempt::UnexpectedAnswer);
                };
                let concessione = EnrollmentGrant {
                    hub: hub.clone(),
                    enrolled_at: Timestamp::from_millis(enrolled_at_ms),
                };
                self.identity
                    .record_grant(database, &concessione, &preparata.salt, operator)?;
                self.salva_il_collegamento(address, impronta, operator, now)?;
                Ok(EnrollmentAttempt::Admitted { hub })
            }
            Ok(EnrollmentAnswer::Refused {
                reason: EnrollmentRefusalReason::DeviceAlreadyEnrolled,
                ..
            }) => {
                // L'AMMISSIONE C'ERA E IL COLLEGAMENTO NO: la volta precedente
                // la seconda scrittura non era riuscita. La postazione ha gia'
                // il sale con cui presentarsi, e scrive cio' che mancava.
                if let DeviceState::Enrolled { hub, .. } = identita.state {
                    self.salva_il_collegamento(address, impronta, operator, now)?;
                    return Ok(EnrollmentAttempt::AlreadyAdmitted { hub });
                }
                self.registra_il_rifiuto("dispositivo_gia_arruolato", operator, now)?;
                Ok(EnrollmentAttempt::Refused(
                    EnrollmentRefusal::DeviceAlreadyEnrolled,
                ))
            }
            Ok(EnrollmentAnswer::Refused {
                reason,
                retry_in_minutes,
            }) => {
                let Some(motivo) = rifiuto_dal_filo(reason, retry_in_minutes)? else {
                    return Ok(EnrollmentAttempt::HubFault);
                };
                self.registra_il_rifiuto(motivo.audit_detail(), operator, now)?;
                Ok(EnrollmentAttempt::Refused(motivo))
            }
            Err(HandshakeError::Refused {
                reason: RefusalReason::Malformed | RefusalReason::UnsupportedVersion,
                ..
            }) => Ok(EnrollmentAttempt::HubDoesNotEnroll),
            Err(HandshakeError::Frame(_)) => Ok(EnrollmentAttempt::NoAnswer),
            Err(_) => Ok(EnrollmentAttempt::UnexpectedAnswer),
        }
    }

    /// Scrive il collegamento con l'impronta **intera** appena verificata.
    ///
    /// La connessione dell'arruolamento è la prima connessione verificata: il
    /// restringimento da prefisso a impronta intera avviene qui, una volta
    /// (ADR-0091 decisione 3, ADR-0132 decisione 3).
    fn salva_il_collegamento(
        &self,
        address: HubAddress,
        impronta: HubFingerprint,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.connection.save(&HubConnection::new(
            address,
            HubExpectation::Pinned(impronta),
        ))?;
        self.scrivi(
            operator.audit_actor()?,
            AUDIT_CONFIGURED,
            &format!("Hub all'indirizzo {address}, impronta appuntata all'arruolamento"),
            now,
        )
    }

    /// Registra che l'Hub ha rifiutato. **Il codice non c'è**: c'è la ragione.
    fn registra_il_rifiuto(
        &self,
        ragione: &str,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.scrivi(
            operator.audit_actor()?,
            AUDIT_ENROLLMENT_REFUSED,
            ragione,
            now,
        )
    }

    /// **Il controllo di avvio**: l'Hub risponde, ed è quello atteso? (PR-04,
    /// ADR-0120).
    ///
    /// # Che cosa fa, e che cosa non fa
    ///
    /// Apre il canale cifrato, legge la chiave che l'Hub presenta, la confronta
    /// con quella attesa e **chiude**. Non si presenta, non chiede nulla, non
    /// recupera eventi: all'Hub non resta una sessione né una presenza, e sulla
    /// postazione non resta nulla — **nemmeno l'impronta**, che al primo
    /// collegamento verificato una sessione vera appunterebbe. Qui la si
    /// confronta e basta: appuntarla sarebbe una scrittura, e il controllo non
    /// ne fa.
    ///
    /// Con i tetti di questo servizio: il controllo di avvio lo costruisce con
    /// quelli delle schermate, i più stretti.
    #[must_use]
    pub fn probe(&self) -> HubReachability {
        let configurazione = match self.connection.load() {
            Ok(Some(configurazione)) => configurazione,
            Ok(None) => return HubReachability::NotConfigured,
            Err(_) => return HubReachability::NotUsable,
        };
        if !self.limits.is_usable() || self.dentro_le_reti(&configurazione.address).is_err() {
            return HubReachability::NotUsable;
        }

        match connect(
            configurazione.address.as_socket_addr(),
            configurazione.expectation,
            &self.limits,
        ) {
            Ok(canale) => {
                let verdetto = lisi_core::model::hub_client::pin_verdict(
                    configurazione.expectation,
                    canale.hub_fingerprint(),
                );
                canale.close();
                match verdetto {
                    PinVerdict::Refused => HubReachability::NotTheExpectedHub,
                    PinVerdict::Pin(_) | PinVerdict::Unchanged => HubReachability::Reachable,
                }
            }
            Err(errore) => match errore.outcome() {
                ConnectOutcome::HubUnreachable => HubReachability::Unreachable,
                ConnectOutcome::NotTheExpectedHub => HubReachability::NotTheExpectedHub,
                ConnectOutcome::LocalFault => HubReachability::NotUsable,
            },
        }
    }

    /// Una sessione con l'Hub, applicando ogni evento con l'applicatore
    /// predefinito: **una riga di audit**.
    ///
    /// La postazione non riceve l'archivio dell'Hub e non ne tiene una copia
    /// (ADR-0091, decisione 8).
    ///
    /// # Errori
    ///
    /// Vedere [`Self::run_session_with`].
    pub fn run_session(&self, now: Timestamp) -> ServiceResult<SessionReport> {
        self.run_session_with(now, |evento| self.registra_evento(evento, now))
    }

    /// Una sessione con l'Hub, applicando ogni evento con `applica`.
    ///
    /// `applica` deve **persistere** ciò che significa applicare l'evento, ed
    /// essere ripetibile: un arresto in mezzo lascia l'ultimo evento da
    /// riapplicare (ADR-0087).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la postazione non ha un Hub configurato, se non
    /// ha un'identità arruolata, se i tetti non sono utilizzabili, o se
    /// l'archivio locale non si lascia scrivere. **Un Hub che non risponde, che
    /// rifiuta o che non è quello atteso non è un errore**: è un esito, e sta
    /// in [`SessionReport::outcome`].
    pub fn run_session_with<A>(
        &self,
        now: Timestamp,
        mut applica: A,
    ) -> ServiceResult<SessionReport>
    where
        A: FnMut(&HubEvent) -> ServiceResult<()>,
    {
        let Some(configurazione) = self.connection.load()? else {
            return Err(ServiceError::HubClient {
                reason: String::from(
                    "questa postazione non ha un Hub configurato: non c'è nulla a cui collegarsi",
                ),
            });
        };
        if !self.limits.is_usable() || !self.session.is_usable() {
            return Err(ServiceError::HubClient {
                reason: String::from(
                    "i tetti del collegamento all'Hub non sono utilizzabili: una durata o un \
                     tetto nullo non è «nessun limite»",
                ),
            });
        }
        let Some(identita) = self.identity.load()? else {
            return Err(ServiceError::HubClient {
                reason: String::from(
                    "questa postazione non ha un'identità di dispositivo: non può presentarsi a \
                     un Hub",
                ),
            });
        };
        let gettone = self.identity.token()?;
        self.dentro_le_reti(&configurazione.address)?;

        let inizio = Instant::now();
        let mut canale = match connect(
            configurazione.address.as_socket_addr(),
            configurazione.expectation,
            &self.limits,
        ) {
            Ok(canale) => canale,
            Err(errore) => {
                return Ok(SessionReport::only(match errore.outcome() {
                    ConnectOutcome::HubUnreachable => SessionOutcome::Unreachable,
                    ConnectOutcome::NotTheExpectedHub => SessionOutcome::NotTheExpectedHub,
                    ConnectOutcome::LocalFault => SessionOutcome::Refused {
                        reason: "il collegamento all'Hub non si è potuto costruire su questa \
                                 postazione: indirizzo o configurazione non utilizzabili",
                    },
                }));
            }
        };

        // L'impronta si decide PRIMA di parlare: il canale è già autenticato
        // dal trasporto, e questo è il secondo controllo, quello che decide se
        // la configurazione cambia.
        let presentata = canale.hub_fingerprint();
        let appuntata =
            match lisi_core::model::hub_client::pin_verdict(configurazione.expectation, presentata)
            {
                PinVerdict::Pin(impronta) => {
                    self.connection.save(&HubConnection::new(
                        configurazione.address,
                        HubExpectation::Pinned(impronta),
                    ))?;
                    self.registra(
                        AUDIT_PINNED,
                        "la prima connessione verificata ha appuntato l'impronta intera dell'Hub",
                        now,
                    )?;
                    true
                }
                PinVerdict::Unchanged => false,
                PinVerdict::Refused => {
                    canale.close();
                    self.registra(
                        AUDIT_REFUSED,
                        "l'Hub ha presentato una chiave diversa da quella appuntata: la \
                     configurazione non è stata modificata",
                        now,
                    )?;
                    return Ok(SessionReport::only(SessionOutcome::NotTheExpectedHub));
                }
            };

        if let Err(errore) =
            client_handshake(&mut canale, &identita.id, &gettone, &ClientOffer::default())
        {
            canale.close();
            let mut rapporto = SessionReport::only(handshake_outcome(&errore));
            rapporto.pinned = appuntata;
            return Ok(rapporto);
        }

        let esito = self.catch_up_loop(&mut canale, now, inizio, &mut applica);
        canale.close();
        let mut rapporto = esito?;
        rapporto.pinned = appuntata;
        Ok(rapporto)
    }

    /// Apre una sessione per la **revisione condivisa** (TEAM-REVIEW-01,
    /// ADR-0094).
    ///
    /// Fa le stesse due verifiche di una sessione ordinaria — l'Hub atteso, il
    /// gettone — e in più controlla la **versione negoziata**: i messaggi della
    /// revisione esistono dalla versione 2, e un Hub più vecchio non li
    /// capirebbe (ADR-0094, decisione 6).
    ///
    /// # Errori
    ///
    /// Gli stessi di [`Self::run_session_with`] per ciò che impedisce di
    /// cominciare. Un Hub che non risponde, che rifiuta o che non è quello
    /// atteso **non è un errore**: è un esito.
    pub fn open_review_session(&self, now: Timestamp) -> ServiceResult<ReviewSessionOutcome> {
        let Some(configurazione) = self.connection.load()? else {
            return Err(ServiceError::HubClient {
                reason: String::from(
                    "questa postazione non ha un Hub configurato: non c'è nulla a cui collegarsi",
                ),
            });
        };
        if !self.limits.is_usable() {
            return Err(ServiceError::HubClient {
                reason: String::from("i tetti del collegamento all'Hub non sono utilizzabili"),
            });
        }
        let Some(identita) = self.identity.load()? else {
            return Err(ServiceError::HubClient {
                reason: String::from(
                    "questa postazione non ha un'identità di dispositivo: non può presentarsi a \
                     un Hub",
                ),
            });
        };
        let gettone = self.identity.token()?;
        self.dentro_le_reti(&configurazione.address)?;

        let mut canale = match connect(
            configurazione.address.as_socket_addr(),
            configurazione.expectation,
            &self.limits,
        ) {
            Ok(canale) => canale,
            Err(errore) => {
                return Ok(match errore.outcome() {
                    ConnectOutcome::HubUnreachable => ReviewSessionOutcome::Unreachable,
                    ConnectOutcome::NotTheExpectedHub => ReviewSessionOutcome::NotTheExpectedHub,
                    ConnectOutcome::LocalFault => ReviewSessionOutcome::Refused {
                        reason: "il collegamento all'Hub non si è potuto costruire su questa \
                                 postazione",
                    },
                });
            }
        };

        // L'impronta si decide prima di parlare, come in ogni sessione.
        let presentata = canale.hub_fingerprint();
        match lisi_core::model::hub_client::pin_verdict(configurazione.expectation, presentata) {
            PinVerdict::Pin(impronta) => {
                self.connection.save(&HubConnection::new(
                    configurazione.address,
                    HubExpectation::Pinned(impronta),
                ))?;
                self.registra(
                    AUDIT_PINNED,
                    "la prima connessione verificata ha appuntato l'impronta intera dell'Hub",
                    now,
                )?;
            }
            PinVerdict::Unchanged => {}
            PinVerdict::Refused => {
                canale.close();
                self.registra(
                    AUDIT_REFUSED,
                    "l'Hub ha presentato una chiave diversa da quella appuntata: la \
                     configurazione non è stata modificata",
                    now,
                )?;
                return Ok(ReviewSessionOutcome::NotTheExpectedHub);
            }
        }

        let accordo =
            match client_handshake(&mut canale, &identita.id, &gettone, &ClientOffer::default()) {
                Ok(accordo) => accordo,
                Err(errore) => {
                    canale.close();
                    return Ok(match handshake_outcome(&errore) {
                        SessionOutcome::Refused { reason }
                        | SessionOutcome::UnexpectedAnswer { reason } => {
                            ReviewSessionOutcome::Refused { reason }
                        }
                        _ => ReviewSessionOutcome::Unreachable,
                    });
                }
            };

        // LA VERSIONE DECIDE CHE COSA SI PUO' CHIEDERE. Mandare i messaggi
        // della revisione a un Hub versione 1 gli farebbe leggere un frame che
        // non sa interpretare, e chiuderebbe la connessione come se questa
        // postazione fosse rotta.
        if accordo.version < REVIEW_PROTOCOL_VERSION {
            canale.close();
            return Ok(ReviewSessionOutcome::NotSupported {
                hub_version: accordo.version,
            });
        }

        Ok(ReviewSessionOutcome::Ready(Box::new(HubReviewSession {
            canale,
            attesa: PAGE_TIMEOUT.min(self.limits.io_timeout),
            persona: None,
            capacita: accordo.capabilities,
            caduta: false,
        })))
    }

    /// Il recupero, pagina dopo pagina, dentro i tetti della sessione.
    fn catch_up_loop<A>(
        &self,
        canale: &mut lisi_hub_transport::HubClientStream,
        now: Timestamp,
        inizio: Instant,
        applica: &mut A,
    ) -> ServiceResult<SessionReport>
    where
        A: FnMut(&HubEvent) -> ServiceResult<()>,
    {
        let mut pagine = 0_u32;
        let mut applicati = 0_usize;
        let mut duplicati = 0_usize;

        // Quale storia chiedere: la propria, se c'è un cursore; altrimenti una
        // che non esiste, perché l'Hub dica la propria (ADR-0086).
        let conservato = self.catch_up.cursor()?;
        let mut flusso = conservato.map_or_else(
            || HubEventStreamId::from_random_bytes([0; HUB_STREAM_ID_BYTES]),
            |cursore| cursore.stream,
        );
        let mut dopo = conservato.map_or(0, |cursore| cursore.last_applied);
        let mut tracker = None;
        // Il nome della storia si impara **una volta sola**: un Hub che
        // rispondesse «non è la tua storia» a ogni domanda terrebbe la
        // postazione a imparare fino al tetto delle pagine.
        let mut imparato = false;

        loop {
            if pagine >= self.session.max_pages {
                return self.troncata(
                    TruncationReason::PageLimit,
                    applicati,
                    duplicati,
                    pagine,
                    now,
                );
            }
            if applicati >= self.session.max_events {
                return self.troncata(
                    TruncationReason::EventLimit,
                    applicati,
                    duplicati,
                    pagine,
                    now,
                );
            }
            if inizio.elapsed() >= self.session.max_duration {
                return self.troncata(
                    TruncationReason::TimeLimit,
                    applicati,
                    duplicati,
                    pagine,
                    now,
                );
            }

            let richiesta = ClientRequest::Resume {
                stream: flusso.to_hex(),
                after: dopo,
                limit: CATCH_UP_PAGE.min(MAX_PAGE_EVENTS),
            };
            if send_request(canale, &richiesta).is_err() {
                return Ok(SessionReport {
                    outcome: SessionOutcome::Unreachable,
                    applied: applicati,
                    duplicates: duplicati,
                    pages: pagine,
                    pinned: false,
                });
            }
            let attesa = PAGE_TIMEOUT.min(self.limits.io_timeout);
            let Ok(risposta) = read_response(canale, attesa) else {
                return Ok(SessionReport {
                    outcome: SessionOutcome::Unreachable,
                    applied: applicati,
                    duplicates: duplicati,
                    pages: pagine,
                    pinned: false,
                });
            };
            pagine += 1;

            match risposta {
                HubResponse::NotOurStream {
                    stream,
                    latest: _latest,
                } => {
                    // Una postazione che seguiva già una storia ha ricevuto un
                    // «non è la tua»: si ferma, e non ricomincia da sola.
                    if tracker.is_some() || conservato.is_some() || imparato {
                        self.catch_up.stopped(CatchUpStop::StreamChanged, now)?;
                        return Ok(SessionReport {
                            outcome: SessionOutcome::Stopped {
                                stop: CatchUpStop::StreamChanged,
                            },
                            applied: applicati,
                            duplicates: duplicati,
                            pages: pagine,
                            pinned: false,
                        });
                    }
                    // Una postazione nuova ha appena imparato il nome della
                    // storia dell'Hub.
                    let Ok(dichiarato) = HubEventStreamId::parse(&stream) else {
                        return Ok(SessionReport {
                            outcome: SessionOutcome::UnexpectedAnswer {
                                reason: "l'Hub ha dichiarato una storia che non è un nome di \
                                         storia",
                            },
                            applied: applicati,
                            duplicates: duplicati,
                            pages: pagine,
                            pinned: false,
                        });
                    };
                    if dichiarato == flusso {
                        return Ok(SessionReport {
                            outcome: SessionOutcome::UnexpectedAnswer {
                                reason: "l'Hub ha risposto «non è la tua storia» dichiarando la \
                                         stessa storia chiesta",
                            },
                            applied: applicati,
                            duplicates: duplicati,
                            pages: pagine,
                            pinned: false,
                        });
                    }
                    flusso = dichiarato;
                    dopo = 0;
                    imparato = true;
                }
                HubResponse::AheadOfHub { latest: _latest } => {
                    self.catch_up.stopped(CatchUpStop::HubWentBackwards, now)?;
                    return Ok(SessionReport {
                        outcome: SessionOutcome::Stopped {
                            stop: CatchUpStop::HubWentBackwards,
                        },
                        applied: applicati,
                        duplicates: duplicati,
                        pages: pagine,
                        pinned: false,
                    });
                }
                HubResponse::Page { events, latest } => {
                    if events.len() > CATCH_UP_PAGE {
                        return Ok(SessionReport {
                            outcome: SessionOutcome::UnexpectedAnswer {
                                reason: "l'Hub ha consegnato più eventi di quanti ne siano stati \
                                         chiesti",
                            },
                            applied: applicati,
                            duplicates: duplicati,
                            pages: pagine,
                            pinned: false,
                        });
                    }

                    let corrente = match &mut tracker {
                        Some(corrente) => corrente,
                        None => match self.catch_up.begin(flusso, now)? {
                            Ok(nuovo) => tracker.insert(nuovo),
                            Err(stop) => {
                                self.catch_up.stopped(stop, now)?;
                                return Ok(SessionReport {
                                    outcome: SessionOutcome::Stopped { stop },
                                    applied: applicati,
                                    duplicates: duplicati,
                                    pages: pagine,
                                    pinned: false,
                                });
                            }
                        },
                    };

                    let mut validati = Vec::with_capacity(events.len());
                    let mut malformato = None;
                    for evento in &events {
                        match dal_filo(evento) {
                            Ok(valido) => validati.push(valido),
                            Err(_) => {
                                malformato = Some(evento.sequence);
                                break;
                            }
                        }
                    }

                    let rapporto =
                        self.catch_up
                            .apply_page(corrente, &validati, latest, now, |evento| {
                                applica(evento)
                            })?;
                    applicati += rapporto.applied;
                    duplicati += rapporto.duplicates;

                    if let Some(sequenza) = malformato {
                        // Si ferma sulla pagina, e lo dice: scartare in
                        // silenzio lascerebbe un buco che nessuno vede.
                        self.registra(
                            AUDIT_MALFORMED,
                            &format!(
                                "l'evento numero {sequenza} non attraversa i tipi del dominio: la \
                                 pagina si ferma qui"
                            ),
                            now,
                        )?;
                        return Ok(SessionReport {
                            outcome: SessionOutcome::UnexpectedAnswer {
                                reason: "l'Hub ha consegnato un evento che non attraversa i tipi \
                                         del dominio",
                            },
                            applied: applicati,
                            duplicates: duplicati,
                            pages: pagine,
                            pinned: false,
                        });
                    }
                    if rapporto.gap.is_some() {
                        return self.troncata(
                            TruncationReason::NoProgress,
                            applicati,
                            duplicati,
                            pagine,
                            now,
                        );
                    }

                    match rapporto.next {
                        NextStep::Live => {
                            return Ok(SessionReport {
                                outcome: SessionOutcome::CaughtUp { latest },
                                applied: applicati,
                                duplicates: duplicati,
                                pages: pagine,
                                pinned: false,
                            });
                        }
                        NextStep::RequestPage { after, limit: _ } => {
                            if rapporto.applied == 0 {
                                return self.troncata(
                                    TruncationReason::NoProgress,
                                    applicati,
                                    duplicati,
                                    pagine,
                                    now,
                                );
                            }
                            dopo = after;
                        }
                    }
                }
                // LE RISPOSTE DELLA REVISIONE NON APPARTENGONO AL RECUPERO
                // (TEAM-REVIEW-01, ADR-0094): qui si chiede la sequenza, e un
                // Hub che rispondesse con altro non sta rispondendo a questa
                // domanda. Si chiude la sessione invece di indovinare.
                HubResponse::ReviewQueuePage { .. }
                | HubResponse::ReviewContentPage { .. }
                | HubResponse::ReviewOutcome { .. }
                | HubResponse::WorkQueuePage { .. }
                | HubResponse::PresencePage { .. }
                | HubResponse::SignInOutcome { .. }
                | HubResponse::PeoplePage { .. }
                | HubResponse::SharedNotesPage { .. }
                | HubResponse::SharedWorkspacesPage { .. }
                | HubResponse::SharedWorkspaceItemsPage { .. }
                | HubResponse::SharedReportsPage { .. }
                | HubResponse::SharedCyberPage { .. }
                | HubResponse::SharedSessionsPage { .. }
                | HubResponse::SharedCoveragePage { .. } => {
                    return Ok(SessionReport {
                        outcome: SessionOutcome::UnexpectedAnswer {
                            reason: "l'Hub ha risposto alla richiesta della sequenza con una \
                                     risposta della revisione",
                        },
                        applied: applicati,
                        duplicates: duplicati,
                        pages: pagine,
                        pinned: false,
                    });
                }
            }
        }
    }

    /// Chiude la sessione a un tetto, registrandolo.
    fn troncata(
        &self,
        reason: TruncationReason,
        applicati: usize,
        duplicati: usize,
        pagine: u32,
        now: Timestamp,
    ) -> ServiceResult<SessionReport> {
        self.registra(
            AUDIT_TRUNCATED,
            &format!(
                "la sessione si è fermata al {}: la postazione resta indietro",
                reason.label()
            ),
            now,
        )?;
        Ok(SessionReport {
            outcome: SessionOutcome::Truncated { reason },
            applied: applicati,
            duplicates: duplicati,
            pages: pagine,
            pinned: false,
        })
    }

    /// L'applicatore predefinito: una riga di audit per evento.
    fn registra_evento(&self, evento: &HubEvent, now: Timestamp) -> ServiceResult<()> {
        self.registra(
            AUDIT_EVENT,
            &format!(
                "numero {}, {}, {}",
                evento.sequence,
                evento.kind.as_str(),
                evento.subject.as_str()
            ),
            now,
        )
    }

    fn registra(&self, azione: &str, dettaglio: &str, now: Timestamp) -> ServiceResult<()> {
        self.scrivi(Actor::try_new(AUDIT_AUTHORITY)?, azione, dettaglio, now)
    }

    fn scrivi(
        &self,
        actor: Actor,
        azione: &str,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let voce = NewAuditEntry {
            actor,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(dettaglio)?),
            recorded_at: now,
        };
        self.catch_up.database().append_audit(&voce)?;
        Ok(())
    }
}

/// Un evento come viaggia, riportato ai tipi del dominio.
///
/// È il secondo controllo: l'Hub li ha già validati scrivendoli, e chi li
/// riceve li valida di nuovo, perché ciò che arriva dalla rete non è ciò che è
/// stato scritto da noi.
fn dal_filo(evento: &lisi_hub_transport::protocol::events::WireEvent) -> ServiceResult<HubEvent> {
    if evento.sequence == 0 {
        return Err(ServiceError::HubClient {
            reason: String::from("un evento dell'Hub non ha il numero zero"),
        });
    }
    if evento.recorded_at < 0 {
        return Err(ServiceError::HubClient {
            reason: String::from("un evento dell'Hub non è stato scritto prima del 1970"),
        });
    }
    Ok(HubEvent {
        sequence: evento.sequence,
        kind: HubEventKind::parse(&evento.kind)?,
        subject: HubEventSubject::try_new(&evento.subject)?,
        detail: evento
            .detail
            .as_deref()
            .map(HubEventDetail::try_new)
            .transpose()?,
        recorded_at: Timestamp::from_millis(evento.recorded_at),
    })
}

/// Che cosa dire all'operatore quando l'handshake non è riuscito.
///
/// Nessuna variante porta dati ricevuti: le frasi sono costanti.
fn handshake_outcome(error: &HandshakeError) -> SessionOutcome {
    use lisi_hub_transport::protocol::handshake::RefusalReason;

    match error {
        HandshakeError::Refused { reason, .. } => SessionOutcome::Refused {
            reason: match reason {
                RefusalReason::DeviceRevoked => {
                    "l'Hub ha ritirato questa postazione: serve un nuovo arruolamento"
                }
                RefusalReason::NotRecognized => {
                    "l'Hub non riconosce questa postazione: serve un arruolamento"
                }
                RefusalReason::UnsupportedVersion => {
                    "l'Hub e questa postazione non parlano una versione in comune: uno dei due va \
                     aggiornato"
                }
                RefusalReason::Malformed => {
                    "l'Hub ha rifiutato la presentazione di questa postazione"
                }
            },
        },
        HandshakeError::Downgrade => SessionOutcome::UnexpectedAnswer {
            reason: "l'Hub ha scelto una versione più bassa di quella in comune: la connessione \
                     si è chiusa",
        },
        HandshakeError::Frame(_) => SessionOutcome::Unreachable,
        HandshakeError::Malformed
        | HandshakeError::ProtocolViolation
        | HandshakeError::MissingCapability => SessionOutcome::UnexpectedAnswer {
            reason: "all'indirizzo risponde qualcosa che non rispetta il protocollo dell'Hub",
        },
        HandshakeError::InvalidOffer => SessionOutcome::Refused {
            reason: "questa postazione non ha costruito una presentazione valida: è un difetto da \
                     segnalare",
        },
    }
}

/// Legge un campo obbligatorio.
fn campo<'a>(voci: &'a BTreeMap<String, String>, chiave: &str) -> ServiceResult<&'a str> {
    voci.get(chiave)
        .map(String::as_str)
        .ok_or_else(|| ServiceError::HubClient {
            reason: String::from("la configurazione dell'Hub è incompleta"),
        })
}

/// Porta un errore di sicurezza in un errore di servizio, senza dettagli del
/// sistema.
fn map_security_error(_errore: SecurityError) -> ServiceError {
    ServiceError::HubClient {
        reason: String::from("la configurazione dell'Hub non è leggibile con il profilo corrente"),
    }
}

/// La versione del protocollo che porta la revisione condivisa.
pub const REVIEW_PROTOCOL_VERSION: u16 = 2;

/// Com'è finito il tentativo di aprire una sessione di revisione.
///
/// La variante che riesce porta la sessione, che tiene un canale TLS: è molto
/// più grande delle altre, e per questo sta dietro un `Box`. Senza, ogni esito
/// — compresi i rifiuti, che sono la maggioranza quando qualcosa va storto —
/// occuperebbe quanto una sessione aperta.
#[derive(Debug)]
pub enum ReviewSessionOutcome {
    /// Il canale è aperto e l'Hub parla la versione che serve.
    Ready(Box<HubReviewSession>),
    /// L'Hub non risponde. È l'unico esito ripetibile.
    Unreachable,
    /// Ha risposto qualcuno che non è l'Hub atteso. Non si riprova da soli.
    NotTheExpectedHub,
    /// L'Hub ha rifiutato questa postazione.
    Refused {
        /// Che cosa dire all'operatore. Una costante.
        reason: &'static str,
    },
    /// L'Hub è di una generazione che non conosce la revisione condivisa.
    NotSupported {
        /// La versione che l'Hub ha scelto.
        hub_version: u16,
    },
}

impl ReviewSessionOutcome {
    /// La frase per l'operatore quando la sessione non si è aperta.
    #[must_use]
    pub fn refusal_message(&self) -> Option<String> {
        match self {
            Self::Ready(_) => None,
            Self::Unreachable => Some(String::from(
                "L'Hub non risponde. Riprovare più tardi; se non risponde nemmeno allora, \
                 chiedere a chi amministra se l'Hub è acceso.",
            )),
            Self::NotTheExpectedHub => Some(String::from(
                "All'indirizzo dell'Hub risponde una chiave diversa da quella attesa. Il \
                 collegamento si è fermato e la configurazione non è stata modificata.",
            )),
            Self::Refused { reason } => Some(String::from(*reason)),
            Self::NotSupported { hub_version } => Some(format!(
                "L'Hub parla la versione {hub_version} del protocollo, che non conosce la \
                 revisione condivisa: va aggiornato. Il live condiviso continua a funzionare."
            )),
        }
    }
}

/// Una sessione aperta per la revisione condivisa.
///
/// Finché vive tiene una connessione all'Hub: si chiude quando la schermata ha
/// finito. Non conserva nulla su disco — **il contenuto letto vive in memoria**
/// (ADR-0094, decisione 1).
#[derive(Debug)]
pub struct HubReviewSession {
    canale: HubClientStream,
    attesa: Duration,
    /// Chi è entrato in questa sessione, se qualcuno.
    ///
    /// Vive quanto la sessione e non si scrive da nessuna parte: un accesso
    /// che sopravvivesse alla sessione sopravvivrebbe alla persona che se ne
    /// va dalla scrivania (ADR-0097, decisione 6).
    persona: Option<PersonId>,
    /// Le capacità che **entrambe** le estremità hanno riconosciuto.
    ///
    /// Chiedere qualcosa che l'Hub non ha dichiarato di saper fare gli
    /// manderebbe un frame che non sa interpretare (ADR-0084): si guarda prima.
    capacita: Vec<String>,
    /// Se uno scambio è fallito sul trasporto (FINAL-REVIEW-01, FR-017).
    ///
    /// Dopo un invio non riuscito o una risposta non arrivata il canale non è
    /// più utilizzabile: una risposta tardiva verrebbe letta come quella della
    /// domanda successiva. Chi tiene la sessione aperta per una persona deve
    /// saperlo, e chiuderla.
    caduta: bool,
}

impl HubReviewSession {
    /// Vero se la connessione è caduta: la sessione non serve più, e chi era
    /// entrato deve entrare di nuovo.
    #[must_use]
    pub const fn is_dropped(&self) -> bool {
        self.caduta
    }

    /// Chiede la pagina della coda da rivedere.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la richiesta non parte, se la risposta non
    /// arriva, o se ciò che arriva non è una risposta a questa domanda.
    pub fn queue(&mut self, cursor: ReviewQueueCursor) -> ServiceResult<Vec<ReviewItem>> {
        let richiesta = ClientRequest::ReviewQueue {
            after_content_id: cursor.after_content_id,
            limit: cursor.limit,
        };
        match self.scambia(&richiesta)? {
            HubResponse::ReviewQueuePage { items } => {
                let mut elementi = Vec::with_capacity(items.len());
                for elemento in &items {
                    elementi.push(dal_filo_elemento(elemento)?);
                }
                Ok(elementi)
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub offre la coda dell'ufficio.
    #[must_use]
    pub fn offre_la_coda(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_WORK_QUEUE)
    }

    /// Chiede la coda dell'ufficio, come l'Hub l'ha composta.
    ///
    /// Restituisce `None` quando questo Hub **non offre** la capacità: non si
    /// manda un messaggio che l'altro capo non sa leggere, e chi guarda deve
    /// saperlo invece di vedere una coda vuota (ADR-0095, decisione 5).
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn work_queue(&mut self, limit: usize) -> ServiceResult<Option<SharedWorkQueue>> {
        if !self.offre_la_coda() {
            return Ok(None);
        }
        let richiesta = ClientRequest::WorkQueue {
            limit: limit.clamp(1, MAX_WORK_QUEUE_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::WorkQueuePage {
                items,
                composed_at,
                untouched,
                in_review,
                total,
            } => {
                let mut righe = Vec::with_capacity(items.len());
                for riga in &items {
                    righe.push(dal_filo_riga(riga)?);
                }
                Ok(Some(SharedWorkQueue {
                    items: righe,
                    composed_at: Timestamp::from_millis(composed_at),
                    untouched,
                    in_review,
                    total,
                }))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub conosce le persone dell'ufficio.
    #[must_use]
    pub fn offre_le_persone(&self) -> bool {
        self.capacita.iter().any(|nome| nome == CAPABILITY_PERSON)
    }

    /// Se questo Hub sa assegnare il lavoro.
    #[must_use]
    pub fn offre_l_assegnazione(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_ASSIGNMENT)
    }

    /// Dimostra all'Hub di essere una persona dell'ufficio.
    ///
    /// **Non dichiara** chi si è: presenta una frase e chiede di essere
    /// verificati (ADR-0097, decisione 1). L'accesso vale per **questa**
    /// sessione e non lascia niente sulla postazione: chiudendola si esce.
    ///
    /// Restituisce `None` quando questo Hub non conosce le persone.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]. Una frase **sbagliata non è un errore**: è un
    /// esito, e la frase per l'operatore lo dice.
    pub fn sign_in(
        &mut self,
        person: &PersonId,
        passphrase: &Passphrase,
    ) -> ServiceResult<Option<SignInReply>> {
        if !self.offre_le_persone() {
            return Ok(None);
        }
        // La frase attraversa il filo dentro un tipo redatto: una richiesta si
        // stampa con la stessa facilità con cui si legge (ADR-0097,
        // decisione 4).
        let Ok(frase) = core::str::from_utf8(passphrase.expose()) else {
            return Err(ServiceError::HubClient {
                reason: String::from("la frase non è testo utilizzabile"),
            });
        };
        let richiesta = ClientRequest::SignIn {
            person: String::from(person.as_str()),
            passphrase: WireSecret::new(frase),
        };
        match self.scambia(&richiesta)? {
            HubResponse::SignInOutcome {
                verdict,
                role,
                detail,
            } => {
                let ruolo = role.as_deref().map(HubRole::parse).transpose()?;
                if verdict == "entrata" && ruolo.is_some() {
                    self.persona = Some(person.clone());
                }
                Ok(Some(SignInReply {
                    entered: verdict == "entrata",
                    role: ruolo,
                    detail,
                }))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// I colleghi dell'ufficio.
    ///
    /// **Chiede a chi è già dentro**: a una sessione in cui nessuno si è
    /// dimostrato l'Hub risponde con un elenco vuoto, e non è un guasto.
    ///
    /// Restituisce `None` quando questo Hub non conosce le persone.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn people(&mut self) -> ServiceResult<Option<Vec<KnownPerson>>> {
        if !self.offre_le_persone() {
            return Ok(None);
        }
        match self.scambia(&ClientRequest::People)? {
            HubResponse::PeoplePage { people } => {
                let mut elenco = Vec::with_capacity(people.len());
                for riga in &people {
                    elenco.push(KnownPerson {
                        id: PersonId::parse(&riga.person)?,
                        label: riga.label.clone(),
                        role: HubRole::parse(&riga.role)?,
                        active: riga.state == PersonState::Active.as_str(),
                    });
                }
                Ok(Some(elenco))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Chi è entrato in questa sessione, se qualcuno.
    #[must_use]
    pub const fn persona(&self) -> Option<&PersonId> {
        self.persona.as_ref()
    }

    /// Scrive a chi è un contenuto, o lo rimette a nessuno.
    ///
    /// `to` vale `None` per la revoca; prendere in carico è passare il proprio
    /// identificativo (ADR-0098, decisione 1).
    ///
    /// Restituisce `None` quando questo Hub non sa assegnare.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn assign(
        &mut self,
        command_id: &str,
        content_id: ContentId,
        expected_version: u64,
        to: Option<&PersonId>,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        if !self.offre_l_assegnazione() {
            return Ok(None);
        }
        let richiesta = ClientRequest::Assign {
            command_id: String::from(command_id),
            content_id: content_id.get(),
            expected_version,
            to: to.map(|persona| String::from(persona.as_str())),
        };
        match self.scambia(&richiesta)? {
            HubResponse::ReviewOutcome {
                verdict,
                detail,
                current_version,
            } => Ok(Some(ReviewSubmission {
                verdict,
                detail,
                current_version,
            })),
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub tiene il blocco condiviso.
    #[must_use]
    pub fn offre_le_note(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_SHARED_NOTES)
    }

    /// Se questo Hub tiene i raccoglitori condivisi.
    #[must_use]
    pub fn offre_i_raccoglitori(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_SHARED_WORKSPACES)
    }

    /// Che cosa l'ufficio ha scritto su qualcosa.
    ///
    /// Comprende **anche le note ritirate**: chi le aveva lette deve poter
    /// capire che cosa è successo a ciò che aveva letto (ADR-0099,
    /// decisione 2).
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn shared_notes(
        &mut self,
        about: ArchiveRef,
        limit: usize,
    ) -> ServiceResult<Option<Vec<SharedNote>>> {
        if !self.offre_le_note() {
            return Ok(None);
        }
        let richiesta = ClientRequest::SharedNotes {
            kind: String::from(about.kind().as_str()),
            target_id: about.target_id(),
            limit: limit.clamp(1, MAX_SHARED_NOTES_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::SharedNotesPage { notes } => {
                let mut note = Vec::with_capacity(notes.len());
                for riga in &notes {
                    note.push(dal_filo_nota(riga)?);
                }
                Ok(Some(note))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Annota qualcosa, per l'ufficio.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn write_shared_note(
        &mut self,
        about: ArchiveRef,
        body: &Note,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        self.scritta(ClientRequest::WriteSharedNote {
            kind: String::from(about.kind().as_str()),
            target_id: about.target_id(),
            body: String::from(body.as_str()),
        })
    }

    /// Ritira una nota. **Non la cancella.**
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn withdraw_shared_note(
        &mut self,
        note_id: NoteId,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        self.scritta(ClientRequest::WithdrawSharedNote {
            note_id: note_id.get(),
        })
    }

    /// I raccoglitori dell'ufficio.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn shared_workspaces(
        &mut self,
        limit: usize,
    ) -> ServiceResult<Option<Vec<SharedWorkspace>>> {
        if !self.offre_i_raccoglitori() {
            return Ok(None);
        }
        let richiesta = ClientRequest::SharedWorkspaces {
            limit: limit.clamp(1, MAX_SHARED_WORKSPACES_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::SharedWorkspacesPage { workspaces } => {
                let mut raccoglitori = Vec::with_capacity(workspaces.len());
                for riga in &workspaces {
                    raccoglitori.push(dal_filo_raccoglitore(riga)?);
                }
                Ok(Some(raccoglitori))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Ciò che un raccoglitore ha raccolto.
    ///
    /// # Errori
    ///
    /// Come [`Self::shared_workspaces`].
    pub fn workspace_items(
        &mut self,
        workspace_id: i64,
        limit: usize,
    ) -> ServiceResult<Option<Vec<SharedWorkspaceItem>>> {
        if !self.offre_i_raccoglitori() {
            return Ok(None);
        }
        let richiesta = ClientRequest::SharedWorkspaceItems {
            workspace_id,
            limit: limit.clamp(1, MAX_WORKSPACE_ITEMS_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::SharedWorkspaceItemsPage { items } => {
                let mut elementi = Vec::with_capacity(items.len());
                for riga in &items {
                    elementi.push(dal_filo_raccolto(riga)?);
                }
                Ok(Some(elementi))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Apre un raccoglitore dell'ufficio.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn open_shared_workspace(
        &mut self,
        name: &DisplayName,
        description: Option<&Note>,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        self.scritta(ClientRequest::OpenSharedWorkspace {
            name: String::from(name.as_str()),
            description: description.map(|testo| String::from(testo.as_str())),
        })
    }

    /// Chiude un raccoglitore. **Non cancella niente.**
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn close_shared_workspace(
        &mut self,
        workspace_id: i64,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        self.scritta(ClientRequest::CloseSharedWorkspace { workspace_id })
    }

    /// Mette un riferimento in un raccoglitore.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn collect_in_workspace(
        &mut self,
        workspace_id: i64,
        item: ArchiveRef,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        self.scritta(ClientRequest::CollectInWorkspace {
            workspace_id,
            kind: String::from(item.kind().as_str()),
            target_id: item.target_id(),
        })
    }

    /// Toglie un riferimento da un raccoglitore.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn drop_from_workspace(
        &mut self,
        workspace_id: i64,
        item: ArchiveRef,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        self.scritta(ClientRequest::DropFromWorkspace {
            workspace_id,
            kind: String::from(item.kind().as_str()),
            target_id: item.target_id(),
        })
    }

    /// Manda una cosa che si scrive insieme, e riporta come è andata.
    ///
    /// Le due capacità si guardano insieme: chi non ne offre nessuna non
    /// riceve nessuno di questi messaggi.
    fn scritta(&mut self, richiesta: ClientRequest) -> ServiceResult<Option<ReviewSubmission>> {
        if !self.offre_le_note() && !self.offre_i_raccoglitori() {
            return Ok(None);
        }
        match self.scambia(&richiesta)? {
            HubResponse::ReviewOutcome {
                verdict,
                detail,
                current_version,
            } => Ok(Some(ReviewSubmission {
                verdict,
                detail,
                current_version,
            })),
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub tiene le relazioni dell'ufficio.
    #[must_use]
    pub fn offre_le_relazioni(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_SHARED_REPORTS)
    }

    /// Le relazioni dell'ufficio.
    ///
    /// Porta **nomi e impronte**, mai i documenti: il protocollo dell'Hub non
    /// trasporta file (ADR-0100, decisione 2).
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn shared_reports(&mut self, limit: usize) -> ServiceResult<Option<Vec<SharedReport>>> {
        if !self.offre_le_relazioni() {
            return Ok(None);
        }
        let richiesta = ClientRequest::SharedReports {
            limit: limit.clamp(1, MAX_SHARED_REPORTS_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::SharedReportsPage { reports } => {
                let mut elenco = Vec::with_capacity(reports.len());
                for riga in &reports {
                    elenco.push(dal_filo_relazione(riga)?);
                }
                Ok(Some(elenco))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Chiede che l'ufficio congeli una fotografia per una sessione.
    ///
    /// **Non chiede un documento**: il documento nasce dove stanno i fatti.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn freeze_shared_report(
        &mut self,
        command_id: &str,
        session_id: SessionId,
        contents: &[ContentId],
    ) -> ServiceResult<Option<ReviewSubmission>> {
        if !self.offre_le_relazioni() {
            return Ok(None);
        }
        let richiesta = ClientRequest::FreezeSharedReport {
            command_id: String::from(command_id),
            session_id: session_id.get(),
            contents: contents.iter().map(|contenuto| contenuto.get()).collect(),
        };
        match self.scambia(&richiesta)? {
            HubResponse::ReviewOutcome {
                verdict,
                detail,
                current_version,
            } => Ok(Some(ReviewSubmission {
                verdict,
                detail,
                current_version,
            })),
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub dice quali monitoraggi ha l'ufficio.
    #[must_use]
    pub fn offre_i_monitoraggi(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_SHARED_SESSIONS)
    }

    /// I monitoraggi dell'ufficio, dal più recente.
    ///
    /// Senza questo elenco una postazione non sa come **nominare** una
    /// sessione, e non può chiedere né i grappoli né una fotografia.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn shared_sessions(&mut self, limit: usize) -> ServiceResult<Option<Vec<SharedSession>>> {
        if !self.offre_i_monitoraggi() {
            return Ok(None);
        }
        let richiesta = ClientRequest::SharedSessions {
            limit: limit.clamp(1, MAX_SHARED_SESSIONS_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::SharedSessionsPage { sessions } => {
                let mut elenco = Vec::with_capacity(sessions.len());
                for riga in &sessions {
                    if riga.session_id <= 0 {
                        return Err(ServiceError::HubClient {
                            reason: String::from(
                                "un monitoraggio non porta un identificativo utilizzabile",
                            ),
                        });
                    }
                    elenco.push(SharedSession {
                        id: SessionId::new(riga.session_id),
                        label: riga.label.clone(),
                        state: riga.state.clone(),
                        started_at: if riga.started_at > 0 {
                            Some(Timestamp::from_millis(riga.started_at))
                        } else {
                            None
                        },
                        ended_at: if riga.ended_at > 0 {
                            Some(Timestamp::from_millis(riga.ended_at))
                        } else {
                            None
                        },
                    });
                }
                Ok(Some(elenco))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub riceve comandi a distanza (HUB-REMOTE-01).
    #[must_use]
    pub fn offre_i_comandi_a_distanza(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_REMOTE_COMMANDS)
    }

    /// Manda un comando a distanza su un monitoraggio dell'Hub (HUB-REMOTE-01,
    /// ADR-0200).
    ///
    /// `None` se questo Hub non riceve comandi a distanza. Un rifiuto dell'Hub
    /// non è un errore: è una risposta, con la sua ragione.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn remote_command(
        &mut self,
        command_id: &str,
        session_id: SessionId,
        action: lisi_core::model::remote_command::RemoteAction,
        reason: &str,
    ) -> ServiceResult<Option<ReviewSubmission>> {
        if !self.offre_i_comandi_a_distanza() {
            return Ok(None);
        }
        let richiesta = ClientRequest::RemoteCommand {
            command_id: String::from(command_id),
            session_id: session_id.get(),
            action: String::from(action.as_str()),
            reason: reason
                .trim()
                .chars()
                .take(MAX_REMOTE_REASON_CHARS)
                .collect(),
        };
        match self.scambia(&richiesta)? {
            HubResponse::ReviewOutcome {
                verdict,
                detail,
                current_version,
            } => Ok(Some(ReviewSubmission {
                verdict,
                detail,
                current_version,
            })),
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub manda la copertura dell'ufficio (HUB-COVERAGE-01).
    #[must_use]
    pub fn offre_la_copertura(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_SHARED_COVERAGE)
    }

    /// La copertura di un monitoraggio dell'ufficio, come l'Hub l'ha calcolata
    /// (HUB-COVERAGE-01, ADR-0199).
    ///
    /// `None` se questo Hub non la manda: la postazione lo dice, invece di
    /// mostrare una copertura vuota.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se la copertura ricevuta non
    /// attraversa i tipi del dominio, compreso uno stato che questa postazione
    /// non conosce.
    pub fn shared_coverage(
        &mut self,
        session_id: SessionId,
    ) -> ServiceResult<Option<SharedCoverageAnswer>> {
        if !self.offre_la_copertura() {
            return Ok(None);
        }
        let richiesta = ClientRequest::SharedCoverage {
            session_id: session_id.get(),
        };
        let risposta = self.scambia(&richiesta)?;
        copertura_dal_filo(risposta)
    }

    /// Se questo Hub offre i grappoli cyber dell'ufficio.
    #[must_use]
    pub fn offre_il_cyber(&self) -> bool {
        self.capacita
            .iter()
            .any(|nome| nome == CAPABILITY_SHARED_CYBER)
    }

    /// I grappoli cyber dell'ufficio, per una sessione.
    ///
    /// **Si guardano, non si rifanno**: l'analisi gira dove stanno i
    /// contenuti (ADR-0102, decisione 1).
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn shared_cyber_events(
        &mut self,
        session_id: SessionId,
        limit: usize,
    ) -> ServiceResult<Option<Vec<SharedCyberEvent>>> {
        if !self.offre_il_cyber() {
            return Ok(None);
        }
        let richiesta = ClientRequest::SharedCyberEvents {
            session_id: session_id.get(),
            limit: limit.clamp(1, MAX_SHARED_CYBER_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::SharedCyberPage { events } => {
                let mut grappoli = Vec::with_capacity(events.len());
                for riga in &events {
                    grappoli.push(dal_filo_grappolo(riga)?);
                }
                Ok(Some(grappoli))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Se questo Hub offre la presenza.
    #[must_use]
    pub fn offre_la_presenza(&self) -> bool {
        self.capacita.iter().any(|nome| nome == CAPABILITY_PRESENCE)
    }

    /// Chiede chi è connesso all'Hub adesso.
    ///
    /// Restituisce `None` quando questo Hub **non offre** la capacità: chi
    /// guarda deve saperlo, invece di leggere «nessuno collegato» e crederci
    /// (ADR-0096, decisione 6).
    ///
    /// La postazione **non dichiara** la propria presenza chiamando questo
    /// metodo: la presenza l'ha già osservata l'Hub autenticando la
    /// connessione (decisione 3). Qui si chiede soltanto di vederla.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se una riga ricevuta non attraversa i
    /// tipi del dominio.
    pub fn presence(&mut self, limit: usize) -> ServiceResult<Option<PresenceSnapshot>> {
        if !self.offre_la_presenza() {
            return Ok(None);
        }
        let richiesta = ClientRequest::Presence {
            limit: limit.clamp(1, MAX_PRESENCE_PAGE),
        };
        match self.scambia(&richiesta)? {
            HubResponse::PresencePage {
                stations,
                composed_at,
                total,
            } => {
                let mut righe = Vec::with_capacity(stations.len());
                for riga in &stations {
                    righe.push(dal_filo_postazione(riga)?);
                }
                Ok(Some(PresenceSnapshot {
                    stations: righe,
                    composed_at: Timestamp::from_millis(composed_at),
                    total,
                }))
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Chiede **un** contenuto da rivedere.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`]; e un errore se il contenuto ricevuto non
    /// attraversa i tipi del dominio.
    pub fn content(&mut self, content_id: ContentId) -> ServiceResult<Option<ReviewContent>> {
        let richiesta = ClientRequest::ReviewContent {
            content_id: content_id.get(),
        };
        match self.scambia(&richiesta)? {
            HubResponse::ReviewContentPage { content } => {
                content.as_ref().map(dal_filo_contenuto).transpose()
            }
            // L'Hub può rispondere con un rifiuto: il ruolo di questa
            // postazione non consente la lettura.
            HubResponse::ReviewOutcome { detail, .. } => {
                Err(ServiceError::HubForbidden { reason: detail })
            }
            _ => Err(risposta_inattesa()),
        }
    }

    /// Manda una decisione.
    ///
    /// # Errori
    ///
    /// Come [`Self::queue`].
    pub fn submit(
        &mut self,
        command_id: &str,
        content_id: ContentId,
        expected_version: u64,
        state: ReviewState,
        note: Option<&str>,
    ) -> ServiceResult<ReviewSubmission> {
        let richiesta = ClientRequest::SubmitReview {
            command_id: String::from(command_id),
            content_id: content_id.get(),
            expected_version,
            state: String::from(state.as_str()),
            note: note.map(String::from),
        };
        match self.scambia(&richiesta)? {
            HubResponse::ReviewOutcome {
                verdict,
                detail,
                current_version,
            } => Ok(ReviewSubmission {
                verdict,
                detail,
                current_version,
            }),
            _ => Err(risposta_inattesa()),
        }
    }

    /// Chiude la sessione, annunciandolo all'Hub.
    pub fn close(self) {
        self.canale.close();
    }

    fn scambia(&mut self, richiesta: &ClientRequest) -> ServiceResult<HubResponse> {
        let dopo = if self.persona.is_some() {
            ": la connessione si è chiusa, e chi era entrato deve entrare di nuovo"
        } else {
            ""
        };
        if send_request(&mut self.canale, richiesta).is_err() {
            self.caduta = true;
            return Err(ServiceError::HubClient {
                reason: format!("la richiesta all'Hub non è partita{dopo}"),
            });
        }
        read_response(&mut self.canale, self.attesa).map_err(|_| {
            self.caduta = true;
            ServiceError::HubClient {
                reason: format!("l'Hub non ha risposto in tempo{dopo}"),
            }
        })
    }
}

/// La coda dell'ufficio, come l'Hub l'ha composta.
///
/// È una **fotografia**: porta l'istante in cui è stata composta, perché una
/// coda senza istante sembra il presente anche quando è di dieci minuti fa
/// (ADR-0095, decisione 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedWorkQueue {
    /// Le righe, nell'ordine in cui vanno guardate.
    pub items: Vec<SharedWorkItem>,
    /// Quando l'Hub l'ha composta.
    pub composed_at: Timestamp,
    /// Quante righe non sono mai state esaminate, in tutta la coda.
    pub untouched: usize,
    /// Quante sono già in esame, in tutta la coda.
    pub in_review: usize,
    /// Quante righe ha la coda in tutto.
    pub total: usize,
}

impl SharedWorkQueue {
    /// Quante righe restano fuori dalla fotografia.
    #[must_use]
    pub const fn beyond(&self) -> usize {
        self.total.saturating_sub(self.items.len())
    }
}

/// Una riga della coda dell'ufficio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedWorkItem {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Il nome della fonte, come l'ufficio l'ha chiamata.
    pub source_name: String,
    /// Il livello attribuito dal motore.
    pub level: u8,
    /// Quando l'avviso è scattato.
    pub raised_at: Timestamp,
    /// Lo stato della revisione, se qualcuno l'ha già toccato.
    pub state: Option<ReviewState>,
    /// Perché sta dov'è.
    pub why_here: String,
    /// A chi è assegnato, quando lo è.
    pub assigned_to: Option<PersonId>,
    /// Quanti cambi di assegnazione ha avuto.
    ///
    /// È la versione da dichiarare per scriverne uno nuovo.
    pub assignment_version: u64,
}

/// Una riga della coda, riportata ai tipi del dominio.
fn dal_filo_riga(riga: &WireWorkItem) -> ServiceResult<SharedWorkItem> {
    if riga.content_id <= 0 {
        return Err(ServiceError::HubClient {
            reason: String::from("una riga della coda non ha un identificativo utilizzabile"),
        });
    }
    Ok(SharedWorkItem {
        content_id: ContentId::new(riga.content_id),
        source_name: riga.source_name.clone(),
        level: riga.level,
        raised_at: Timestamp::from_millis(riga.raised_at),
        state: riga
            .state
            .as_deref()
            .map(ReviewState::from_str)
            .transpose()?,
        why_here: riga.why_here.clone(),
        assigned_to: riga
            .assigned_to
            .as_deref()
            .map(PersonId::parse)
            .transpose()?,
        assignment_version: riga.assignment_version,
    })
}

/// Una postazione presente, riportata ai tipi del dominio.
///
/// L'identificativo che arriva dalla rete **si riconosce**, non si crede: un
/// Hub autenticato resta un Hub autenticato, non un Hub fidato (ADR-0091).
fn dal_filo_postazione(riga: &WirePresentStation) -> ServiceResult<PresentStation> {
    let device = DeviceId::parse(&riga.device).map_err(|_| ServiceError::HubClient {
        reason: String::from(
            "una riga della presenza non porta un identificativo di postazione utilizzabile",
        ),
    })?;
    Ok(PresentStation {
        device,
        connected_since: Timestamp::from_millis(riga.connected_since),
        last_seen: Timestamp::from_millis(riga.last_seen),
    })
}

/// Una nota dell'ufficio, riportata ai tipi del dominio.
fn dal_filo_nota(riga: &WireSharedNote) -> ServiceResult<SharedNote> {
    let genere = ArchiveRefKind::from_str(&riga.kind).map_err(|_| ServiceError::HubClient {
        reason: String::from("una nota condivisa non dice su che genere di cosa è scritta"),
    })?;
    Ok(SharedNote {
        id: NoteId::new(riga.id),
        about: ArchiveRef::to(genere, riga.target_id)?,
        body: Note::try_new(&riga.body)?,
        author: PersonId::parse(&riga.author)?,
        written_at: Timestamp::from_millis(riga.written_at),
        withdrawn: match riga.withdrawn_by.as_deref() {
            Some(chi) => Some((
                PersonId::parse(chi)?,
                Timestamp::from_millis(riga.withdrawn_at),
            )),
            None => None,
        },
    })
}

/// Un raccoglitore, riportato ai tipi del dominio.
fn dal_filo_raccoglitore(riga: &WireSharedWorkspace) -> ServiceResult<SharedWorkspace> {
    Ok(SharedWorkspace {
        id: riga.id,
        name: DisplayName::try_new(&riga.name)?,
        description: riga.description.as_deref().map(Note::try_new).transpose()?,
        state: SharedWorkspaceState::parse(&riga.state)?,
        opened_by: PersonId::parse(&riga.opened_by)?,
        opened_at: Timestamp::from_millis(riga.opened_at),
        items: riga.items,
    })
}

/// Un riferimento raccolto, riportato ai tipi del dominio.
fn dal_filo_raccolto(riga: &WireWorkspaceItem) -> ServiceResult<SharedWorkspaceItem> {
    let genere = ArchiveRefKind::from_str(&riga.kind).map_err(|_| ServiceError::HubClient {
        reason: String::from("un elemento raccolto non dice di che genere di cosa si tratta"),
    })?;
    Ok(SharedWorkspaceItem {
        item: ArchiveRef::to(genere, riga.target_id)?,
        added_by: PersonId::parse(&riga.added_by)?,
        added_at: Timestamp::from_millis(riga.added_at),
    })
}

/// Una relazione dell'ufficio, riportata ai tipi del dominio.
fn dal_filo_relazione(riga: &WireSharedReport) -> ServiceResult<SharedReport> {
    if riga.session_id <= 0 {
        return Err(ServiceError::HubClient {
            reason: String::from("una relazione non dice quale sessione documenta"),
        });
    }
    Ok(SharedReport {
        report_id: riga.report_id.clone(),
        session_id: SessionId::new(riga.session_id),
        requested_by: riga.requested_by.clone(),
        status: ReportGenerationStatus::from_str(&riga.status)?,
        requested_at: Timestamp::from_millis(riga.requested_at),
        completed_at: if riga.completed_at > 0 {
            Some(Timestamp::from_millis(riga.completed_at))
        } else {
            None
        },
        monitored: riga.monitored,
        selected: riga.selected,
        artifacts: riga
            .artifacts
            .iter()
            .map(|documento| SharedArtifact {
                file_name: documento.file_name.clone(),
                size_bytes: documento.size_bytes,
                sha256: documento.sha256.clone(),
            })
            .collect(),
    })
}

/// Un monitoraggio dell'ufficio, come la postazione lo conosce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSession {
    /// Quale monitoraggio.
    pub id: SessionId,
    /// Come lo chiama l'ufficio.
    pub label: String,
    /// In quale stato è.
    pub state: String,
    /// Quando è cominciato.
    pub started_at: Option<Timestamp>,
    /// Quando è finito.
    pub ended_at: Option<Timestamp>,
}

/// La copertura di un monitoraggio dell'ufficio, come l'Hub l'ha calcolata
/// (HUB-COVERAGE-01, ADR-0199).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedCoverage {
    /// Quale monitoraggio.
    pub session_id: SessionId,
    /// L'istante in cui l'Hub l'ha calcolata: è una fotografia.
    pub taken_at: Timestamp,
    /// Il programma e il collegamento, sulla finestra del monitoraggio.
    pub overall: Coverage,
    /// Ciascuna fonte del monitoraggio, con il suo nome.
    pub sources: Vec<(String, Coverage)>,
}

/// Che cosa l'Hub ha risposto alla domanda sulla copertura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedCoverageAnswer {
    /// La copertura, intera.
    Taken(SharedCoverage),
    /// L'Hub non la manda, e dice perché.
    Refused(String),
}

/// La risposta dell'Hub alla domanda sulla copertura, riportata ai tipi del
/// dominio. Un tratto con un nome di stato sconosciuto, o una sequenza con
/// buchi, rende la risposta inutilizzabile: non diventa mai «coperto».
pub(crate) fn copertura_dal_filo(
    risposta: HubResponse,
) -> ServiceResult<Option<SharedCoverageAnswer>> {
    let inutilizzabile = || ServiceError::HubClient {
        reason: String::from("la copertura arrivata dall'Hub non è in una forma utilizzabile"),
    };
    let ricomponi = |tratti: &[WireCoverageStretch]| -> ServiceResult<Coverage> {
        let mut dominio = Vec::with_capacity(tratti.len());
        for tratto in tratti {
            let state = CoverageState::from_token(&tratto.state).ok_or_else(inutilizzabile)?;
            dominio.push(CoverageInterval {
                from: Timestamp::from_millis(tratto.from),
                to: Timestamp::from_millis(tratto.to),
                state,
            });
        }
        Coverage::build(dominio).ok_or_else(inutilizzabile)
    };
    match risposta {
        HubResponse::SharedCoveragePage {
            session_id,
            taken_at,
            overall,
            sources,
        } => {
            let mut fonti = Vec::with_capacity(sources.len());
            for fonte in &sources {
                fonti.push((fonte.name.clone(), ricomponi(&fonte.stretches)?));
            }
            Ok(Some(SharedCoverageAnswer::Taken(SharedCoverage {
                session_id: SessionId::new(session_id),
                taken_at: Timestamp::from_millis(taken_at),
                overall: ricomponi(&overall)?,
                sources: fonti,
            })))
        }
        HubResponse::ReviewOutcome {
            verdict, detail, ..
        } if verdict == "rifiutata" => Ok(Some(SharedCoverageAnswer::Refused(detail))),
        _ => Err(risposta_inattesa()),
    }
}

/// Un grappolo cyber, riportato ai tipi del dominio.
fn dal_filo_grappolo(riga: &WireCyberEvent) -> ServiceResult<SharedCyberEvent> {
    if riga.session_id <= 0 {
        return Err(ServiceError::HubClient {
            reason: String::from("un grappolo non dice in quale sessione si è formato"),
        });
    }
    Ok(SharedCyberEvent {
        position: riga.position,
        session_id: SessionId::new(riga.session_id),
        reason: riga.reason.clone(),
        contents: riga.contents,
        distinct_sources: riga.distinct_sources,
        apparent_reposts: riga.apparent_reposts,
        italy: riga.italy.clone(),
        sectors: riga.sectors.clone(),
        indicators: riga
            .indicators
            .iter()
            .map(|indicatore| SharedIndicator {
                kind: indicatore.kind.clone(),
                value: indicatore.value.clone(),
            })
            .collect(),
        decided: riga.decided,
        in_progress: riga.in_progress,
        untouched: riga.untouched,
        seen_between: if riga.first_seen > 0 || riga.last_seen > 0 {
            Some((
                Timestamp::from_millis(riga.first_seen),
                Timestamp::from_millis(riga.last_seen),
            ))
        } else {
            None
        },
    })
}

/// Un collega, come la postazione lo conosce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPerson {
    /// Come si chiama negli atti.
    pub id: PersonId,
    /// Come lo chiama l'ufficio.
    pub label: String,
    /// Che cosa gli è consentito.
    pub role: HubRole,
    /// Se può entrare.
    pub active: bool,
}

/// Che cosa l'Hub ha risposto a un tentativo di entrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInReply {
    /// Se si è entrati.
    pub entered: bool,
    /// Il ruolo con cui, quando si è entrati.
    pub role: Option<HubRole>,
    /// La frase per l'operatore. **Mai la frase di accesso.**
    pub detail: String,
}

/// Che cosa l'Hub ha fatto di una decisione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSubmission {
    /// `applicata`, `ripetuta`, `conflitto` oppure `rifiutata`.
    pub verdict: String,
    /// La frase per l'operatore.
    pub detail: String,
    /// La versione che il contenuto ha adesso.
    pub current_version: u64,
}

impl ReviewSubmission {
    /// Se la decisione è stata registrata adesso.
    #[must_use]
    pub fn is_applied(&self) -> bool {
        self.verdict == "applicata"
    }

    /// Se qualcun altro aveva già deciso.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        self.verdict == "conflitto"
    }
}

/// L'errore di una risposta che non risponde alla domanda fatta.
fn risposta_inattesa() -> ServiceError {
    ServiceError::HubClient {
        reason: String::from("l'Hub ha risposto con qualcosa che non risponde alla domanda"),
    }
}

/// Un elemento della coda, riportato ai tipi del dominio.
fn dal_filo_elemento(elemento: &WireReviewItem) -> ServiceResult<ReviewItem> {
    if elemento.content_id <= 0 {
        return Err(ServiceError::HubClient {
            reason: String::from("un elemento della coda non ha un identificativo utilizzabile"),
        });
    }
    Ok(ReviewItem {
        content_id: ContentId::new(elemento.content_id),
        source: SourceIdentifier::try_new(&elemento.source)?,
        level: elemento.level,
        raised_at: Timestamp::from_millis(elemento.raised_at),
        state: elemento
            .state
            .as_deref()
            .map(ReviewState::from_str)
            .transpose()?,
        version: elemento.version,
    })
}

/// Il contenuto ricevuto, riportato ai tipi del dominio.
fn dal_filo_contenuto(contenuto: &WireReviewContent) -> ServiceResult<ReviewContent> {
    if contenuto.content_id <= 0 {
        return Err(ServiceError::HubClient {
            reason: String::from("il contenuto ricevuto non ha un identificativo utilizzabile"),
        });
    }
    if contenuto.body.chars().count() > MAX_REVIEW_BODY_CHARS {
        return Err(ServiceError::HubClient {
            reason: String::from("il contenuto ricevuto è più lungo di quanto il dominio ammetta"),
        });
    }
    Ok(ReviewContent {
        content_id: ContentId::new(contenuto.content_id),
        source: SourceIdentifier::try_new(&contenuto.source)?,
        source_name: DisplayName::try_new(&contenuto.source_name)?,
        published_at: Timestamp::from_millis(contenuto.published_at),
        body: contenuto.body.clone(),
        level: contenuto.level,
        version: contenuto.version,
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::model::hub_client::{HubAddress, HubConnection};
    use lisi_core::model::hub_identity::{HUB_FINGERPRINT_BYTES, HubExpectation, HubFingerprint};
    use lisi_hub_transport::protocol::events::WireEvent;
    use lisi_security::ProtectedStore;

    use super::{HubConnectionStore, dal_filo};

    fn impronta(seme: u8) -> HubFingerprint {
        HubFingerprint::from_bytes([seme; HUB_FINGERPRINT_BYTES])
    }

    fn indirizzo() -> HubAddress {
        match HubAddress::parse("192.0.2.10:8443") {
            Ok(indirizzo) => indirizzo,
            Err(errore) => panic!("indirizzo: {errore}"),
        }
    }

    fn archivio(cartella: &tempfile::TempDir) -> HubConnectionStore {
        HubConnectionStore::at(ProtectedStore::at(
            cartella.path().join("hub-client.protetto"),
        ))
    }

    fn cartella() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(cartella) => cartella,
            Err(errore) => panic!("cartella temporanea: {errore}"),
        }
    }

    fn evento(sequence: u64) -> WireEvent {
        WireEvent {
            sequence,
            kind: String::from("dispositivo_ammesso"),
            subject: String::from("ABCD-EFGH"),
            detail: None,
            recorded_at: 1_759_000_000_000,
        }
    }

    #[test]
    fn a_station_without_the_file_has_no_hub_and_it_is_not_an_error() {
        let cartella = cartella();
        let archivio = archivio(&cartella);
        assert!(!archivio.exists());
        assert_eq!(archivio.load().ok(), Some(None));
    }

    #[test]
    fn both_forms_of_the_expectation_survive_the_protected_file() {
        let cartella = cartella();
        let archivio = archivio(&cartella);

        let dal_foglietto = HubConnection::new(
            indirizzo(),
            HubExpectation::Enrollment(impronta(3).prefix()),
        );
        if archivio.save(&dal_foglietto).is_err() {
            panic!("la configurazione deve potersi scrivere");
        }
        assert_eq!(archivio.load().ok(), Some(Some(dal_foglietto)));

        let appuntata = HubConnection::new(indirizzo(), HubExpectation::Pinned(impronta(3)));
        if archivio.save(&appuntata).is_err() {
            panic!("la configurazione deve potersi riscrivere");
        }
        assert_eq!(archivio.load().ok(), Some(Some(appuntata)));
    }

    #[test]
    fn a_configuration_that_does_not_say_which_key_is_expected_is_refused() {
        let cartella = cartella();
        let archivio = archivio(&cartella);
        let mut voci = std::collections::BTreeMap::new();
        voci.insert(
            String::from(super::ADDRESS_KEY),
            String::from("192.0.2.10:8443"),
        );
        voci.insert(
            String::from(super::EXPECTATION_KIND_KEY),
            String::from("fidati"),
        );
        voci.insert(String::from(super::EXPECTATION_KEY), impronta(3).to_hex());
        let protetto = ProtectedStore::at(cartella.path().join("hub-client.protetto"));
        if protetto.save(&voci).is_err() {
            panic!("il file deve potersi scrivere");
        }
        assert!(
            archivio.load().is_err(),
            "«fidati» non è una forma dell'attesa, e non si legge come se lo fosse"
        );
    }

    #[test]
    fn an_event_that_does_not_cross_the_domain_types_is_refused() {
        assert!(dal_filo(&evento(1)).is_ok());

        let mut numero_zero = evento(0);
        numero_zero.sequence = 0;
        assert!(dal_filo(&numero_zero).is_err(), "il numero zero non esiste");

        let mut prima_del_1970 = evento(1);
        prima_del_1970.recorded_at = -1;
        assert!(dal_filo(&prima_del_1970).is_err());

        let mut tipo_inventato = evento(1);
        tipo_inventato.kind = String::from("tipo_inventato");
        assert!(dal_filo(&tipo_inventato).is_err());

        let mut soggetto_vuoto = evento(1);
        soggetto_vuoto.subject = String::new();
        assert!(dal_filo(&soggetto_vuoto).is_err());
    }
}

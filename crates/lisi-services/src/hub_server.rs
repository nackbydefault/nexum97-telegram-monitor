//! La modalità Hub: la porta che **una persona** apre (TEAM-LIVE-01,
//! ADR-0093).
//!
//! # Che cosa cambia rispetto a ieri
//!
//! Fino al 2026-09-20 il ciclo che ascolta viveva soltanto nel banco dei
//! guasti (ADR-0090): il prodotto non apriva alcuna porta, e una prova lo
//! verificava. Qui quel ciclo entra nel prodotto, con le regole che ADR-0083
//! aveva già scritto per il giorno in cui sarebbe successo.
//!
//! # Nessuna porta finché qualcuno non la apre
//!
//! L'ascolto non comincia all'avvio del programma e non è una condizione
//! dell'installazione: lo attiva una persona, l'atto finisce nell'audit con il
//! suo identificativo, e si disattiva chiudendo la porta.
//!
//! **L'indirizzo si scrive**, come quello del client: IP letterale con la sua
//! porta, mai «tutte le interfacce» (il trasporto rifiuta l'indirizzo non
//! specificato). Sta sotto DPAPI in un file proprio.
//!
//! # Un'autorità sola
//!
//! Una postazione che **segue** un Hub non può diventare Hub: sarebbero due
//! autorità per lo stesso ufficio (ADR-0042), e il rifiuto lo dice invece di
//! lasciar accadere la cosa.
//!
//! # Che cosa serve l'Hub
//!
//! Le pagine della sequenza autorevole, a chi si è autenticato con il gettone
//! (ADR-0085, ADR-0086, ADR-0087). **Nessun comando** e nessun contenuto
//! monitorato: il live condiviso dice che cosa accade, non che cosa è scritto
//! (ADR-0093, decisione 1).
//!
//! # Che cosa non è misurato
//!
//! Il firewall di Windows la prima volta che questa porta si apre su una rete
//! d'ufficio (HVQ-79), e il comportamento con più client sotto carico (HVQ-08).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use core::str::FromStr;
use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;

use lisi_core::ContentId;
use lisi_core::NoteId;
use lisi_core::SessionId;
use lisi_core::model::enrollment::{EnrollmentCode, EnrollmentRefusal, EnrollmentRequest};
use lisi_core::model::hub_client::HubAddress;
use lisi_core::model::hub_command::{CommandId, CommandOutcome, CommandVerdict};
use lisi_core::model::hub_cyber::SharedCyberEvent;
use lisi_core::model::hub_event::{HubEvent, HubEventStreamId, ResumeVerdict, resume_from};
use lisi_core::model::hub_identity::HubFingerprint;
use lisi_core::model::hub_identity::HubFingerprintPrefix;
use lisi_core::model::hub_notes::{SharedNote, SharedWorkspace, SharedWorkspaceItem};
use lisi_core::model::hub_person::{Passphrase, Person, PersonId};
use lisi_core::model::hub_presence::{MAX_PRESENCE_PAGE, PresentStation};
use lisi_core::model::hub_report::SharedReport;
use lisi_core::model::hub_review::{ReviewContent, ReviewItem, ReviewQueueCursor};
use lisi_core::model::identity::OperatorId;
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::model::review::ReviewState;
use lisi_core::text::{AuditAction, AuditDetail, AuditEntity, DisplayName, Note};
use lisi_hub_transport::protocol::events::{
    ClientRequest, EVENTS_MAX_FRAME_BYTES, HubResponse, MAX_SHARED_SESSIONS_PAGE,
    MAX_WORK_QUEUE_PAGE, WireArtifact, WireCyberEvent, WireEvent, WireIndicator, WirePerson,
    WirePresentStation, WireReviewContent, WireReviewItem, WireSharedNote, WireSharedReport,
    WireSharedSession, WireSharedWorkspace, WireWorkItem, WireWorkspaceItem, read_request,
    send_response,
};
use lisi_hub_transport::protocol::events::{
    WireCoverageStretch, WireSourceCoverage, response_is_valid,
};
use lisi_hub_transport::protocol::handshake::{
    AuthDecision, EnrollmentAnswer, EnrollmentRefusalReason, HubOffer, HubOpening, hub_opening,
};
use lisi_hub_transport::protocol::negotiation::CAPABILITY_ASSIGNMENT;
use lisi_hub_transport::{HubKey, HubListener, HubServer, HubServerStream, ServerLimits};
use lisi_security::hub_key::{HUB_KEY_FILE, HubKeyMaterial, load_hub_key, store_new_hub_key};
use lisi_security::{ProtectedStore, SecurityError};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_access::{AccessOutcome, AuthenticatedDevice, HubAccessService};
use crate::hub_assignment::HubAssignmentService;
use crate::hub_client::HubConnectionStore;
use crate::hub_cyber::HubCyberService;
use crate::hub_enrollment::{EnrollmentOutcome, HubEnrollmentService};
use crate::hub_events::HubEventService;
use crate::hub_notes::HubNotesService;
use crate::hub_people::{AuthenticatedOperator, HubPeopleService, SignInOutcome};
use crate::hub_presence::{PresenceRegistry, Presente};
use crate::hub_report::HubReportService;
use crate::hub_review::HubReviewService;
use crate::office_networks::OfficeNetworksStore;
use crate::work_queue::{QueueItem, WorkQueueService};

/// Nome del file protetto con l'indirizzo su cui l'Hub ascolta.
pub const HUB_SERVER_FILE: &str = "hub-server.protetto";

/// Chiave dell'indirizzo di ascolto.
const LISTEN_KEY: &str = "hub_listen_address";

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "modalita_hub";

const AUDIT_CONFIGURED: &str = "indirizzo_hub_configurato";
const AUDIT_ACTIVATED: &str = "modalita_hub_attivata";
const AUDIT_DEACTIVATED: &str = "modalita_hub_disattivata";

/// Quanto si aspetta una richiesta da un client collegato.
///
/// Un client che tace non tiene occupato l'Hub: la connessione si chiude e le
/// altre restano (ADR-0090, guasto 2).
const ATTESA_RICHIESTA: Duration = Duration::from_secs(30);

/// Quanto si aspetta una richiesta da una connessione in cui una persona è
/// entrata (FINAL-REVIEW-01, FR-017).
///
/// Dieci minuti: quanto il blocco predefinito della postazione. Chi si alza
/// dalla scrivania blocca la postazione, e l'accesso muore con la connessione
/// (ADR-0097, decisione 6); chi sta leggendo non deve perderlo dopo trenta
/// secondi. Il posto occupato resta limitato dal tetto delle connessioni.
const ATTESA_CON_UNA_PERSONA: Duration = Duration::from_secs(600);

/// L'indirizzo su cui questa postazione ascolta, conservato.
#[derive(Debug)]
pub struct HubServerStore {
    store: ProtectedStore,
}

impl HubServerStore {
    /// Archivio sul file indicato.
    #[must_use]
    pub const fn at(store: ProtectedStore) -> Self {
        Self { store }
    }

    /// Archivio nella cartella indicata, accanto agli altri file protetti.
    #[must_use]
    pub fn in_directory(base: &Path) -> Self {
        Self::at(ProtectedStore::at(base.join(HUB_SERVER_FILE)))
    }

    /// Vero se questa postazione ha un indirizzo di ascolto configurato.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.store.exists()
    }

    /// Legge l'indirizzo conservato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il file esiste ma non è leggibile o non
    /// contiene un indirizzo utilizzabile.
    pub fn load(&self) -> ServiceResult<Option<HubAddress>> {
        if !self.store.exists() {
            return Ok(None);
        }
        let voci = self.store.load().map_err(map_security_error)?;
        let Some(testo) = voci.get(LISTEN_KEY) else {
            return Err(ServiceError::HubServer {
                reason: String::from("la configurazione della modalità Hub è incompleta"),
            });
        };
        Ok(Some(HubAddress::parse(testo)?))
    }

    /// Scrive l'indirizzo di ascolto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura protetta non riesce.
    pub fn save(&self, address: &HubAddress) -> ServiceResult<()> {
        let mut voci = BTreeMap::new();
        voci.insert(String::from(LISTEN_KEY), address.to_string());
        self.store.save(&voci).map_err(map_security_error)
    }
}

/// L'Hub acceso: finché vive, la porta è aperta.
pub struct RunningHub {
    server: HubServer,
    fingerprint: HubFingerprint,
}

impl core::fmt::Debug for RunningHub {
    /// Non mostra il server, che non ha una resa propria: dice l'indirizzo e
    /// l'impronta, che sono dati pubblici.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "RunningHub({}, {:?})",
            self.server.local_addr(),
            self.fingerprint
        )
    }
}

impl RunningHub {
    /// L'indirizzo effettivo su cui l'Hub ascolta.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    /// Quante connessioni sono in corso.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.server.active_connections()
    }

    /// Quante connessioni da fuori delle reti dell'ufficio sono state chiuse
    /// prima della negoziazione, da quando l'Hub ascolta (ADR-0198).
    #[must_use]
    pub fn refused_outside(&self) -> usize {
        self.server.refused_outside()
    }

    /// L'impronta della chiave di questo Hub.
    ///
    /// È ciò che va sul foglietto dell'arruolamento, nella forma leggibile dei
    /// primi 120 bit (ADR-0082).
    #[must_use]
    pub const fn fingerprint(&self) -> HubFingerprint {
        self.fingerprint
    }

    /// Chiude la porta.
    pub fn stop(self) {
        self.server.stop();
    }
}

/// Il nome con cui un Hub si presenta quando nessuno gliene ha dato uno.
pub const DEFAULT_HUB_NAME: &str = "Hub dell'ufficio";

/// Il foglietto dell'arruolamento: ciò che una persona ricopia e porta alla
/// postazione da collegare (ADR-0047, ADR-0082, ADR-0132).
///
/// # Che cosa contiene, e che cosa no
///
/// Il **codice** vale quindici minuti e una volta sola; l'**impronta** e
/// l'**indirizzo** sono dati pubblici, che servono a riconoscere l'Hub e a
/// raggiungerlo. Nessun segreto durevole: né la chiave dell'Hub, né un gettone.
///
/// `Debug` non mostra il codice (lo redige il suo tipo), e `Display` non
/// esiste: la sola via per leggerlo è [`Self::text_for_the_administrator`].
#[derive(Debug)]
pub struct EnrollmentSheet {
    /// Il codice monouso.
    code: EnrollmentCode,
    /// Fino a quando vale.
    pub expires_at: Timestamp,
    /// I primi 120 bit dell'impronta della chiave dell'Hub.
    pub fingerprint: HubFingerprintPrefix,
    /// Dove la postazione deve collegarsi.
    pub address: HubAddress,
    /// Come si chiama l'Hub.
    pub hub: DisplayName,
}

impl EnrollmentSheet {
    /// Il foglietto da mostrare a chi amministra, **codice compreso**.
    ///
    /// Destinato allo schermo dell'Hub e a nient'altro: non si registra, non si
    /// esporta, non va negli appunti.
    #[must_use]
    pub fn text_for_the_administrator(&self) -> String {
        format!(
            "Hub: {}\nIndirizzo dell'Hub: {}\nImpronta dell'Hub: {}\nCodice di arruolamento: {}\n\
             Vale fino al {}, una volta sola.",
            self.hub.as_str(),
            self.address,
            self.fingerprint.to_readable(),
            self.code.reveal_to_administrator(),
            self.expires_at.to_readable_utc()
        )
    }
}

/// La modalità Hub di questa postazione.
#[derive(Debug)]
pub struct HubServerService {
    listen: HubServerStore,
    connection: HubConnectionStore,
    /// Le reti dell'ufficio: dove l'Hub ascolta e da dove lo si raggiunge
    /// (HUB-SITES-01, ADR-0198).
    networks: OfficeNetworksStore,
    protected_dir: PathBuf,
    archive: PathBuf,
    limits: ServerLimits,
    /// Il nome dell'Hub, se chi lo accende gliene ha dato uno.
    name: Option<DisplayName>,
}

impl HubServerService {
    /// Costruisce il servizio.
    ///
    /// `protected_dir` è la cartella dei file protetti (dove vivono la chiave
    /// dell'Hub e le configurazioni); `archive` è il percorso dell'archivio
    /// SQLite che l'Hub serve — i fili delle connessioni lo aprono **ciascuno
    /// per conto proprio**, perché SQLite serializza chi scrive e una
    /// connessione per filo è il modo in cui va usato.
    #[must_use]
    pub fn new(protected_dir: PathBuf, archive: PathBuf) -> Self {
        Self {
            listen: HubServerStore::in_directory(&protected_dir),
            connection: HubConnectionStore::in_directory(&protected_dir),
            networks: OfficeNetworksStore::in_directory(&protected_dir),
            protected_dir,
            archive,
            limits: ServerLimits::default(),
            name: None,
        }
    }

    /// Sostituisce i tetti del trasporto. Serve alle prove.
    #[must_use]
    pub const fn with_limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Dà un nome a questo Hub.
    ///
    /// Il nome arriva sulla postazione all'arruolamento e vi resta: è il modo
    /// in cui la postazione riconosce di essere tornata **nello stesso** Hub
    /// (ADR-0047 decisione 8). Per questo deve restare lo stesso fra un
    /// avvio e l'altro.
    #[must_use]
    pub fn named(mut self, name: DisplayName) -> Self {
        self.name = Some(name);
        self
    }

    /// Il nome di questo Hub, o quello predefinito.
    fn nome(&self) -> ServiceResult<DisplayName> {
        match &self.name {
            Some(nome) => Ok(nome.clone()),
            None => Ok(DisplayName::try_new(DEFAULT_HUB_NAME)?),
        }
    }

    /// Emette un codice di arruolamento e compone il foglietto (ADR-0132).
    /// **Atto di una persona**, registrato con il suo identificativo, senza il
    /// codice.
    ///
    /// Non richiede che la porta sia aperta: il foglietto si può preparare
    /// prima. La postazione potrà collegarsi solo a porta aperta, e il codice
    /// vale quindici minuti.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se questa postazione segue un Hub, se l'indirizzo
    /// di ascolto non è configurato — il foglietto lo deve portare —, se la
    /// chiave non è utilizzabile, o se la scrittura non riesce.
    pub fn issue_enrollment_sheet(
        &self,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<EnrollmentSheet> {
        self.refuse_if_client()?;
        let Some(indirizzo) = self.listen.load()? else {
            return Err(ServiceError::HubServer {
                reason: String::from(
                    "prima di emettere un codice va salvato l'indirizzo dell'Hub: il foglietto \
                     lo deve portare",
                ),
            });
        };
        let impronta = self.key()?.fingerprint().prefix();
        let nome = self.nome()?;
        let emesso = HubEnrollmentService::new(Database::open(&self.archive)?, nome.clone())
            .issue_code(operator, now)?;
        Ok(EnrollmentSheet {
            code: emesso.code,
            expires_at: emesso.expires_at,
            fingerprint: impronta,
            address: indirizzo,
            hub: nome,
        })
    }

    /// L'indirizzo di ascolto configurato, se c'è.
    ///
    /// # Errori
    ///
    /// Gli stessi di [`HubServerStore::load`].
    pub fn address(&self) -> ServiceResult<Option<HubAddress>> {
        self.listen.load()
    }

    /// Configura l'indirizzo su cui questa postazione ascolterà. **Atto di una
    /// persona**, registrato con il suo identificativo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se questa postazione **segue** un Hub, se la
    /// scrittura protetta non riesce o se l'audit non si scrive.
    pub fn configure(
        &self,
        address: &HubAddress,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.refuse_if_client()?;
        // MAI SU UN INDIRIZZO CHE INTERNET RAGGIUNGE (ADR-0198, decisione 3),
        // salvo che l'ufficio non lo abbia dichiarato come proprio.
        if !self.networks.admits(address.as_socket_addr().ip())? {
            return Err(fuori_dalle_reti());
        }
        self.listen.save(address)?;
        self.audit(
            operator,
            AUDIT_CONFIGURED,
            &format!("ascolto su {address}"),
            now,
        )
    }

    /// Accende l'Hub: apre la porta e comincia a servire.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se questa postazione segue un Hub, se l'indirizzo
    /// non è configurato, se la chiave non è utilizzabile, se l'ascolto non
    /// riesce, o se l'audit non si scrive. **Nessuna porta resta aperta** se
    /// una di queste cose fallisce.
    pub fn activate(&self, operator: &OperatorId, now: Timestamp) -> ServiceResult<RunningHub> {
        self.refuse_if_client()?;

        let Some(indirizzo) = self.listen.load()? else {
            return Err(ServiceError::HubServer {
                reason: String::from(
                    "la modalità Hub non ha un indirizzo su cui ascoltare: va scelto prima di \
                     attivarla",
                ),
            });
        };

        let chiave = self.key()?;
        let impronta = chiave.fingerprint();

        // LE RETI DELL'UFFICIO SI RILEGGONO A OGNI ACCENSIONE (ADR-0198, decisione
        // 3 e 4): l'indirizzo di ascolto deve esserne parte, e da fuori non si
        // entra.
        let reti = self.networks.load()?;
        if !reti.admits(indirizzo.as_socket_addr().ip()) {
            return Err(fuori_dalle_reti());
        }
        let ascolto = HubListener::bind(indirizzo.as_socket_addr(), &chiave, self.limits)
            .and_then(|ascolto| ascolto.admit_only(reti))
            .map_err(|errore| ServiceError::HubServer {
                reason: format!("la porta non si è aperta: {errore}"),
            })?;

        let archivio = self.archive.clone();
        let nome = self.nome()?;
        // IL REGISTRO DELLE PRESENZE VIVE QUANTO LA PORTA APERTA, e non un
        // minuto di piu': niente archivio, niente eventi, niente audit
        // (ADR-0096, decisione 1). Quando l'Hub si ferma, non resta niente.
        let presenza = std::sync::Arc::new(PresenceRegistry::new());
        // I FRENI VIVONO QUANTO L'HUB ACCESO, e sono gli stessi per tutte le
        // connessioni (FINAL-REVIEW-01, FR-019): uno nuovo per connessione non
        // frenava nulla.
        let freni = Freni::default();
        let server = ascolto
            .serve(move |canale| {
                servi_una_connessione(&archivio, &nome, &presenza, &freni, canale, now);
            })
            .map_err(|errore| ServiceError::HubServer {
                reason: format!("l'Hub non è partito: {errore}"),
            })?;

        self.audit(
            operator,
            AUDIT_ACTIVATED,
            &format!("ascolto su {indirizzo}"),
            now,
        )?;

        Ok(RunningHub {
            server,
            fingerprint: impronta,
        })
    }

    /// Registra che la modalità Hub è stata disattivata.
    ///
    /// Chiudere la porta è [`RunningHub::stop`]; questo è l'atto che resta
    /// scritto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'audit non si scrive.
    pub fn record_deactivation(
        &self,
        operator: &OperatorId,
        now: Timestamp,
        refused_outside: usize,
    ) -> ServiceResult<()> {
        // LE CONNESSIONI DA FUORI SI RIASSUMONO QUI, una riga sola (ADR-0198,
        // decisione 4): una porta raggiunta da Internet ne riceverebbe migliaia.
        let dettaglio = if refused_outside == 0 {
            String::from("la porta dell'Hub è stata chiusa")
        } else {
            format!(
                "la porta dell'Hub è stata chiusa; connessioni da fuori delle reti \n                 dell'ufficio chiuse prima della negoziazione: {refused_outside}"
            )
        };
        self.audit(operator, AUDIT_DEACTIVATED, &dettaglio, now)
    }

    /// La chiave di questo Hub, generandola la prima volta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la generazione, la scrittura protetta o la
    /// rilettura non riescono.
    pub fn key(&self) -> ServiceResult<HubKey> {
        let percorso = self.protected_dir.join(HUB_KEY_FILE);
        if percorso.is_file() {
            let materiale = load_hub_key(percorso).map_err(map_security_error)?;
            return HubKey::from_pkcs8(materiale.expose_secret()).map_err(|errore| {
                ServiceError::HubServer {
                    reason: format!("la chiave dell'Hub non è utilizzabile: {errore}"),
                }
            });
        }

        let chiave = HubKey::generate().map_err(|errore| ServiceError::HubServer {
            reason: format!("la chiave dell'Hub non si è potuta generare: {errore}"),
        })?;
        let materiale = HubKeyMaterial::from_bytes(chiave.pkcs8_for_protection().to_vec());
        store_new_hub_key(percorso, &materiale).map_err(map_security_error)?;
        Ok(chiave)
    }

    /// Rifiuta quando questa postazione segue un Hub.
    fn refuse_if_client(&self) -> ServiceResult<()> {
        if self.connection.exists() {
            return Err(ServiceError::HubServer {
                reason: String::from(
                    "questa postazione segue un Hub: non può esserne uno a sua volta. Un ufficio \
                     ha una sola autorità, e cambiarla è un atto di chi amministra",
                ),
            });
        }
        Ok(())
    }

    fn audit(
        &self,
        operator: &OperatorId,
        azione: &str,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let database = Database::open(&self.archive)?;
        let voce = NewAuditEntry {
            actor: operator.audit_actor()?,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(dettaglio)?),
            recorded_at: now,
        };
        database.append_audit(&voce)?;
        Ok(())
    }
}

/// Serve una connessione: i due handshake, poi le pagine della sequenza.
///
/// Un guasto di un client **non è un guasto dell'Hub** (ADR-0090): qui si
/// chiude quella connessione e basta, e nessun errore risale a fermare
/// l'ascolto.
fn servi_una_connessione(
    archivio: &Path,
    nome: &DisplayName,
    presenza: &PresenceRegistry,
    freni: &Freni,
    mut canale: HubServerStream,
    now: Timestamp,
) {
    let Ok(database) = Database::open(archivio) else {
        canale.close();
        return;
    };
    let mut accesso =
        HubAccessService::with_brake(database, std::sync::Arc::clone(&freni.dispositivi));
    // L'INDIRIZZO, NON LA PORTA (FR-019): la porta del chiamante cambia a ogni
    // connessione, e un freno che la usasse come chiave non vedrebbe mai due
    // tentativi dallo stesso posto.
    let indirizzo = canale.peer_address().ip().to_string();

    let mut autenticato = None;
    let apertura = hub_opening(
        &mut canale,
        &HubOffer::default(),
        |device, presentato| match accesso.authenticate(
            device,
            &presentato.verifier(),
            &indirizzo,
            adesso_o(now),
        ) {
            Ok(AccessOutcome::Entered(dispositivo)) => {
                autenticato = Some(dispositivo);
                AuthDecision::Accepted
            }
            Ok(AccessOutcome::Revoked) => AuthDecision::Revoked,
            Ok(AccessOutcome::NotRecognized) | Err(_) => AuthDecision::NotRecognized,
        },
        // L'ISTANTE E' QUELLO DELLA RICHIESTA, non quello dell'accensione: un
        // codice emesso dopo che la porta e' stata aperta sembrerebbe emesso
        // nel futuro (ADR-0132, decisione 4).
        |richiesta| ammetti(archivio, nome, &richiesta, adesso_o(now)),
    );
    let accettato = match apertura {
        Ok(HubOpening::Session(accettato)) => accettato,
        // Dopo l'esito dell'arruolamento la connessione non serve piu': chi
        // e' entrato si ripresenta con il gettone (ADR-0132, decisione 1).
        Ok(HubOpening::Enrollment) | Err(_) => {
            canale.close();
            return;
        }
    };
    // LE CAPACITA' NEGOZIATE DECIDONO CHE COSA VIAGGIA (ADR-0084): i campi
    // dell'assegnazione partono solo verso chi li ha chiesti, e un client
    // della generazione precedente riceve la riga che sa leggere.
    let assegna = accettato
        .negotiated
        .capabilities
        .iter()
        .any(|nome| nome == CAPABILITY_ASSIGNMENT);

    // IL DISPOSITIVO AUTENTICATO SERVE ALLA REVISIONE CONDIVISA: e' cio' che
    // l'Hub autentica, e quindi cio' a cui una decisione viene attribuita
    // (ADR-0094, decisione 3). Alle pagine della sequenza non serve.
    let Some(autenticato) = autenticato else {
        canale.close();
        return;
    };

    // LA PRESENZA E' UN'OSSERVAZIONE DELL'HUB (ADR-0096, decisione 3): la
    // riga nasce **appena l'Hub ha autenticato**, e non piu' tardi. Aprire
    // prima l'archivio della revisione farebbe comparire la postazione
    // qualche millisecondo dopo che ha gia' cominciato a parlare, e chi
    // guarda vedrebbe un elenco in ritardo su cio' che sta succedendo.
    // Se ne va uscendo da questa funzione, comunque se ne esca (decisione 4).
    let presente = Presente::arriva(presenza, autenticato.device(), adesso_o(now));

    let eventi = HubEventService::new(accesso.into_database());
    // Una seconda connessione all'archivio per la revisione: SQLite serializza
    // chi scrive, e una connessione per mestiere e' il modo in cui va usato.
    let Ok(per_la_revisione) = Database::open(archivio) else {
        canale.close();
        return;
    };
    let mut revisione = HubReviewService::new(per_la_revisione);

    // DUE CONNESSIONI IN PIU' PER DUE MESTIERI IN PIU': SQLite serializza chi
    // scrive, e una connessione per mestiere e' il modo in cui va usato.
    let (Ok(per_le_persone), Ok(per_le_assegnazioni)) =
        (Database::open(archivio), Database::open(archivio))
    else {
        canale.close();
        return;
    };
    let mut persone =
        HubPeopleService::with_brake(per_le_persone, std::sync::Arc::clone(&freni.persone));
    let Ok(per_lo_scritto_insieme) = Database::open(archivio) else {
        canale.close();
        return;
    };
    let insieme = HubNotesService::new(per_lo_scritto_insieme);
    let (Ok(per_i_comandi_delle_relazioni), Ok(per_le_relazioni)) =
        (Database::open(archivio), Database::open(archivio))
    else {
        canale.close();
        return;
    };
    let mut relazioni = HubReportService::new(per_i_comandi_delle_relazioni, per_le_relazioni);
    let Ok(per_il_cyber) = Database::open(archivio) else {
        canale.close();
        return;
    };
    let cyber = HubCyberService::new(per_il_cyber);
    let mut assegnazioni = HubAssignmentService::new(per_le_assegnazioni);

    servi_le_richieste(
        &mut canale,
        &eventi,
        &mut revisione,
        &mut persone,
        &mut assegnazioni,
        &insieme,
        &mut relazioni,
        &cyber,
        assegna,
        &autenticato,
        &presente,
        presenza,
        archivio,
        now,
    );
    drop(presente);
    canale.close();
}

/// Risponde alle richieste finché il client parla.
///
/// Un guasto su una richiesta **chiude quella connessione e basta**: non risale
/// a fermare l'ascolto (ADR-0090).
#[allow(
    clippy::too_many_arguments,
    reason = "servire una connessione ha bisogno di tutto cio' che la connessione riguarda; \
              raggrupparlo in una struttura nasconderebbe che sono cose distinte"
)]
fn servi_le_richieste(
    canale: &mut HubServerStream,
    eventi: &HubEventService,
    revisione: &mut HubReviewService,
    persone: &mut HubPeopleService,
    assegnazioni: &mut HubAssignmentService,
    insieme: &HubNotesService,
    relazioni: &mut HubReportService,
    cyber: &HubCyberService,
    assegna: bool,
    device: &AuthenticatedDevice,
    presente: &Presente<'_>,
    presenza: &PresenceRegistry,
    archivio: &Path,
    now: Timestamp,
) {
    // CHI E' ENTRATO VALE PER QUESTA CONNESSIONE, E MUORE CON LEI (ADR-0097,
    // decisione 6): sulla postazione non resta niente, e un accesso non
    // sopravvive alla persona che se ne va dalla scrivania.
    let mut operatore: Option<AuthenticatedOperator> = None;

    loop {
        // CHI È ENTRATO LEGGE, E LEGGERE NON È SILENZIO (FINAL-REVIEW-01, FR-017).
        // Una postazione senza persona che tace occupa un posto per niente, e
        // dopo trenta secondi si chiude. Una persona entrata, invece, legge un
        // contenuto prima di decidere: fino al 2026-10-03 la sua connessione si
        // chiudeva allo stesso modo, e la decisione presa dopo non partiva.
        let attesa = if operatore.is_some() {
            ATTESA_CON_UNA_PERSONA
        } else {
            ATTESA_RICHIESTA
        };
        let Ok(richiesta) = read_request(canale, attesa) else {
            return;
        };
        // L'HUB HA APPENA SENTITO QUESTA POSTAZIONE. Non e' un tempo di
        // lavoro: e' cio' che distingue una riga viva da una connessione
        // caduta senza chiudersi (ADR-0096, decisione 4).
        presente.si_fa_sentire(adesso_o(now));

        let risposta = match richiesta {
            ClientRequest::Resume {
                stream,
                after,
                limit,
            } => {
                let Some(risposta) =
                    pagina_della_sequenza(eventi, &stream, after, limit, adesso_o(now))
                else {
                    return;
                };
                risposta
            }
            ClientRequest::ReviewQueue {
                after_content_id,
                limit,
            } => {
                let cursore = ReviewQueueCursor {
                    after_content_id,
                    limit,
                };
                let Ok(elementi) = revisione.queue(cursore) else {
                    return;
                };
                HubResponse::ReviewQueuePage {
                    items: elementi.iter().map(elemento_sul_filo).collect(),
                }
            }
            ClientRequest::WorkQueue { limit } => {
                // LA CODA DELL'UFFICIO LA COMPONE L'HUB (ADR-0095): due
                // postazioni devono guardare la stessa sequenza, e un client
                // che ordinasse da se' ordinerebbe su cio' che ha.
                let coda = WorkQueueService::new(match Database::open(archivio) {
                    Ok(database) => database,
                    Err(_) => return,
                });
                let Ok(composta) = coda.compose(adesso_o(now)) else {
                    return;
                };
                // A CHI E' IL LAVORO, IN UNA LETTURA SOLA (ADR-0098,
                // decisione 6). L'ORDINE NON CAMBIA: far salire o scendere le
                // righe per via dell'assegnazione darebbe a ogni persona una
                // coda diversa, e la coda dell'ufficio e' una sola.
                let mostrate: Vec<_> = composta
                    .items
                    .iter()
                    .take(limit.min(MAX_WORK_QUEUE_PAGE))
                    .collect();
                let identificativi: Vec<_> = mostrate.iter().map(|riga| riga.content_id).collect();
                let assegnati = if assegna {
                    match assegnazioni.database().hub_assignments_of(&identificativi) {
                        Ok(assegnati) => assegnati,
                        Err(_) => return,
                    }
                } else {
                    std::collections::BTreeMap::new()
                };
                HubResponse::WorkQueuePage {
                    items: mostrate
                        .iter()
                        .map(|riga| {
                            let versione = if assegna {
                                assegnazioni.version(riga.content_id).unwrap_or_default()
                            } else {
                                0
                            };
                            riga_sul_filo(
                                riga,
                                assegnati
                                    .get(&riga.content_id.get())
                                    .map(|persona| String::from(persona.as_str())),
                                versione,
                                composta.composed_at,
                            )
                        })
                        .collect(),
                    composed_at: composta.composed_at.as_millis(),
                    untouched: composta.untouched(),
                    in_review: composta.in_review(),
                    total: composta.items.len(),
                }
            }
            ClientRequest::SignIn { person, passphrase } => {
                // L'IDENTITA' NON SI DICHIARA: SI DIMOSTRA (ADR-0097,
                // decisione 1). Un identificativo o una frase che non
                // attraversano i tipi del dominio ricevono lo stesso rifiuto
                // di una frase sbagliata: dire che erano malformati direbbe
                // qualcosa a chi sta provando.
                let indirizzo = canale.peer_address().to_string();
                let esito = match (
                    PersonId::parse(&person),
                    Passphrase::try_new(passphrase.expose()),
                ) {
                    (Ok(chi), Ok(frase)) => {
                        match persone.sign_in(&chi, &frase, &indirizzo, adesso_o(now)) {
                            Ok(esito) => esito,
                            Err(_) => return,
                        }
                    }
                    _ => SignInOutcome::NotRecognized,
                };

                let (verdetto, ruolo) = match &esito {
                    SignInOutcome::Entered(entrato) => {
                        let ruolo = String::from(entrato.role().as_str());
                        operatore = Some(entrato.clone());
                        ("entrata", Some(ruolo))
                    }
                    SignInOutcome::NotRecognized => ("non_riconosciuta", None),
                    SignInOutcome::Suspended => ("sospesa", None),
                };
                HubResponse::SignInOutcome {
                    verdict: String::from(verdetto),
                    role: ruolo,
                    detail: String::from(esito.operator_message()),
                }
            }
            ClientRequest::SharedNotes {
                kind,
                target_id,
                limit,
            } => match riferimento(&kind, target_id) {
                Some(dove) => match insieme.notes_about(dove, limit) {
                    Ok(note) => HubResponse::SharedNotesPage {
                        notes: note.iter().map(nota_sul_filo).collect(),
                    },
                    Err(_) => return,
                },
                None => rifiutata("il riferimento non è utilizzabile"),
            },
            ClientRequest::WriteSharedNote {
                kind,
                target_id,
                body,
            } => scritta_insieme(operatore.as_ref(), |entrato| {
                let (Some(dove), Ok(parole)) =
                    (riferimento(&kind, target_id), Note::try_new(&body))
                else {
                    return rifiutata("la nota non è in una forma che questo Hub riconosce");
                };
                match insieme.write(entrato, dove, &parole, adesso_o(now)) {
                    Ok(_) => fatta("nota scritta"),
                    Err(errore) => rifiutata(&errore.operator_message()),
                }
            }),
            ClientRequest::WithdrawSharedNote { note_id } => {
                scritta_insieme(operatore.as_ref(), |entrato| {
                    match insieme.withdraw(entrato, NoteId::new(note_id), adesso_o(now)) {
                        Ok(()) => fatta("nota ritirata"),
                        Err(errore) => rifiutata(&errore.operator_message()),
                    }
                })
            }
            ClientRequest::SharedWorkspaces { limit } => match insieme.workspaces(limit) {
                Ok(raccoglitori) => HubResponse::SharedWorkspacesPage {
                    workspaces: raccoglitori.iter().map(raccoglitore_sul_filo).collect(),
                },
                Err(_) => return,
            },
            ClientRequest::SharedWorkspaceItems {
                workspace_id,
                limit,
            } => match insieme.items(workspace_id, limit) {
                Ok(elementi) => HubResponse::SharedWorkspaceItemsPage {
                    items: elementi.iter().map(elemento_raccolto_sul_filo).collect(),
                },
                Err(_) => return,
            },
            ClientRequest::OpenSharedWorkspace { name, description } => {
                scritta_insieme(operatore.as_ref(), |entrato| {
                    let Ok(nome) = DisplayName::try_new(&name) else {
                        return rifiutata("il nome non è in una forma che questo Hub riconosce");
                    };
                    let descrizione = match description.as_deref().map(Note::try_new).transpose() {
                        Ok(descrizione) => descrizione,
                        Err(_) => {
                            return rifiutata(
                                "la descrizione non è in una forma che questo Hub riconosce",
                            );
                        }
                    };
                    match insieme.open_workspace(
                        entrato,
                        &nome,
                        descrizione.as_ref(),
                        adesso_o(now),
                    ) {
                        Ok(_) => fatta("raccoglitore aperto"),
                        Err(errore) => rifiutata(&errore.operator_message()),
                    }
                })
            }
            ClientRequest::CloseSharedWorkspace { workspace_id } => {
                scritta_insieme(operatore.as_ref(), |entrato| {
                    match insieme.close_workspace(entrato, workspace_id, adesso_o(now)) {
                        Ok(()) => fatta("raccoglitore chiuso"),
                        Err(errore) => rifiutata(&errore.operator_message()),
                    }
                })
            }
            ClientRequest::CollectInWorkspace {
                workspace_id,
                kind,
                target_id,
            } => scritta_insieme(operatore.as_ref(), |entrato| {
                let Some(cosa) = riferimento(&kind, target_id) else {
                    return rifiutata("il riferimento non è utilizzabile");
                };
                match insieme.collect(entrato, workspace_id, cosa, adesso_o(now)) {
                    Ok(()) => fatta("elemento raccolto"),
                    Err(errore) => rifiutata(&errore.operator_message()),
                }
            }),
            ClientRequest::DropFromWorkspace {
                workspace_id,
                kind,
                target_id,
            } => scritta_insieme(operatore.as_ref(), |entrato| {
                let Some(cosa) = riferimento(&kind, target_id) else {
                    return rifiutata("il riferimento non è utilizzabile");
                };
                match insieme.drop_item(entrato, workspace_id, cosa, adesso_o(now)) {
                    Ok(()) => fatta("elemento tolto"),
                    Err(errore) => rifiutata(&errore.operator_message()),
                }
            }),
            ClientRequest::SharedReports { limit } => match relazioni.reports(limit) {
                Ok(elenco) => HubResponse::SharedReportsPage {
                    reports: elenco.iter().map(relazione_sul_filo).collect(),
                },
                Err(_) => return,
            },
            ClientRequest::FreezeSharedReport {
                command_id,
                session_id,
                contents,
            } => scritta_insieme(operatore.as_ref(), |entrato| {
                let Ok(identificativo) = CommandId::parse(&command_id) else {
                    return rifiutata("la richiesta non è in una forma che questo Hub riconosce");
                };
                match relazioni.freeze(
                    device,
                    entrato,
                    identificativo,
                    SessionId::new(session_id),
                    &contents,
                    adesso_o(now),
                ) {
                    Ok(verdetto) => verdetto_sul_filo(&verdetto, 0),
                    Err(errore) => rifiutata(&errore.operator_message()),
                }
            }),
            ClientRequest::SharedCyberEvents { session_id, limit } => {
                match cyber.events(SessionId::new(session_id), limit) {
                    Ok(grappoli) => HubResponse::SharedCyberPage {
                        events: grappoli.iter().map(grappolo_sul_filo).collect(),
                    },
                    Err(_) => return,
                }
            }
            ClientRequest::SharedSessions { limit } => {
                let Ok(sessioni) = cyber.database().sessions() else {
                    return;
                };
                HubResponse::SharedSessionsPage {
                    sessions: sessioni
                        .iter()
                        .take(limit.min(MAX_SHARED_SESSIONS_PAGE))
                        .map(monitoraggio_sul_filo)
                        .collect(),
                }
            }
            ClientRequest::RemoteCommand {
                command_id,
                session_id,
                action,
                reason,
            } => {
                // NESSUN COMANDO SENZA NOME (ADR-0200, decisione 2): una
                // postazione senza persona non comanda.
                match operatore.as_ref() {
                    None => rifiutata(
                        "Per comandare a distanza occorre prima entrare come persona su questo Hub.",
                    ),
                    Some(entrato) => comando_a_distanza(
                        archivio,
                        device,
                        entrato,
                        &command_id,
                        SessionId::new(session_id),
                        &action,
                        &reason,
                        adesso_o(now),
                    ),
                }
            }
            ClientRequest::SharedCoverage { session_id } => {
                copertura_sul_filo(cyber.database(), SessionId::new(session_id), adesso_o(now))
            }
            ClientRequest::People => {
                // L'ELENCO DEI COLLEGHI E' DI CHI E' GIA' DENTRO (ADR-0097):
                // a chi non si e' dimostrato l'Hub non dice quali
                // identificativi esistono.
                if operatore.is_none() {
                    HubResponse::PeoplePage { people: Vec::new() }
                } else {
                    let Ok(elenco) = persone.people() else {
                        return;
                    };
                    HubResponse::PeoplePage {
                        people: elenco.iter().map(persona_sul_filo).collect(),
                    }
                }
            }
            ClientRequest::Assign {
                command_id,
                content_id,
                expected_version,
                to,
            } => assegnazione_ricevuta(
                assegnazioni,
                device,
                operatore.as_ref(),
                &command_id,
                ContentId::new(content_id),
                expected_version,
                to.as_deref(),
                adesso_o(now),
            ),
            ClientRequest::Presence { limit } => {
                let fotografia = presenza.snapshot(adesso_o(now), limit.min(MAX_PRESENCE_PAGE));
                HubResponse::PresencePage {
                    stations: fotografia
                        .stations
                        .iter()
                        .map(postazione_sul_filo)
                        .collect(),
                    composed_at: fotografia.composed_at.as_millis(),
                    total: fotografia.total,
                }
            }
            ClientRequest::ReviewContent { content_id } => {
                match revisione.content_for(device, ContentId::new(content_id), adesso_o(now)) {
                    Ok(contenuto) => HubResponse::ReviewContentPage {
                        content: contenuto.as_ref().map(contenuto_sul_filo),
                    },
                    // Il rifiuto per ruolo e' un esito, non un guasto: si dice,
                    // e la connessione resta.
                    Err(errore) => HubResponse::ReviewOutcome {
                        verdict: String::from("rifiutata"),
                        detail: errore.operator_message(),
                        current_version: 0,
                    },
                }
            }
            ClientRequest::SubmitReview {
                command_id,
                content_id,
                expected_version,
                state,
                note,
            } => decisione_ricevuta(
                revisione,
                device,
                operatore.as_ref(),
                &command_id,
                ContentId::new(content_id),
                expected_version,
                &state,
                note.as_deref(),
                adesso_o(now),
            ),
        };

        if send_response(canale, &entro_la_misura(risposta)).is_err() {
            return;
        }
    }
}

/// Registra una decisione ricevuta, e dice com'e' andata.
///
/// Una decisione **malformata** non chiude la connessione: si risponde che non
/// e' in una forma riconosciuta. Chiudere lascerebbe l'operatore davanti a una
/// finestra che dice «l'Hub non risponde» per un difetto di chi ha scritto il
/// client.
#[allow(clippy::too_many_arguments)]
fn decisione_ricevuta(
    revisione: &mut HubReviewService,
    device: &AuthenticatedDevice,
    operator: Option<&AuthenticatedOperator>,
    command_id: &str,
    content_id: ContentId,
    expected_version: u64,
    state: &str,
    note: Option<&str>,
    now: Timestamp,
) -> HubResponse {
    let malformata = |detail: &str| HubResponse::ReviewOutcome {
        verdict: String::from("rifiutata"),
        detail: String::from(detail),
        current_version: expected_version,
    };

    let (Ok(identificativo), Ok(stato)) =
        (CommandId::parse(command_id), ReviewState::from_str(state))
    else {
        return malformata("la decisione non è in una forma che questo Hub riconosce");
    };
    let nota = match note.map(Note::try_new).transpose() {
        Ok(nota) => nota,
        Err(_) => return malformata("la motivazione non è in una forma che questo Hub riconosce"),
    };

    let Ok(verdetto) = revisione.submit(
        device,
        operator,
        identificativo,
        content_id,
        expected_version,
        stato,
        nota,
        now,
    ) else {
        return malformata("la decisione non è stata registrata");
    };
    let versione = revisione
        .database()
        .hub_review_version(content_id)
        .unwrap_or(expected_version);
    verdetto_sul_filo(&verdetto, versione)
}

/// Registra un cambio di assegnazione, e dice com'e' andata.
///
/// Come per la decisione, una richiesta **malformata** non chiude la
/// connessione: si risponde che non e' in una forma riconosciuta.
#[allow(
    clippy::too_many_arguments,
    reason = "assegnare ha bisogno di chi, a chi, che cosa e contro quale versione; \
              raggrupparlo nasconderebbe che sono cose distinte"
)]
fn assegnazione_ricevuta(
    assegnazioni: &mut HubAssignmentService,
    device: &AuthenticatedDevice,
    operatore: Option<&AuthenticatedOperator>,
    command_id: &str,
    content_id: ContentId,
    expected_version: u64,
    to: Option<&str>,
    now: Timestamp,
) -> HubResponse {
    let rifiutata = |detail: &str| HubResponse::ReviewOutcome {
        verdict: String::from("rifiutata"),
        detail: String::from(detail),
        current_version: expected_version,
    };

    // ASSEGNARE E' UN ATTO DI UNA PERSONA (ADR-0098, decisione 5). Senza
    // persona entrata non c'e' a chi attribuirlo, e attribuirlo alla
    // postazione sarebbe il segnaposto con un nome piu' convincente.
    let Some(entrato) = operatore else {
        return rifiutata(
            "Per assegnare il lavoro occorre prima entrare come persona su questo Hub.",
        );
    };

    let Ok(identificativo) = CommandId::parse(command_id) else {
        return rifiutata("la richiesta non è in una forma che questo Hub riconosce");
    };
    let destinatario = match to.map(PersonId::parse).transpose() {
        Ok(destinatario) => destinatario,
        Err(_) => return rifiutata("l'identificativo della persona non è utilizzabile"),
    };

    let Ok(verdetto) = assegnazioni.submit(
        device,
        entrato,
        identificativo,
        content_id,
        expected_version,
        destinatario,
        now,
    ) else {
        return rifiutata("il cambio non è stato registrato");
    };
    let versione = assegnazioni.version(content_id).unwrap_or(expected_version);
    verdetto_sul_filo(&verdetto, versione)
}

/// La pagina della sequenza per una richiesta di recupero.
fn pagina_della_sequenza(
    eventi: &HubEventService,
    stream: &str,
    after: u64,
    limit: usize,
    now: Timestamp,
) -> Option<HubResponse> {
    let (Ok(flusso), Ok(latest)) = (HubEventStreamId::parse(stream), eventi.latest()) else {
        return None;
    };
    let Ok(nostro) = eventi.stream_id(now) else {
        return None;
    };

    let cursore = lisi_core::model::hub_event::EventCursor {
        stream: flusso,
        last_sequence: after,
    };
    Some(match resume_from(cursore, nostro, latest) {
        ResumeVerdict::StreamChanged => HubResponse::NotOurStream {
            stream: nostro.to_hex(),
            latest,
        },
        ResumeVerdict::AheadOfHub => HubResponse::AheadOfHub { latest },
        ResumeVerdict::Resume { after } => {
            let pagina = eventi.database().hub_events_after(after, limit).ok()?;
            HubResponse::Page {
                events: pagina.iter().map(sul_filo).collect(),
                latest,
            }
        }
    })
}

/// Fa una cosa che si scrive insieme, se qualcuno si e' dimostrato.
///
/// Senza persona non si scrive: una nota e' **parole di qualcuno**, e senza un
/// autore verificato e' un foglietto anonimo lasciato sulla scrivania di tutti
/// (ADR-0099, decisione 3).
fn scritta_insieme<F>(operatore: Option<&AuthenticatedOperator>, azione: F) -> HubResponse
where
    F: FnOnce(&AuthenticatedOperator) -> HubResponse,
{
    match operatore {
        Some(entrato) => azione(entrato),
        None => rifiutata(
            "Per scrivere insieme agli altri occorre prima entrare come persona su questo Hub.",
        ),
    }
}

/// La risposta che dice «rifiutata», e perche'.
fn rifiutata(detail: &str) -> HubResponse {
    HubResponse::ReviewOutcome {
        verdict: String::from("rifiutata"),
        detail: String::from(detail),
        current_version: 0,
    }
}

/// La risposta che dice «fatta».
fn fatta(detail: &str) -> HubResponse {
    HubResponse::ReviewOutcome {
        verdict: String::from("applicata"),
        detail: String::from(detail),
        current_version: 0,
    }
}

/// Il riferimento che arriva dalla rete, riportato ai tipi del dominio.
fn riferimento(kind: &str, target_id: i64) -> Option<ArchiveRef> {
    let genere = ArchiveRefKind::from_str(kind).ok()?;
    ArchiveRef::to(genere, target_id).ok()
}

/// Una nota dell'ufficio come viaggia.
fn nota_sul_filo(nota: &SharedNote) -> WireSharedNote {
    WireSharedNote {
        id: nota.id.get(),
        kind: String::from(nota.about.kind().as_str()),
        target_id: nota.about.target_id(),
        body: String::from(nota.body.as_str()),
        author: String::from(nota.author.as_str()),
        written_at: nota.written_at.as_millis(),
        withdrawn_by: nota
            .withdrawn
            .as_ref()
            .map(|(chi, _)| String::from(chi.as_str())),
        withdrawn_at: nota
            .withdrawn
            .as_ref()
            .map_or(0, |(_, quando)| quando.as_millis()),
    }
}

/// Un raccoglitore dell'ufficio come viaggia.
fn raccoglitore_sul_filo(raccoglitore: &SharedWorkspace) -> WireSharedWorkspace {
    WireSharedWorkspace {
        id: raccoglitore.id,
        name: String::from(raccoglitore.name.as_str()),
        description: raccoglitore
            .description
            .as_ref()
            .map(|testo| String::from(testo.as_str())),
        state: String::from(raccoglitore.state.as_str()),
        opened_by: String::from(raccoglitore.opened_by.as_str()),
        opened_at: raccoglitore.opened_at.as_millis(),
        items: raccoglitore.items,
    }
}

/// Un riferimento raccolto come viaggia.
fn elemento_raccolto_sul_filo(elemento: &SharedWorkspaceItem) -> WireWorkspaceItem {
    WireWorkspaceItem {
        kind: String::from(elemento.item.kind().as_str()),
        target_id: elemento.item.target_id(),
        added_by: String::from(elemento.added_by.as_str()),
        added_at: elemento.added_at.as_millis(),
    }
}

/// Un monitoraggio dell'ufficio come viaggia.
///
/// **Nessun contenuto**: come si chiama, in quale stato e' e quando.
fn monitoraggio_sul_filo(sessione: &lisi_core::model::Session) -> WireSharedSession {
    WireSharedSession {
        session_id: sessione.id.get(),
        label: String::from(sessione.label.as_str()),
        state: String::from(sessione.state.as_str()),
        started_at: sessione
            .started_at
            .map_or(0, lisi_core::Timestamp::as_millis),
        ended_at: sessione.ended_at.map_or(0, lisi_core::Timestamp::as_millis),
    }
}

/// Un comando a distanza, deciso dal servizio e detto sul filo (HUB-REMOTE-01,
/// ADR-0200). Eseguito, rifiutato o ripetuto, la risposta dice sempre com'è
/// andata.
#[allow(clippy::too_many_arguments)]
fn comando_a_distanza(
    archivio: &Path,
    device: &AuthenticatedDevice,
    entrato: &AuthenticatedOperator,
    command_id: &str,
    sessione: SessionId,
    atto: &str,
    motivo: &str,
    adesso: Timestamp,
) -> HubResponse {
    let richiesta = crate::remote_commands::RemoteCommandRequest {
        command_id,
        device: device.device().as_str(),
        person: entrato.person(),
        role: entrato.role(),
        session_id: sessione,
        action: atto,
        reason: motivo,
    };
    match crate::remote_commands::execute(archivio, &richiesta, adesso) {
        Ok(crate::remote_commands::RemoteVerdict::Executed(frase)) => fatta(&frase),
        Ok(crate::remote_commands::RemoteVerdict::Refused(ragione)) => rifiutata(&ragione),
        Ok(crate::remote_commands::RemoteVerdict::Replay(_, frase)) => HubResponse::ReviewOutcome {
            verdict: String::from("ripetuta"),
            detail: frase,
            current_version: 0,
        },
        Err(_) => rifiutata("il comando a distanza non si è potuto registrare sull'Hub"),
    }
}

/// La copertura di un monitoraggio dell'ufficio come viaggia (HUB-COVERAGE-01,
/// ADR-0199).
///
/// Si calcola con lo stesso codice dello schermo dell'Hub, e viaggia **intera**:
/// una copertura che non sta nei limiti del canale diventa un rifiuto detto,
/// mai una copertura con meno tratti o meno fonti (decisione 4).
fn copertura_sul_filo(archivio: &Database, sessione: SessionId, adesso: Timestamp) -> HubResponse {
    match archivio.sessions() {
        Ok(sessioni) if sessioni.iter().any(|riga| riga.id == sessione) => {}
        Ok(_) => return rifiutata("questo monitoraggio non è nell'archivio dell'Hub"),
        Err(_) => {
            return rifiutata("la copertura di questo monitoraggio non si è potuta comporre");
        }
    }
    let Ok(copertura) = crate::coverage::for_monitoring(archivio, sessione, adesso) else {
        return rifiutata("la copertura di questo monitoraggio non si è potuta comporre");
    };
    let tratti = |copertura: &lisi_core::model::coverage::Coverage| {
        copertura
            .intervals()
            .iter()
            .map(|tratto| WireCoverageStretch {
                from: tratto.from.as_millis(),
                to: tratto.to.as_millis(),
                state: String::from(tratto.state.token()),
            })
            .collect()
    };
    let risposta = HubResponse::SharedCoveragePage {
        session_id: sessione.get(),
        taken_at: adesso.as_millis(),
        overall: tratti(&copertura.overall),
        sources: copertura
            .sources
            .iter()
            .map(|(_, nome, fonte)| WireSourceCoverage {
                name: nome.clone(),
                stretches: tratti(fonte),
            })
            .collect(),
    };
    if response_is_valid(&risposta) {
        risposta
    } else {
        rifiutata(
            "la copertura di questo monitoraggio ha troppi tratti per il canale: si legge \
             sull'Hub",
        )
    }
}

/// Un grappolo cyber dell'ufficio come viaggia.
///
/// **Gli osservabili e i fatti, mai il testo** (ADR-0102, decisione 2).
fn grappolo_sul_filo(grappolo: &SharedCyberEvent) -> WireCyberEvent {
    WireCyberEvent {
        position: grappolo.position,
        session_id: grappolo.session_id.get(),
        reason: grappolo.reason.clone(),
        contents: grappolo.contents,
        distinct_sources: grappolo.distinct_sources,
        apparent_reposts: grappolo.apparent_reposts,
        italy: grappolo.italy.clone(),
        sectors: grappolo.sectors.clone(),
        indicators: grappolo
            .indicators
            .iter()
            .map(|indicatore| WireIndicator {
                kind: indicatore.kind.clone(),
                value: indicatore.value.clone(),
            })
            .collect(),
        decided: grappolo.decided,
        in_progress: grappolo.in_progress,
        untouched: grappolo.untouched,
        first_seen: grappolo
            .seen_between
            .map_or(0, |(primo, _)| primo.as_millis()),
        last_seen: grappolo
            .seen_between
            .map_or(0, |(_, ultimo)| ultimo.as_millis()),
    }
}

/// Una relazione dell'ufficio come viaggia.
///
/// **Nomi e impronte, mai byte** (ADR-0100, decisione 2).
fn relazione_sul_filo(relazione: &SharedReport) -> WireSharedReport {
    WireSharedReport {
        report_id: relazione.report_id.clone(),
        session_id: relazione.session_id.get(),
        requested_by: relazione.requested_by.clone(),
        status: String::from(relazione.status.as_str()),
        requested_at: relazione.requested_at.as_millis(),
        completed_at: relazione
            .completed_at
            .map_or(0, lisi_core::Timestamp::as_millis),
        monitored: relazione.monitored,
        selected: relazione.selected,
        artifacts: relazione
            .artifacts
            .iter()
            .map(|documento| WireArtifact {
                file_name: documento.file_name.clone(),
                size_bytes: documento.size_bytes,
                sha256: documento.sha256.clone(),
            })
            .collect(),
    }
}

/// Una persona dell'ufficio come viaggia.
///
/// **Nessun verificatore**: cio' che l'Hub conserva al posto di una frase non
/// esce da li'.
fn persona_sul_filo(persona: &Person) -> WirePerson {
    WirePerson {
        person: String::from(persona.id.as_str()),
        label: String::from(persona.label.as_str()),
        role: String::from(persona.role.as_str()),
        state: String::from(persona.state.as_str()),
    }
}

/// Una postazione presente come viaggia.
///
/// Tre cose, e nessuna in piu' (ADR-0096, decisione 2).
fn postazione_sul_filo(postazione: &PresentStation) -> WirePresentStation {
    WirePresentStation {
        device: String::from(postazione.device.as_str()),
        connected_since: postazione.connected_since.as_millis(),
        last_seen: postazione.last_seen.as_millis(),
    }
}

/// Una risposta che sta nel frame (FINAL-REVIEW-01, FR-018).
///
/// Le pagine si limitano in **righe** e i testi in **caratteri**, ma il frame
/// si misura in **byte**: cinquanta note da duemila caratteri di quattro byte
/// sono circa quattrocento kibibyte, oltre il tetto. Fino al 2026-10-03 l'invio
/// falliva e l'Hub chiudeva la connessione senza una parola, ogni volta che
/// qualcuno apriva quel contenuto — portandosi via l'accesso della persona.
///
/// Ora una pagina troppo grande si **accorcia** dalla coda, una riga alla
/// volta, finché entra: chi la riceve ne vede meno, e le altre restano
/// sull'Hub. La pagina degli eventi del recupero **non** si accorcia qui,
/// perché il suo cursore è un patto con il client; una risposta che non si
/// può accorciare diventa un rifiuto detto, non una chiusura muta.
fn entro_la_misura(mut risposta: HubResponse) -> HubResponse {
    let tetto = usize::try_from(EVENTS_MAX_FRAME_BYTES).unwrap_or(usize::MAX);
    let misura =
        |risposta: &HubResponse| serde_json::to_vec(risposta).map_or(usize::MAX, |b| b.len());
    while misura(&risposta) > tetto {
        let accorciata = match &mut risposta {
            HubResponse::SharedNotesPage { notes } => notes.pop().is_some(),
            HubResponse::ReviewQueuePage { items } => items.pop().is_some(),
            HubResponse::WorkQueuePage { items, .. } => items.pop().is_some(),
            HubResponse::PresencePage { stations, .. } => stations.pop().is_some(),
            HubResponse::SharedWorkspacesPage { workspaces } => workspaces.pop().is_some(),
            HubResponse::SharedWorkspaceItemsPage { items } => items.pop().is_some(),
            HubResponse::SharedReportsPage { reports } => reports.pop().is_some(),
            HubResponse::SharedCyberPage { events } => events.pop().is_some(),
            HubResponse::SharedSessionsPage { sessions } => sessions.pop().is_some(),
            HubResponse::PeoplePage { people } => people.pop().is_some(),
            _ => false,
        };
        if !accorciata {
            return HubResponse::ReviewOutcome {
                verdict: String::from("rifiutata"),
                detail: String::from(
                    "la risposta supera la misura del canale e non si può accorciare",
                ),
                current_version: 0,
            };
        }
    }
    risposta
}

/// I due freni di un Hub acceso: dispositivi non riconosciuti e frasi
/// sbagliate (FINAL-REVIEW-01, FR-019). Frenano la **registrazione** dei
/// tentativi, non l'esito: chi presenta la credenziale giusta entra comunque
/// (ADR-0085, decisione 4).
#[derive(Debug, Default)]
struct Freni {
    dispositivi: crate::hub_access::SharedBrake,
    persone: crate::hub_access::SharedBrake,
}

/// L'ora vera, o quella con cui l'Hub e' stato acceso.
///
/// Ogni atto dell'Hub si data con l'ora **di adesso**, non con quella
/// dell'accensione (FINAL-REVIEW-01, FR-005). Se l'orologio del sistema non si
/// lascia leggere, si usa
/// quello dell'accensione: una riga con un'ora vecchia e' meno grave di una
/// connessione che si chiude.
fn adesso_o(accensione: Timestamp) -> Timestamp {
    Timestamp::now().unwrap_or(accensione)
}

/// Decide una richiesta di arruolamento arrivata dalla rete (ADR-0132).
///
/// È il servizio che c'era: freno, dispositivo, codice consumato nella stessa
/// transazione, audit con l'attore `hub.arruolamento`, evento
/// `DeviceEnrolled`. Questa funzione traduce soltanto l'esito nella forma del
/// filo.
///
/// La ragione di un ritiro **non viaggia**: la legge chi amministra l'Hub.
fn ammetti(
    archivio: &Path,
    nome: &DisplayName,
    richiesta: &EnrollmentRequest,
    now: Timestamp,
) -> EnrollmentAnswer {
    let esito = match Database::open(archivio) {
        Ok(database) => HubEnrollmentService::new(database, nome.clone()).admit(richiesta, now),
        Err(errore) => Err(ServiceError::from(errore)),
    };
    let rifiuto = |reason| EnrollmentAnswer::Refused {
        reason,
        retry_in_minutes: None,
    };
    match esito {
        Ok(EnrollmentOutcome::Admitted(concessione)) => EnrollmentAnswer::Admitted {
            hub: String::from(concessione.hub.as_str()),
            enrolled_at_ms: concessione.enrolled_at.as_millis(),
        },
        Ok(EnrollmentOutcome::Refused(motivo)) => match motivo {
            EnrollmentRefusal::CodeNotRecognised => {
                rifiuto(EnrollmentRefusalReason::CodeNotRecognised)
            }
            EnrollmentRefusal::CodeExpired => rifiuto(EnrollmentRefusalReason::CodeExpired),
            EnrollmentRefusal::CodeAlreadyUsed => rifiuto(EnrollmentRefusalReason::CodeAlreadyUsed),
            EnrollmentRefusal::DeviceAlreadyEnrolled => {
                rifiuto(EnrollmentRefusalReason::DeviceAlreadyEnrolled)
            }
            EnrollmentRefusal::DeviceRevoked { .. } => {
                rifiuto(EnrollmentRefusalReason::DeviceRevoked)
            }
            EnrollmentRefusal::TooManyRecentFailures { retry_in_minutes } => {
                EnrollmentAnswer::Refused {
                    reason: EnrollmentRefusalReason::TooManyRecentFailures,
                    retry_in_minutes: Some(retry_in_minutes),
                }
            }
        },
        Err(errore) => {
            // Il tipo dell'errore, mai la richiesta: dentro c'e' il codice.
            tracing::warn!(kind = errore.kind(), "arruolamento non registrato dall'Hub");
            rifiuto(EnrollmentRefusalReason::HubFault)
        }
    }
}

/// Una riga della coda dell'ufficio come viaggia.
///
/// Porta i fatti e il **perche' sta qui**, mai il testo del contenuto.
fn riga_sul_filo(
    riga: &QueueItem,
    assigned_to: Option<String>,
    assignment_version: u64,
    now: Timestamp,
) -> WireWorkItem {
    WireWorkItem {
        content_id: riga.content_id.get(),
        source_name: riga.source_name.clone(),
        level: riga.level,
        raised_at: riga.raised_at.as_millis(),
        state: riga.state.map(|stato| String::from(stato.as_str())),
        why_here: riga.why_here(now),
        assigned_to,
        assignment_version,
    }
}

/// Un elemento della coda come viaggia: **metadati, mai testo**.
fn elemento_sul_filo(elemento: &ReviewItem) -> WireReviewItem {
    WireReviewItem {
        content_id: elemento.content_id.get(),
        source: String::from(elemento.source.as_str()),
        level: elemento.level,
        raised_at: elemento.raised_at.as_millis(),
        state: elemento.state.map(|stato| String::from(stato.as_str())),
        version: elemento.version,
    }
}

/// Il contenuto consegnato per la revisione, come viaggia.
fn contenuto_sul_filo(contenuto: &ReviewContent) -> WireReviewContent {
    WireReviewContent {
        content_id: contenuto.content_id.get(),
        source: String::from(contenuto.source.as_str()),
        source_name: String::from(contenuto.source_name.as_str()),
        published_at: contenuto.published_at.as_millis(),
        body: contenuto.body.clone(),
        level: contenuto.level,
        version: contenuto.version,
    }
}

/// L'esito di una revisione, come viaggia.
fn verdetto_sul_filo(verdetto: &CommandVerdict, versione: u64) -> HubResponse {
    let (parola, dettaglio) = match verdetto {
        CommandVerdict::Applied(CommandOutcome::Done { detail }) => (
            "applicata",
            detail.as_ref().map_or_else(
                || String::from("registrata"),
                |dettaglio| String::from(dettaglio.as_str()),
            ),
        ),
        CommandVerdict::Applied(CommandOutcome::Refused { reason }) => {
            ("rifiutata", String::from(reason.as_str()))
        }
        CommandVerdict::Replay(_) => (
            "ripetuta",
            String::from("questa decisione era già stata registrata: nulla è stato rieseguito"),
        ),
        CommandVerdict::Conflict(conflitto) => ("conflitto", conflitto.operator_message()),
    };
    HubResponse::ReviewOutcome {
        verdict: String::from(parola),
        detail: dettaglio,
        current_version: versione,
    }
}

/// Un evento come viaggia.
fn sul_filo(evento: &HubEvent) -> WireEvent {
    WireEvent {
        sequence: evento.sequence,
        kind: String::from(evento.kind.as_str()),
        subject: String::from(evento.subject.as_str()),
        detail: evento
            .detail
            .as_ref()
            .map(|detail| String::from(detail.as_str())),
        recorded_at: evento.recorded_at.as_millis(),
    }
}

/// Porta un errore di sicurezza in un errore di servizio, senza dettagli del
/// sistema.
/// L'indirizzo di ascolto non è dell'ufficio.
fn fuori_dalle_reti() -> ServiceError {
    ServiceError::HubServer {
        reason: String::from(
            "l'Hub ascolta soltanto su un indirizzo delle reti dell'ufficio, mai su uno che \
             Internet raggiunge. Se l'ufficio usa questo indirizzo al proprio interno, va \
             dichiarato fra le reti dell'ufficio",
        ),
    }
}

fn map_security_error(_errore: SecurityError) -> ServiceError {
    ServiceError::HubServer {
        reason: String::from(
            "la configurazione della modalità Hub non è leggibile con il profilo corrente",
        ),
    }
}

#[cfg(test)]
mod tests {
    use lisi_hub_transport::protocol::events::{
        EVENTS_MAX_FRAME_BYTES, HubResponse, MAX_NOTE_CHARS, MAX_SHARED_NOTES_PAGE, WireSharedNote,
    };

    /// Questo file, letto a tempo di compilazione.
    const QUESTO_FILE: &str = include_str!("hub_server.rs");

    /// **Cinquanta note lunghe di caratteri larghi entrano nel frame,
    /// accorciate** (FINAL-REVIEW-01, FR-018).
    #[test]
    fn una_pagina_troppo_grande_si_accorcia_e_non_chiude() {
        let nota = |id: i64| WireSharedNote {
            id,
            kind: String::from("contenuto"),
            target_id: 1,
            body: "\u{1F600}".repeat(MAX_NOTE_CHARS),
            author: String::from("mrossi"),
            written_at: 1_700_000_000_000,
            withdrawn_by: None,
            withdrawn_at: 0,
        };
        let pagina = HubResponse::SharedNotesPage {
            notes: (1..=i64::try_from(MAX_SHARED_NOTES_PAGE).unwrap_or(50))
                .map(nota)
                .collect(),
        };
        let Ok(prima) = serde_json::to_vec(&pagina) else {
            panic!("la pagina si serializza");
        };
        assert!(
            prima.len() > usize::try_from(EVENTS_MAX_FRAME_BYTES).unwrap_or(usize::MAX),
            "la prova deve partire da una pagina oltre il tetto"
        );

        let accorciata = super::entro_la_misura(pagina);
        let Ok(dopo) = serde_json::to_vec(&accorciata) else {
            panic!("la pagina accorciata si serializza");
        };
        assert!(dopo.len() <= usize::try_from(EVENTS_MAX_FRAME_BYTES).unwrap_or(0));
        let HubResponse::SharedNotesPage { notes } = accorciata else {
            panic!("resta una pagina di note, non un rifiuto");
        };
        assert!(!notes.is_empty() && notes.len() < MAX_SHARED_NOTES_PAGE);
        assert_eq!(notes[0].id, 1, "si accorcia dalla coda, la testa resta");
    }

    /// **La copertura che arriva alla postazione è quella dell'Hub**, tratto per
    /// tratto e fonte per fonte (HUB-COVERAGE-01, ADR-0199, decisione 2); un
    /// monitoraggio che l'Hub non ha è un rifiuto detto.
    #[test]
    fn la_copertura_dell_ufficio_arriva_uguale_a_quella_dell_hub() {
        use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
        use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let (Ok(attore), Ok(identificativo), Ok(nome), Ok(etichetta)) = (
            Actor::try_new("operatore.prova"),
            SourceIdentifier::try_new("canale_sintetico"),
            DisplayName::try_new("Canale sintetico"),
            DisplayName::try_new("Monitoraggio sintetico"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let ora =
            |minuti: i64| lisi_core::Timestamp::from_millis(1_800_000_000_000 + minuti * 60_000);
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: attore.clone(),
                active: true,
            },
            ora(0),
        ) else {
            panic!("la fonte deve registrarsi");
        };
        let Ok(sessione) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: attore,
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![fonte],
            },
            ora(1),
        ) else {
            panic!("la sessione deve crearsi");
        };
        let Ok(()) = database.update_session_state(
            sessione,
            lisi_core::model::SessionState::Running,
            ora(1),
        ) else {
            panic!("la sessione deve avviarsi");
        };

        let Ok(sull_hub) = crate::coverage::for_monitoring(&database, sessione, ora(30)) else {
            panic!("la copertura deve comporsi sull'Hub");
        };
        let risposta = super::copertura_sul_filo(&database, sessione, ora(30));
        let Ok(Some(crate::hub_client::SharedCoverageAnswer::Taken(arrivata))) =
            crate::hub_client::copertura_dal_filo(risposta)
        else {
            panic!("la copertura deve arrivare intera");
        };
        assert_eq!(arrivata.session_id, sessione);
        assert_eq!(arrivata.taken_at, ora(30));
        assert_eq!(arrivata.overall, sull_hub.overall);
        assert!(!arrivata.overall.intervals().is_empty());
        let fonti: Vec<_> = sull_hub
            .sources
            .iter()
            .map(|(_, nome, copertura)| (nome.clone(), copertura.clone()))
            .collect();
        assert_eq!(arrivata.sources, fonti);

        let assente = super::copertura_sul_filo(
            &database,
            lisi_core::SessionId::new(sessione.get() + 1),
            ora(30),
        );
        assert!(matches!(
            crate::hub_client::copertura_dal_filo(assente),
            Ok(Some(crate::hub_client::SharedCoverageAnswer::Refused(_)))
        ));
    }

    /// L'Hub manda ogni risposta attraverso la misura.
    #[test]
    fn ogni_risposta_passa_dalla_misura() {
        assert!(
            QUESTO_FILE.contains("send_response(canale, &entro_la_misura(risposta))"),
            "una risposta oltre il tetto chiuderebbe la connessione"
        );
    }

    /// **Ciò che l'Hub registra porta l'istante in cui accade, non quello in
    /// cui l'Hub è stato acceso** (FINAL-REVIEW-01, FR-005).
    ///
    /// Il servizio delle connessioni riceve l'istante dell'accensione e lo
    /// porta con sé per tutta la vita dell'Hub. Fino al 2026-10-03 cinque
    /// chiamate lo usavano così com'era: una decisione presa alle 16:00 su un
    /// Hub acceso alle 08:00 portava 08:00 nella revisione, nell'evento e nel
    /// registro. Dentro il servizio delle connessioni quell'istante può solo
    /// essere inoltrato al passo successivo, o passare da `adesso_o`.
    #[test]
    fn l_istante_dell_accensione_non_si_usa_nudo() {
        let Some((_, dopo)) = QUESTO_FILE.split_once("fn servi_una_connessione(") else {
            panic!("il servizio delle connessioni deve esistere");
        };
        let Some((servizio, _)) = dopo.split_once("/// Registra una decisione ricevuta") else {
            panic!("il servizio delle connessioni deve finire dove la guardia lo cerca");
        };
        let mut inoltri = 0_usize;
        let mut nudi = Vec::new();
        for riga in servizio.lines() {
            let riga = riga.trim();
            if riga.starts_with("//") || !riga.contains("now") {
                continue;
            }
            if riga.contains("adesso_o(now)") || riga.contains("now: Timestamp") {
                continue;
            }
            if riga == "now," {
                inoltri += 1;
                continue;
            }
            nudi.push(riga.to_owned());
        }
        assert!(
            nudi.is_empty(),
            "l'istante dell'accensione è usato nudo: {nudi:#?}"
        );
        assert_eq!(
            inoltri, 1,
            "l'istante dell'accensione si inoltra una volta sola, al servizio delle richieste"
        );
    }

    /// **L'Hub non si configura su un indirizzo che Internet raggiunge**, e
    /// su uno dell'ufficio sì (HUB-SITES-01, ADR-0198, decisione 3).
    #[test]
    fn un_indirizzo_che_internet_raggiunge_non_si_configura() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let archivio = cartella.path().join("archivio.sqlite");
        if crate::Database::open(&archivio).is_err() {
            panic!("archivio di prova");
        }
        let servizio = super::HubServerService::new(cartella.path().to_path_buf(), archivio);
        let Ok(operatore) = lisi_core::model::identity::OperatorId::try_new("amministratore")
        else {
            panic!("operatore di prova");
        };
        let adesso = lisi_core::Timestamp::from_millis(1_800_000_000_000);
        let (Ok(pubblico), Ok(ufficio)) = (
            lisi_core::model::hub_client::HubAddress::parse("8.8.8.8:8443"),
            lisi_core::model::hub_client::HubAddress::parse("10.20.0.5:8443"),
        ) else {
            panic!("indirizzi di prova");
        };
        assert!(servizio.configure(&pubblico, &operatore, adesso).is_err());
        assert_eq!(
            servizio.address().ok(),
            Some(None),
            "niente è stato conservato"
        );
        assert!(servizio.configure(&ufficio, &operatore, adesso).is_ok());
        assert_eq!(servizio.address().ok(), Some(Some(ufficio)));
    }
}

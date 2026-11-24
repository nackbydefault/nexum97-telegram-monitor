//! Il lato Hub dell'accesso: chi entra, con quale ruolo, e che cosa gli si
//! consente (HUB-AUTHZ-01, ADR-0085).
//!
//! # Dove si aggancia
//!
//! Il protocollo (HUB-PROTO-01) chiede a una funzione di decidere, dati
//! l'identificativo del dispositivo e l'impronta del gettone presentato. Quella
//! decisione è [`HubAccessService::authenticate`]. Questo modulo **non conosce
//! il trasporto** e non ne dipende: riceve un'impronta e un'etichetta
//! d'indirizzo, restituisce un esito.
//!
//! # Il ruolo non si può inventare
//!
//! [`AuthenticatedDevice`] **non ha un costruttore pubblico**: lo produce solo
//! un'autenticazione riuscita. [`HubAccessService::authorize`] lo richiede, quindi
//! non esiste un modo di chiedere un'autorizzazione per un dispositivo che non è
//! passato di qui — una funzione che non si può chiamare senza la cosa giusta
//! non si può chiamare con quella sbagliata.
//!
//! # Che cosa va nell'audit
//!
//! - ogni **ingresso** riuscito, attribuito all'autorità `hub.accesso`: chi si è
//!   collegato all'Hub è un fatto che chi amministra deve poter ricostruire;
//! - ogni tentativo di un dispositivo **ritirato** (ADR-0082 decisione 4);
//! - i tentativi **non riconosciuti**, uno per uno **fino al freno**; poi una
//!   riga che dice che il freno è scattato, e silenzio fino a fine finestra;
//! - ogni **cambio di ruolo**, attribuito alla **persona** che lo decide;
//! - ogni **rifiuto di autorizzazione**.
//!
//! Mai il gettone né la sua impronta.

use lisi_core::Sha256Digest;
use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::hub_access::{
    AccessBrake, BrakeVerdict, DeviceAccess, HubAction, HubRole, decide_device_access,
};
use lisi_core::model::hub_event::{HubEventKind, NewHubEvent};
use lisi_core::model::identity::{DeviceId, OperatorId};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::text::{HubEventDetail, HubEventSubject};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_events::publish_event;

/// Entità dell'audit per le voci di questo modulo.
const AUDIT_ENTITY: &str = "accesso_hub";
/// Soggetto degli atti decisi dalla regola e non da una persona.
const AUDIT_AUTHORITY: &str = "hub.accesso";

const AUDIT_ENTERED: &str = "dispositivo_collegato";
const AUDIT_REVOKED: &str = "dispositivo_ritirato_respinto";
const AUDIT_NOT_RECOGNIZED: &str = "dispositivo_non_riconosciuto";
const AUDIT_BRAKE: &str = "freno_accesso_attivato";
const AUDIT_ROLE: &str = "ruolo_dispositivo_cambiato";
const AUDIT_FORBIDDEN: &str = "azione_rifiutata_dall_hub";

/// Un dispositivo che l'Hub ha appena riconosciuto.
///
/// Nessun costruttore pubblico: vedere la nota del modulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDevice {
    device: DeviceId,
    role: HubRole,
}

impl AuthenticatedDevice {
    /// Il dispositivo.
    #[must_use]
    pub const fn device(&self) -> &DeviceId {
        &self.device
    }

    /// Il ruolo con cui è entrato.
    #[must_use]
    pub const fn role(&self) -> HubRole {
        self.role
    }
}

/// L'esito di un'autenticazione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessOutcome {
    /// Entra.
    Entered(AuthenticatedDevice),
    /// Sconosciuto o gettone sbagliato.
    NotRecognized,
    /// Ritirato.
    Revoked,
}

/// Un freno condiviso fra le connessioni di un Hub acceso (FINAL-REVIEW-01,
/// FR-019).
///
/// Fino al 2026-10-03 ogni connessione ne costruiva uno nuovo, con chiave
/// l'indirizzo **e la porta** del chiamante: un tentativo per connessione, e il
/// freno non scattava mai. Ora l'Hub acceso ne tiene uno per i dispositivi e uno
/// per le persone, e la chiave è l'indirizzo IP. Il lucchetto si tiene solo per
/// contare, mai durante una scrittura.
pub type SharedBrake = std::sync::Arc<std::sync::Mutex<AccessBrake>>;

/// Conta un fallimento sul freno condiviso, anche se un'altra connessione si è
/// fermata a metà mentre lo teneva: il conteggio resta valido.
pub(crate) fn frena(brake: &SharedBrake, address: &str, now: Timestamp) -> BrakeVerdict {
    brake
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .record_failure(address, now)
}

/// L'autorità che decide l'accesso all'Hub.
#[derive(Debug)]
pub struct HubAccessService {
    database: Database,
    brake: SharedBrake,
}

impl HubAccessService {
    /// Costruisce l'autorità sull'archivio indicato.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self {
            database,
            brake: SharedBrake::default(),
        }
    }

    /// Costruisce l'autorità con il freno dell'Hub acceso, condiviso fra le
    /// connessioni (FR-019).
    #[must_use]
    pub const fn with_brake(database: Database, brake: SharedBrake) -> Self {
        Self { database, brake }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce l'archivio, per passarlo a un'altra autorità dell'Hub.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Quanti tentativi falliti non sono stati registrati uno per uno.
    #[must_use]
    pub fn suppressed_attempts(&self) -> u64 {
        self.brake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .suppressed()
    }

    /// Decide se un dispositivo entra.
    ///
    /// `peer` è l'etichetta dell'indirizzo da cui arriva la connessione, così
    /// come il trasporto la rende: serve al freno e all'audit, **non è
    /// un'identità**.
    ///
    /// # Errori
    ///
    /// Un errore se la lettura o l'audit non riescono. Un rifiuto **non è un
    /// errore**: è un esito.
    pub fn authenticate(
        &mut self,
        device: &DeviceId,
        presented: &Sha256Digest,
        peer: &str,
        now: Timestamp,
    ) -> ServiceResult<AccessOutcome> {
        let stored = self.database.device_credential(device.as_str())?;

        match decide_device_access(stored.as_ref(), presented) {
            DeviceAccess::Accepted(role) => {
                self.registra_autorita(
                    AUDIT_ENTERED,
                    &format!("dispositivo {device} da {peer}, ruolo {}", role.as_str()),
                    now,
                )?;
                Ok(AccessOutcome::Entered(AuthenticatedDevice {
                    device: device.clone(),
                    role,
                }))
            }
            DeviceAccess::Revoked => {
                self.registra_autorita(
                    AUDIT_REVOKED,
                    &format!("dispositivo {device} da {peer}"),
                    now,
                )?;
                Ok(AccessOutcome::Revoked)
            }
            DeviceAccess::NotRecognized => {
                match frena(&self.brake, peer, now) {
                    BrakeVerdict::Record => self.registra_autorita(
                        AUDIT_NOT_RECOGNIZED,
                        &format!("dispositivo dichiarato {device} da {peer}"),
                        now,
                    )?,
                    BrakeVerdict::RecordAndEngage => {
                        self.registra_autorita(
                            AUDIT_NOT_RECOGNIZED,
                            &format!("dispositivo dichiarato {device} da {peer}"),
                            now,
                        )?;
                        self.registra_autorita(
                            AUDIT_BRAKE,
                            &format!(
                                "da {peer}: troppi tentativi non riconosciuti; fino a fine \
                                 finestra non si registrano uno per uno"
                            ),
                            now,
                        )?;
                    }
                    BrakeVerdict::Suppress => {}
                }
                Ok(AccessOutcome::NotRecognized)
            }
        }
    }

    /// Autorizza un'azione, o la rifiuta dicendo perché.
    ///
    /// # Errori
    ///
    /// [`ServiceError::HubForbidden`] se il ruolo non la consente; un errore
    /// d'archivio se l'audit del rifiuto non si scrive.
    pub fn authorize(
        &self,
        device: &AuthenticatedDevice,
        action: HubAction,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if device.role.permits(action) {
            return Ok(());
        }
        self.registra_autorita(
            AUDIT_FORBIDDEN,
            &format!(
                "dispositivo {} con ruolo {}: {}",
                device.device,
                device.role.as_str(),
                action.as_str()
            ),
            now,
        )?;
        Err(ServiceError::HubForbidden {
            reason: format!(
                "Questo dispositivo è collegato all'Hub con il ruolo {}: l'azione è \
                 riservata a chi amministra, perché {}.",
                device.role.label(),
                action.reason()
            ),
        })
    }

    /// Assegna un ruolo a un dispositivo. **È un atto di una persona**, e
    /// l'audit porta il suo identificativo.
    ///
    /// Chi chiama deve aver verificato che quella persona amministra l'Hub: la
    /// modalità della postazione Hub (ADR-0015) è il confine, come per ogni
    /// azione riservata locale.
    ///
    /// # Errori
    ///
    /// [`ServiceError::DeviceIdentity`] se l'Hub non conosce il dispositivo o
    /// se è ritirato; un errore d'archivio se la scrittura non riesce.
    pub fn assign_role(
        &mut self,
        device: &DeviceId,
        role: HubRole,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<bool> {
        let Some(credenziale) = self.database.device_credential(device.as_str())? else {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from("questo Hub non conosce il dispositivo indicato"),
            });
        };
        if credenziale.revoked {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from(
                    "il dispositivo è stato ritirato: un dispositivo ritirato non riceve un ruolo",
                ),
            });
        }
        let cambiato = self
            .database
            .set_enrolled_device_role(device.as_str(), role)?;
        if cambiato {
            // Il cambio di ruolo entra nella sequenza autorevole (ADR-0086):
            // i client devono poterlo ricostruire come ogni altro fatto.
            let evento = NewHubEvent {
                kind: HubEventKind::DeviceRoleChanged,
                subject: HubEventSubject::try_new(device.as_str())?,
                detail: Some(HubEventDetail::try_new(role.as_str())?),
            };
            publish_event(&mut self.database, &evento, now)?;
            self.scrivi(
                operator.audit_actor()?,
                AUDIT_ROLE,
                &format!(
                    "dispositivo {device}: {} -> {}",
                    credenziale.role.as_str(),
                    role.as_str()
                ),
                now,
            )?;
        }
        Ok(cambiato)
    }

    fn registra_autorita(
        &self,
        azione: &str,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.scrivi(Actor::try_new(AUDIT_AUTHORITY)?, azione, dettaglio, now)
    }

    fn scrivi(
        &self,
        actor: Actor,
        azione: &str,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let entry = NewAuditEntry {
            actor,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(dettaglio)?),
            recorded_at: now,
        };
        self.database.append_audit(&entry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Sha256Digest;
    use lisi_core::Timestamp;
    use lisi_core::model::enrollment::{
        ENROLLMENT_CODE_BYTES, EnrollmentCode, EnrollmentRequest, EnrollmentSalt,
    };
    use lisi_core::model::hub_access::{ACCESS_BRAKE_THRESHOLD, HubAction, HubRole};
    use lisi_core::model::identity::{
        DEVICE_ID_BYTES, DEVICE_SECRET_BYTES, DeviceId, DeviceSecret, OperatorId,
    };
    use lisi_core::role::RestrictedAction;
    use lisi_core::text::{DisplayName, Note};

    use super::{AccessOutcome, HubAccessService};
    use crate::error::ServiceError;
    use crate::hub_enrollment::{EnrollmentOutcome, HubEnrollmentService};

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_000_000_000)
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(valore) = DisplayName::try_new(testo) else {
            panic!("nome di prova");
        };
        valore
    }

    fn operatore() -> OperatorId {
        let Ok(id) = OperatorId::try_new("amministratore.hub") else {
            panic!("operatore di prova");
        };
        id
    }

    /// Un Hub con un dispositivo arruolato davvero, attraverso il servizio di
    /// arruolamento, e l'impronta del suo gettone.
    fn hub_con_un_dispositivo() -> (HubAccessService, DeviceId, Sha256Digest) {
        use lisi_core::model::enrollment::DeviceToken;

        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio di prova");
        };
        let mut arruolamento = HubEnrollmentService::new(database, nome("Hub di prova"));
        let Ok(emesso) = arruolamento.issue_code(&operatore(), adesso()) else {
            panic!("codice");
        };
        let _ = ENROLLMENT_CODE_BYTES;
        let codice: EnrollmentCode = emesso.code.clone();
        let salt = EnrollmentSalt::from_random_bytes(&[4; 16]);
        let token = DeviceToken::derive(
            &salt,
            &DeviceSecret::from_random_bytes([4; DEVICE_SECRET_BYTES]),
        );
        let dispositivo = DeviceId::from_random_bytes(&[4; DEVICE_ID_BYTES]);
        let richiesta = EnrollmentRequest {
            device_id: dispositivo.clone(),
            label: nome("Postazione 4"),
            code: codice,
            salt,
            verifier: token.verifier(),
        };
        let Ok(EnrollmentOutcome::Admitted(_)) = arruolamento.admit(&richiesta, adesso()) else {
            panic!("il dispositivo di prova deve entrare");
        };
        let verificatore = token.verifier();
        (
            HubAccessService::new(arruolamento.into_database()),
            dispositivo,
            verificatore,
        )
    }

    fn azioni(servizio: &HubAccessService) -> Vec<String> {
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("audit");
        };
        voci.iter()
            .filter(|voce| voce.entity.as_str() == "accesso_hub")
            .map(|voce| voce.action.as_str().to_owned())
            .collect()
    }

    #[test]
    fn an_enrolled_device_enters_as_operator_and_the_entry_is_audited() {
        let (mut servizio, dispositivo, impronta) = hub_con_un_dispositivo();
        let Ok(AccessOutcome::Entered(entrato)) =
            servizio.authenticate(&dispositivo, &impronta, "192.0.2.4", adesso())
        else {
            panic!("il dispositivo arruolato deve entrare");
        };
        assert_eq!(
            entrato.role(),
            HubRole::Operator,
            "il privilegio si concede, non si trova"
        );
        assert_eq!(azioni(&servizio), vec!["dispositivo_collegato"]);
    }

    #[test]
    fn a_wrong_token_and_an_unknown_device_get_the_same_outcome() {
        let (mut servizio, dispositivo, _) = hub_con_un_dispositivo();
        let sbagliata = Sha256Digest::of_bytes(b"non e' il gettone");
        assert_eq!(
            servizio
                .authenticate(&dispositivo, &sbagliata, "192.0.2.9", adesso())
                .ok(),
            Some(AccessOutcome::NotRecognized)
        );
        let sconosciuto = DeviceId::from_random_bytes(&[9; DEVICE_ID_BYTES]);
        assert_eq!(
            servizio
                .authenticate(&sconosciuto, &sbagliata, "192.0.2.9", adesso())
                .ok(),
            Some(AccessOutcome::NotRecognized)
        );
        // L'audit non porta mai l'impronta presentata.
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("audit");
        };
        for voce in voci {
            let dettaglio = voce
                .detail
                .map(|d| d.as_str().to_owned())
                .unwrap_or_default();
            assert!(!dettaglio.contains(sbagliata.as_str()));
        }
    }

    #[test]
    fn a_revoked_device_is_refused_as_such_only_with_its_token() {
        let (mut servizio, dispositivo, impronta) = hub_con_un_dispositivo();
        let Ok(nota) = Note::try_new("postazione dismessa") else {
            panic!("nota");
        };
        assert!(matches!(
            servizio
                .database()
                .revoke_enrolled_device(dispositivo.as_str(), &nota, adesso()),
            Ok(true)
        ));

        assert_eq!(
            servizio
                .authenticate(&dispositivo, &impronta, "192.0.2.4", adesso())
                .ok(),
            Some(AccessOutcome::Revoked)
        );
        assert_eq!(
            servizio
                .authenticate(
                    &dispositivo,
                    &Sha256Digest::of_bytes(b"altro"),
                    "192.0.2.4",
                    adesso()
                )
                .ok(),
            Some(AccessOutcome::NotRecognized)
        );
        assert!(azioni(&servizio).contains(&String::from("dispositivo_ritirato_respinto")));
        // E un dispositivo ritirato non riceve un ruolo.
        assert!(matches!(
            servizio.assign_role(&dispositivo, HubRole::Administrator, &operatore(), adesso()),
            Err(ServiceError::DeviceIdentity { .. })
        ));
    }

    #[test]
    fn the_brake_quiets_the_audit_but_never_stops_the_right_token() {
        let (mut servizio, dispositivo, impronta) = hub_con_un_dispositivo();
        let sbagliata = Sha256Digest::of_bytes(b"tentativo");
        for _ in 0..(ACCESS_BRAKE_THRESHOLD + 20) {
            let _ = servizio.authenticate(&dispositivo, &sbagliata, "192.0.2.66", adesso());
        }
        let registrate = azioni(&servizio);
        assert_eq!(
            registrate
                .iter()
                .filter(|a| *a == "dispositivo_non_riconosciuto")
                .count(),
            usize::try_from(ACCESS_BRAKE_THRESHOLD).unwrap_or(0)
        );
        assert_eq!(
            registrate
                .iter()
                .filter(|a| *a == "freno_accesso_attivato")
                .count(),
            1
        );
        assert_eq!(servizio.suppressed_attempts(), 20);

        // Dallo stesso indirizzo frenato, il gettone giusto entra.
        assert!(matches!(
            servizio.authenticate(&dispositivo, &impronta, "192.0.2.66", adesso()),
            Ok(AccessOutcome::Entered(_))
        ));
    }

    #[test]
    fn authorization_follows_the_role_and_a_refusal_says_why() {
        let (mut servizio, dispositivo, impronta) = hub_con_un_dispositivo();
        let Ok(AccessOutcome::Entered(operatore_entrato)) =
            servizio.authenticate(&dispositivo, &impronta, "192.0.2.4", adesso())
        else {
            panic!("ingresso");
        };
        let azione = HubAction::Restricted(RestrictedAction::ConfigureSources);
        let Err(ServiceError::HubForbidden { reason }) =
            servizio.authorize(&operatore_entrato, azione, adesso())
        else {
            panic!("un operatore non configura le fonti dell'Hub");
        };
        assert!(reason.contains("Operatore"));
        assert!(reason.contains(RestrictedAction::ConfigureSources.reason()));
        assert!(azioni(&servizio).contains(&String::from("azione_rifiutata_dall_hub")));

        // Chi amministra concede il ruolo; il nuovo ruolo vale dalla connessione successiva.
        assert!(matches!(
            servizio.assign_role(&dispositivo, HubRole::Administrator, &operatore(), adesso()),
            Ok(true)
        ));
        assert!(matches!(
            servizio.assign_role(&dispositivo, HubRole::Administrator, &operatore(), adesso()),
            Ok(false)
        ));
        assert!(
            servizio
                .authorize(&operatore_entrato, azione, adesso())
                .is_err()
        );
        let Ok(AccessOutcome::Entered(amministratore)) =
            servizio.authenticate(&dispositivo, &impronta, "192.0.2.4", adesso())
        else {
            panic!("ingresso");
        };
        assert!(
            servizio
                .authorize(&amministratore, azione, adesso())
                .is_ok()
        );
        assert!(
            servizio
                .authorize(&amministratore, HubAction::AdministerDevices, adesso())
                .is_ok()
        );
    }

    #[test]
    fn the_acts_of_the_hub_enter_the_authoritative_sequence() {
        let (mut servizio, dispositivo, _) = hub_con_un_dispositivo();
        // L'ammissione ha gia' scritto il primo evento.
        assert!(matches!(
            servizio.assign_role(&dispositivo, HubRole::Administrator, &operatore(), adesso()),
            Ok(true)
        ));

        let Ok(eventi) = servizio.database().hub_events_after(0, 10) else {
            panic!("lettura della sequenza");
        };
        let fatti: Vec<(u64, &str)> = eventi
            .iter()
            .map(|evento| (evento.sequence, evento.kind.as_str()))
            .collect();
        assert_eq!(
            fatti,
            vec![
                (1, "dispositivo_ammesso"),
                (2, "ruolo_dispositivo_cambiato")
            ],
            "ogni atto dell'Hub ha un numero, e i numeri non saltano"
        );
        assert_eq!(
            eventi[1]
                .detail
                .as_ref()
                .map(lisi_core::text::HubEventDetail::as_str),
            Some("amministratore")
        );
        // Un cambio che non cambia nulla non scrive un evento.
        assert!(matches!(
            servizio.assign_role(&dispositivo, HubRole::Administrator, &operatore(), adesso()),
            Ok(false)
        ));
        assert_eq!(servizio.database().latest_hub_sequence().ok(), Some(2));
    }

    #[test]
    fn an_unknown_device_cannot_receive_a_role() {
        let (mut servizio, _, _) = hub_con_un_dispositivo();
        let sconosciuto = DeviceId::from_random_bytes(&[8; DEVICE_ID_BYTES]);
        assert!(matches!(
            servizio.assign_role(&sconosciuto, HubRole::Administrator, &operatore(), adesso()),
            Err(ServiceError::DeviceIdentity { .. })
        ));
    }
}

#[cfg(test)]
mod shared_brake_tests {
    use lisi_core::Sha256Digest;
    use lisi_core::Timestamp;
    use lisi_core::model::hub_access::ACCESS_BRAKE_THRESHOLD;
    use lisi_core::model::identity::{DEVICE_ID_BYTES, DeviceId};

    use super::{HubAccessService, SharedBrake};

    /// **Il freno vale per l'Hub acceso, non per la connessione**
    /// (FINAL-REVIEW-01, FR-019).
    ///
    /// Ogni tentativo arriva su una connessione nuova, con un servizio nuovo:
    /// è ciò che fa il server. Fino al 2026-10-03 ognuno aveva il suo freno, e
    /// trenta tentativi scrivevano trenta righe.
    #[test]
    fn the_brake_holds_across_connections() {
        let freno = SharedBrake::default();
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio di prova");
        };
        let mut primo = HubAccessService::with_brake(database, std::sync::Arc::clone(&freno));
        let sbagliata = Sha256Digest::of_bytes(b"non e' il gettone");
        let sconosciuto = DeviceId::from_random_bytes(&[9; DEVICE_ID_BYTES]);
        let adesso = Timestamp::from_millis(1_758_000_000_000);

        for tentativo in 0..(ACCESS_BRAKE_THRESHOLD + 20) {
            // Una connessione nuova per ogni tentativo, sullo stesso archivio.
            let database = primo.into_database();
            let mut connessione =
                HubAccessService::with_brake(database, std::sync::Arc::clone(&freno));
            let _ = connessione.authenticate(
                &sconosciuto,
                &sbagliata,
                "192.0.2.77",
                adesso.plus_seconds(i64::from(tentativo)),
            );
            primo = connessione;
        }

        let Ok(voci) = primo.database().audit_entries() else {
            panic!("audit");
        };
        let righe = voci
            .iter()
            .filter(|voce| voce.entity.as_str() == "accesso_hub")
            .count();
        assert_eq!(
            righe,
            usize::try_from(ACCESS_BRAKE_THRESHOLD).unwrap_or(0) + 1,
            "dieci tentativi registrati e la riga del freno, poi silenzio"
        );
    }

    /// Il server costruisce i freni UNA volta per Hub acceso, e la chiave è
    /// l'indirizzo senza la porta.
    #[test]
    fn the_server_builds_the_brakes_once_and_keys_them_on_the_address() {
        const SERVER: &str = include_str!("hub_server.rs");
        assert!(
            SERVER.contains("let freni = Freni::default();"),
            "i freni si costruiscono all'accensione"
        );
        assert!(
            SERVER.contains("HubAccessService::with_brake(")
                && SERVER.contains("HubPeopleService::with_brake("),
            "ogni connessione usa i freni dell'Hub acceso"
        );
        assert!(
            !SERVER.contains("HubAccessService::new(database)")
                && !SERVER.contains("HubPeopleService::new(per_le_persone)"),
            "nessuna connessione si costruisce un freno suo"
        );
        assert!(
            SERVER.contains("canale.peer_address().ip().to_string()"),
            "la chiave del freno è l'indirizzo, non l'indirizzo con la porta"
        );
    }
}

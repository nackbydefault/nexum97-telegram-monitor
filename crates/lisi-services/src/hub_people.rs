//! Le persone dell'ufficio, dal lato dell'Hub (TEAM-ASSIGN-01, ADR-0097).
//!
//! # L'identità non si dichiara: si dimostra
//!
//! [`AuthenticatedOperator`] **non ha un costruttore pubblico**: lo produce
//! solo [`HubPeopleService::sign_in`] quando la frase presentata supera la
//! verifica. È la stessa forma di [`crate::hub_access::AuthenticatedDevice`] e
//! di [`crate::acquisition_authority::AcquisitionAuthority`] — una funzione che
//! non si può chiamare senza la cosa giusta non si può chiamare con quella
//! sbagliata.
//!
//! # Che cosa va nell'audit, e che cosa mai
//!
//! Va: la creazione di una persona, ogni ingresso riuscito, ogni tentativo
//! fallito **fino al freno**, la sospensione, il rimettere la frase.
//!
//! Mai: **la frase**. Né in chiaro, né troncata, né «la frase cominciava per».
//! Un errore che la citasse la scriverebbe in ogni posto in cui l'errore
//! finisce.
//!
//! # Il rifiuto non distingue
//!
//! Una persona che non esiste e una frase sbagliata ricevono la **stessa**
//! risposta, per la stessa ragione per cui l'Hub non distingue un dispositivo
//! sconosciuto da un gettone sbagliato (ADR-0085): distinguere direbbe a chi
//! prova quali identificativi esistono.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::hub_access::{BrakeVerdict, HubAction, HubRole};
use lisi_core::model::hub_person::{
    Passphrase, PassphraseVerifier, Person, PersonId, PersonState, attore_della_persona,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, DisplayName};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_access::AuthenticatedDevice;

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "persone_ufficio";
/// Soggetto degli atti decisi dalla regola e non da una persona.
const AUDIT_AUTHORITY: &str = "hub.persone";

const AUDIT_CREATED: &str = "persona_creata";
const AUDIT_SIGNED_IN: &str = "persona_entrata";
const AUDIT_REFUSED: &str = "persona_non_riconosciuta";
const AUDIT_SUSPENDED_ATTEMPT: &str = "persona_sospesa_respinta";
const AUDIT_BRAKE: &str = "freno_persone_attivato";
const AUDIT_STATE: &str = "stato_persona_cambiato";
const AUDIT_PASSPHRASE: &str = "frase_rimessa";

/// Una persona che ha appena dimostrato di essere sé stessa.
///
/// Nessun costruttore pubblico: vedere la nota del modulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedOperator {
    person: PersonId,
    role: HubRole,
    /// Campo privato senza accessori: rende il tipo non costruibile
    /// **nemmeno dentro questa crate** con una struttura letterale scritta
    /// altrove.
    _privato: (),
}

impl AuthenticatedOperator {
    /// Chi è.
    #[must_use]
    pub const fn person(&self) -> &PersonId {
        &self.person
    }

    /// Che cosa le è consentito.
    #[must_use]
    pub const fn role(&self) -> HubRole {
        self.role
    }

    /// Come compare negli atti.
    #[must_use]
    pub fn actor(&self) -> String {
        attore_della_persona(&self.person)
    }

    /// Se questa persona può compiere l'azione.
    #[must_use]
    pub const fn permits(&self, action: HubAction) -> bool {
        self.role.permits(action)
    }
}

/// Che cosa è successo a un tentativo di entrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInOutcome {
    /// Entra.
    Entered(AuthenticatedOperator),
    /// Persona sconosciuta o frase sbagliata: **non si distinguono**.
    NotRecognized,
    /// La persona esiste ma è sospesa.
    ///
    /// Si distingue dal rifiuto precedente perché è uno stato che chi
    /// amministra ha deciso, e chi lo subisce deve sapere a chi rivolgersi.
    Suspended,
}

impl SignInOutcome {
    /// La frase per chi ha provato a entrare.
    #[must_use]
    pub const fn operator_message(&self) -> &'static str {
        match self {
            Self::Entered(_) => "Accesso riuscito.",
            Self::NotRecognized => {
                "Identificativo o frase non riconosciuti. Riprovare; se il problema resta, \
                 chiedere a chi amministra."
            }
            Self::Suspended => {
                "Questa persona è sospesa e non può entrare. Serve chi amministra l'Hub."
            }
        }
    }
}

/// Le persone dell'ufficio, servite dall'Hub.
#[derive(Debug)]
pub struct HubPeopleService {
    database: Database,
    brake: crate::hub_access::SharedBrake,
}

impl HubPeopleService {
    /// Costruisce il servizio sull'archivio dell'Hub.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self {
            database,
            brake: crate::hub_access::SharedBrake::default(),
        }
    }

    /// Costruisce il servizio con il freno dell'Hub acceso, condiviso fra le
    /// connessioni (FINAL-REVIEW-01, FR-019).
    #[must_use]
    pub const fn with_brake(database: Database, brake: crate::hub_access::SharedBrake) -> Self {
        Self { database, brake }
    }

    /// L'archivio, per chi deve leggere accanto.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Crea una persona dell'ufficio.
    ///
    /// La decide **chi amministra**, e il dispositivo che la chiede deve
    /// averne il ruolo: creare persone è amministrare l'ufficio.
    ///
    /// # Errori
    ///
    /// Un errore se il dispositivo non è autorizzato, se l'identificativo è
    /// già in uso, o se la scrittura non riesce.
    pub fn create(
        &self,
        device: &AuthenticatedDevice,
        id: &PersonId,
        label: &DisplayName,
        role: HubRole,
        passphrase: &Passphrase,
        now: Timestamp,
    ) -> ServiceResult<Person> {
        if !device.role().permits(HubAction::AdministerPeople) {
            return Err(ServiceError::HubServer {
                reason: format!(
                    "il dispositivo ha il ruolo {} e l'azione è riservata: {}",
                    device.role().label(),
                    HubAction::AdministerPeople.reason()
                ),
            });
        }

        self.crea(
            &format!("postazione.{}", device.device()),
            id,
            label,
            role,
            passphrase,
            now,
        )
    }

    /// Crea una persona dell'ufficio **dalla postazione che fa da Hub**, per mano
    /// di chi la amministra (FINAL-REVIEW-01, FR-047).
    ///
    /// ADR-0097: «Le crea chi amministra». Fino al 2026-10-04 l'unica via
    /// passava da un dispositivo con il ruolo d'amministratore, che nessuna
    /// schermata assegnava, attraverso una richiesta che il protocollo non ha:
    /// nessuna persona poteva esistere, e «Entra» non riusciva mai. La
    /// modalità amministratore la controlla chi chiama, dove il comando gira,
    /// come per il foglietto dell'arruolamento (ADR-0132, decisione 5).
    ///
    /// # Errori
    ///
    /// Come [`Self::create`], salvo il ruolo del dispositivo.
    pub fn create_on_the_hub(
        &self,
        administrator: &lisi_core::model::identity::OperatorId,
        id: &PersonId,
        label: &DisplayName,
        role: HubRole,
        passphrase: &Passphrase,
        now: Timestamp,
    ) -> ServiceResult<Person> {
        self.crea(
            &format!("amministratore.{}", administrator.as_str()),
            id,
            label,
            role,
            passphrase,
            now,
        )
    }

    fn crea(
        &self,
        creata_da: &str,
        id: &PersonId,
        label: &DisplayName,
        role: HubRole,
        passphrase: &Passphrase,
        now: Timestamp,
    ) -> ServiceResult<Person> {
        let verificatore =
            PassphraseVerifier::try_new(&lisi_security::derive_verifier(passphrase.expose())?)?;
        self.database
            .insert_hub_person(&lisi_storage::repository::hub_person::NewPerson {
                id,
                label,
                role,
                verifier: &verificatore,
                created_by: creata_da,
                created_at: now,
            })?;

        self.registra(
            AUDIT_CREATED,
            &format!(
                "{} creata da {creata_da} con il ruolo {}",
                attore_della_persona(id),
                role.as_str()
            ),
            now,
        )?;

        Ok(Person {
            id: id.clone(),
            label: label.clone(),
            role,
            state: PersonState::Active,
            created_at: now,
        })
    }

    /// Verifica una frase e, se è quella giusta, fa entrare la persona.
    ///
    /// La verifica è **lenta apposta** (ADR-0097, decisione 3): è il costo che
    /// rende inutile provare le frasi una dopo l'altra.
    ///
    /// # Errori
    ///
    /// Un errore se la lettura o la scrittura dell'audit non riescono. Una
    /// frase **sbagliata non è un errore**: è un esito.
    pub fn sign_in(
        &mut self,
        id: &PersonId,
        passphrase: &Passphrase,
        address: &str,
        now: Timestamp,
    ) -> ServiceResult<SignInOutcome> {
        let persona = self.database.hub_person(id)?;
        let verificatore = self.database.hub_person_verifier(id)?;

        let giusta = match verificatore {
            Some(verificatore) => {
                lisi_security::verify_passphrase(verificatore.as_str(), passphrase.expose())?
            }
            // NESSUNA USCITA IN ANTICIPO PER CHI NON ESISTE: rispondere subito
            // direbbe, dal tempo di risposta, quali identificativi esistono.
            // Si verifica comunque contro un verificatore che non corrisponde
            // a nessuno.
            None => {
                let _ = lisi_security::verify_passphrase(VERIFICATORE_DI_NESSUNO, b"");
                false
            }
        };

        if !giusta {
            return self.rifiuta(id, address, now);
        }

        // LA PERSONA SOSPESA NON ENTRA, E LO SA — ma solo se la frase è la sua
        // (FINAL-REVIEW-01, FR-020). Non è il rifiuto anonimo: è uno stato che
        // chi amministra ha deciso, e chi lo subisce deve sapere a chi
        // rivolgersi. Fino al 2026-10-03 lo si diceva PRIMA di verificare la
        // frase, e senza il costo della verifica: chiunque, con una frase
        // qualunque, sapeva quali identificativi esistono e sono sospesi
        // (ADR-0097, decisione 5: il rifiuto non distingue, non esce prima).
        if persona
            .as_ref()
            .is_some_and(|persona| !persona.may_sign_in())
        {
            self.registra(
                AUDIT_SUSPENDED_ATTEMPT,
                &format!(
                    "{} ha provato a entrare da {address}",
                    attore_della_persona(id)
                ),
                now,
            )?;
            return Ok(SignInOutcome::Suspended);
        }

        let Some(persona) = persona else {
            // Non può accadere: senza persona non c'è verificatore, e senza
            // verificatore la frase non è mai giusta. Se accadesse, non si
            // entra.
            return self.rifiuta(id, address, now);
        };

        self.registra(
            AUDIT_SIGNED_IN,
            &format!("{} è entrata da {address}", attore_della_persona(id)),
            now,
        )?;
        Ok(SignInOutcome::Entered(AuthenticatedOperator {
            person: persona.id,
            role: persona.role,
            _privato: (),
        }))
    }

    /// Sospende una persona, o la rimette in servizio.
    ///
    /// **Non cancella**: gli atti già compiuti restano suoi.
    ///
    /// # Errori
    ///
    /// Un errore se il dispositivo non è autorizzato, se la persona non
    /// esiste, o se la scrittura non riesce.
    pub fn set_state(
        &self,
        device: &AuthenticatedDevice,
        id: &PersonId,
        state: PersonState,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !device.role().permits(HubAction::AdministerPeople) {
            return Err(ServiceError::HubServer {
                reason: format!(
                    "il dispositivo ha il ruolo {} e l'azione è riservata: {}",
                    device.role().label(),
                    HubAction::AdministerPeople.reason()
                ),
            });
        }
        self.cambia_stato(&format!("postazione.{}", device.device()), id, state, now)
    }

    /// Sospende o rimette in servizio una persona dalla postazione che fa da
    /// Hub, per mano di chi la amministra (FINAL-REVIEW-01, FR-047).
    ///
    /// # Errori
    ///
    /// Come [`Self::set_state`], salvo il ruolo del dispositivo.
    pub fn set_state_on_the_hub(
        &self,
        administrator: &lisi_core::model::identity::OperatorId,
        id: &PersonId,
        state: PersonState,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.cambia_stato(
            &format!("amministratore.{}", administrator.as_str()),
            id,
            state,
            now,
        )
    }

    fn cambia_stato(
        &self,
        chi: &str,
        id: &PersonId,
        state: PersonState,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.set_hub_person_state(id, state)?;
        self.registra(
            AUDIT_STATE,
            &format!(
                "{} è ora {} per decisione di {chi}",
                attore_della_persona(id),
                state.as_str(),
            ),
            now,
        )
    }

    /// Rimette la frase di una persona.
    ///
    /// È l'unico modo di recuperarla: **non esiste un recupero automatico**,
    /// che sarebbe una seconda via d'ingresso più debole della prima
    /// (ADR-0097).
    ///
    /// # Errori
    ///
    /// Un errore se il dispositivo non è autorizzato, se la persona non
    /// esiste, o se la scrittura non riesce.
    pub fn reset_passphrase(
        &self,
        device: &AuthenticatedDevice,
        id: &PersonId,
        passphrase: &Passphrase,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !device.role().permits(HubAction::AdministerPeople) {
            return Err(ServiceError::HubServer {
                reason: format!(
                    "il dispositivo ha il ruolo {} e l'azione è riservata: {}",
                    device.role().label(),
                    HubAction::AdministerPeople.reason()
                ),
            });
        }
        self.rimetti_frase(
            &format!("postazione.{}", device.device()),
            id,
            passphrase,
            now,
        )
    }

    /// Rimette la frase di una persona dalla postazione che fa da Hub, per mano
    /// di chi la amministra (FINAL-REVIEW-01, FR-047).
    ///
    /// # Errori
    ///
    /// Come [`Self::reset_passphrase`], salvo il ruolo del dispositivo.
    pub fn reset_passphrase_on_the_hub(
        &self,
        administrator: &lisi_core::model::identity::OperatorId,
        id: &PersonId,
        passphrase: &Passphrase,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.rimetti_frase(
            &format!("amministratore.{}", administrator.as_str()),
            id,
            passphrase,
            now,
        )
    }

    fn rimetti_frase(
        &self,
        chi: &str,
        id: &PersonId,
        passphrase: &Passphrase,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let verificatore =
            PassphraseVerifier::try_new(&lisi_security::derive_verifier(passphrase.expose())?)?;
        self.database.set_hub_person_verifier(id, &verificatore)?;
        self.registra(
            AUDIT_PASSPHRASE,
            &format!(
                "la frase di {} è stata rimessa da {chi}",
                attore_della_persona(id)
            ),
            now,
        )
    }

    /// Le persone dell'ufficio.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn people(&self) -> ServiceResult<Vec<Person>> {
        Ok(self.database.hub_people()?)
    }

    /// Conta il tentativo fallito e risponde senza dire perché.
    fn rifiuta(
        &mut self,
        id: &PersonId,
        address: &str,
        now: Timestamp,
    ) -> ServiceResult<SignInOutcome> {
        // IL FRENO PROTEGGE L'AUDIT, MAI IL LEGITTIMO (ADR-0085). Mille
        // tentativi non devono poter scrivere mille righe; ma chi sbaglia a
        // digitare non deve restare chiuso fuori, e per questo il freno **non**
        // cambia l'esito: cambia soltanto che cosa si scrive.
        //
        // Contro chi prova le frasi una dopo l'altra c'è il costo di Argon2id,
        // che è la difesa scritta per quel caso (ADR-0097, decisione 3).
        match crate::hub_access::frena(&self.brake, address, now) {
            BrakeVerdict::Record => {
                self.registra(
                    AUDIT_REFUSED,
                    &format!("tentativo non riuscito per {} da {address}", id.as_str()),
                    now,
                )?;
            }
            BrakeVerdict::RecordAndEngage => {
                self.registra(
                    AUDIT_BRAKE,
                    &format!(
                        "troppi tentativi da {address}: da qui in avanti non si registrano uno \
                         per uno"
                    ),
                    now,
                )?;
            }
            BrakeVerdict::Suppress => {}
        }
        Ok(SignInOutcome::NotRecognized)
    }

    fn registra(&self, azione: &str, dettaglio: &str, now: Timestamp) -> ServiceResult<()> {
        let voce = NewAuditEntry {
            actor: Actor::try_new(AUDIT_AUTHORITY)?,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(dettaglio)?),
            recorded_at: now,
        };
        self.database.append_audit(&voce)?;
        Ok(())
    }
}

/// Un verificatore che non appartiene a nessuno.
///
/// Serve a far costare uguale il tentativo su una persona che non esiste: se
/// il rifiuto arrivasse subito, il **tempo di risposta** direbbe quali
/// identificativi esistono, e il freno non servirebbe a niente.
///
/// È il verificatore della frase vuota con i parametri correnti, scritto qui
/// una volta per tutte: calcolarlo a ogni tentativo costerebbe una derivazione
/// in più senza cambiare nulla.
const VERIFICATORE_DI_NESSUNO: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$\
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

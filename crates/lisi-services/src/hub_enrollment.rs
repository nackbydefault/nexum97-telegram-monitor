//! L'autorità che ammette i dispositivi: il **lato Hub** dell'arruolamento.
//!
//! # Che cosa questo modulo è, e dove gira
//!
//! Gira sull'Hub, che non è un'altra macchina: ADR-0042 decisione 4 lo dice per
//! intero — «l'Hub **è** la postazione». È questo prodotto, in una modalità
//! diversa, e per questo le tabelle stanno nell'archivio ordinario.
//!
//! # I tre controlli, e il loro ordine
//!
//! **Prima il freno.** Se ci sono stati troppi tentativi a vuoto di recente,
//! l'arruolamento è chiuso e non si guarda nemmeno il codice. Guardarlo prima
//! significherebbe valutare le ipotesi di chi sta tentando, che è esattamente
//! ciò che il freno esiste per impedire.
//!
//! **Poi il dispositivo.** Se questo Hub lo conosce già, o lo ha ritirato, non
//! si scrive nulla. A garantire che l'autorizzazione non venga bruciata è la
//! transazione, non quest'ordine — un controllo negativo lo ha verificato; il
//! controllo viene prima perché costa una lettura ed evita una scrittura
//! inutile.
//!
//! **Infine il codice**, consumato e speso nello stesso atto in cui il
//! dispositivo entra.
//!
//! # Che cosa questo modulo non fa
//!
//! Non parla in rete, non ascolta su una porta, non cifra nulla. Riceve una
//! richiesta già costruita e restituisce un esito. Il trasporto è HUB-04, e
//! **finché non esiste, nessuna richiesta deve attraversare una rete**: il
//! gettone, quando verrà presentato, ha la stessa forma di una parola d'accesso
//! e va sotto TLS.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::enrollment::{
    ENROLLMENT_CODE_BYTES, ENROLLMENT_CODE_MINUTES, EnrollmentCode, EnrollmentGrant,
    EnrollmentRefusal, EnrollmentRequest, FAILURE_WINDOW_MINUTES, MAX_RECENT_FAILURES,
};
use lisi_core::model::hub_event::{HubEventKind, NewHubEvent};
use lisi_core::model::identity::{DeviceId, OperatorId};
use lisi_core::text::HubEventSubject;
use lisi_core::text::{AuditAction, AuditDetail, AuditEntity, DisplayName, Note};
use lisi_storage::repository::enrollment::{Admission, EnrolledDevice};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_events::publish_event;

/// Entità dell'audit per le voci di questo modulo.
const AUDIT_ENTITY: &str = "arruolamento";
/// Azione registrata all'emissione di un'autorizzazione.
const AUDIT_ISSUED: &str = "codice_arruolamento_emesso";
/// Azione registrata quando un dispositivo entra.
const AUDIT_ADMITTED: &str = "dispositivo_ammesso";
/// Azione registrata quando un dispositivo non entra.
const AUDIT_REFUSED: &str = "arruolamento_rifiutato";
/// Azione registrata quando l'Hub ritira un dispositivo.
const AUDIT_REVOKED: &str = "dispositivo_ritirato_dall_hub";

/// Soggetto registrato per gli atti compiuti dall'autorità, non da una persona.
///
/// # Perché non l'operatore locale
///
/// Perché non è vero. Un'ammissione la chiede una **macchina**, e la decide
/// questo processo applicando una regola; scrivere nell'audit che l'ha compiuta
/// l'operatore della postazione attribuirebbe a una persona un atto che non ha
/// fatto — che è esattamente il danno che ADR-0042 decisione 2 esiste per
/// impedire, e sarebbe ironico farlo proprio qui.
///
/// Emissione e ritiro restano invece atti di una **persona**, e portano il suo
/// identificativo.
///
/// È la stessa forma dell'attore `acquisizione`, usato dal ciclo automatico.
const AUDIT_AUTHORITY: &str = "hub.arruolamento";

/// Millisecondi in un minuto.
const MINUTO_MS: i64 = 60_000;

/// Un'autorizzazione appena emessa, da consegnare fuori banda.
///
/// # Perché il codice esce di qui e non viene conservato
///
/// L'Hub conserva l'impronta. Questo è **l'unico momento** in cui il codice
/// esiste in chiaro, e chi lo riceve deve consegnarlo subito: non c'è modo di
/// rileggerlo dopo, e non è una dimenticanza.
#[derive(Debug)]
pub struct IssuedCode {
    /// Il codice da leggere a chi deve arruolare la postazione.
    pub code: EnrollmentCode,
    /// Fino a quando vale.
    pub expires_at: Timestamp,
}

impl IssuedCode {
    /// Che cosa dire a chi ha emesso il codice.
    ///
    /// Contiene il codice: è destinata a essere letta a schermo e riferita a
    /// voce, **non** registrata né esportata.
    #[must_use]
    pub fn administrator_message(&self) -> String {
        format!(
            "Codice di arruolamento: {}\n\nVale {ENROLLMENT_CODE_MINUTES} minuti e per un solo \
             dispositivo. Consegnarlo a voce o di persona, non sullo stesso canale che si sta \
             autorizzando. Non verrà mostrato una seconda volta.",
            self.code.reveal_to_administrator()
        )
    }
}

/// Esito di una richiesta di arruolamento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentOutcome {
    /// Il dispositivo è entrato.
    Admitted(EnrollmentGrant),
    /// Il dispositivo non è entrato, e la ragione dice quale controllo è
    /// fallito.
    Refused(EnrollmentRefusal),
}

impl EnrollmentOutcome {
    /// Frase da mostrare a chi ha tentato l'arruolamento.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Admitted(grant) => format!(
                "Questo dispositivo è stato ammesso dall'Hub «{}».",
                grant.hub.as_str()
            ),
            Self::Refused(refusal) => refusal.operator_message(),
        }
    }

    /// Vero se il dispositivo è entrato.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted(_))
    }
}

/// L'autorità di arruolamento di questo Hub.
pub struct HubEnrollmentService {
    database: Database,
    hub: DisplayName,
}

impl HubEnrollmentService {
    /// Costruisce l'autorità sull'archivio indicato.
    ///
    /// Il nome dell'Hub non è decorazione: finisce nel messaggio che il
    /// dispositivo mostra al proprio operatore, e serve a sapere **dove** si è
    /// entrati quando un ufficio ne ha più di uno.
    #[must_use]
    pub const fn new(database: Database, hub: DisplayName) -> Self {
        Self { database, hub }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Emette un'autorizzazione, da consegnare fuori banda.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il generatore crittografico rifiuta la
    /// richiesta o se la scrittura non riesce.
    pub fn issue_code(&self, operator: &OperatorId, now: Timestamp) -> ServiceResult<IssuedCode> {
        let mut byte = [0_u8; ENROLLMENT_CODE_BYTES];
        lisi_security::random_bytes(&mut byte).map_err(|errore| ServiceError::DeviceIdentity {
            reason: String::from(errore.operator_message()),
        })?;
        let code = EnrollmentCode::from_random_bytes(&byte);
        let expires_at =
            Timestamp::from_millis(now.as_millis() + ENROLLMENT_CODE_MINUTES * MINUTO_MS);

        self.database.record_enrollment_code(
            &code.fingerprint(),
            operator.as_str(),
            now,
            expires_at,
        )?;

        // L'audit registra CHE un'autorizzazione e' stata emessa e da chi.
        // **Non il codice**: l'audit documenta le azioni, non i dati su cui
        // insistono, e un codice in un registro e' un'autorizzazione in un
        // registro.
        self.registra(operator, AUDIT_ISSUED, "autorizzazione emessa", now)?;

        Ok(IssuedCode { code, expires_at })
    }

    /// Decide se ammettere un dispositivo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se una lettura o una scrittura non riescono. Un
    /// **rifiuto non è un errore**: è un esito, e chi chiama lo deve mostrare.
    pub fn admit(
        &mut self,
        request: &EnrollmentRequest,
        now: Timestamp,
    ) -> ServiceResult<EnrollmentOutcome> {
        if let Some(refusal) = self.brake(now)? {
            return self.refuse(request, refusal, now);
        }

        let admission = self
            .database
            .admit_device(request, &request.verifier, now)?;

        let refusal = match admission {
            Admission::Admitted { .. } => {
                let grant = EnrollmentGrant {
                    hub: self.hub.clone(),
                    enrolled_at: now,
                };
                self.registra_autorita(
                    AUDIT_ADMITTED,
                    &format!("dispositivo {}", request.device_id),
                    now,
                )?;
                // L'ingresso di un dispositivo e' un fatto che i client devono
                // poter ricostruire: entra nella sequenza (ADR-0086).
                self.pubblica(HubEventKind::DeviceEnrolled, &request.device_id, now)?;
                return Ok(EnrollmentOutcome::Admitted(grant));
            }
            Admission::CodeNotFound => EnrollmentRefusal::CodeNotRecognised,
            Admission::CodeExpired => EnrollmentRefusal::CodeExpired,
            Admission::CodeAlreadyUsed => EnrollmentRefusal::CodeAlreadyUsed,
            Admission::DeviceAlreadyEnrolled => EnrollmentRefusal::DeviceAlreadyEnrolled,
            Admission::DeviceRevoked { reason } => EnrollmentRefusal::DeviceRevoked { reason },
        };

        self.refuse(request, refusal, now)
    }

    /// Ritira un dispositivo. **È la revoca che conta.**
    ///
    /// Quella registrata sulla postazione è una copia che spiega all'operatore
    /// perché la macchina ha smesso di provarci; questa è quella che il
    /// dispositivo non può riscrivere, perché non ci arriva.
    ///
    /// Ritirare due volte non è un errore e non cambia nulla: prevale la prima
    /// ragione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, o se questo Hub non
    /// conosce il dispositivo — ritirare ciò che non è mai entrato lascerebbe
    /// credere di aver chiuso una porta che non c'era.
    pub fn revoke(
        &mut self,
        device_id: &DeviceId,
        operator: &OperatorId,
        reason: &Note,
        now: Timestamp,
    ) -> ServiceResult<bool> {
        if self.database.enrolled_device(device_id.as_str())?.is_none() {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from("questo Hub non conosce il dispositivo indicato"),
            });
        }

        let ritirato = self
            .database
            .revoke_enrolled_device(device_id.as_str(), reason, now)?;
        if ritirato {
            self.registra(
                operator,
                AUDIT_REVOKED,
                &format!("dispositivo {device_id}: {}", reason.as_str()),
                now,
            )?;
            self.pubblica(HubEventKind::DeviceRevoked, device_id, now)?;
        }
        Ok(ritirato)
    }

    /// Restituisce l'archivio, per passarlo a un'altra autorità dell'Hub.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// I dispositivi che questo Hub ha ammesso, ritirati compresi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn enrolled(&self) -> ServiceResult<Vec<EnrolledDevice>> {
        Ok(self.database.enrolled_devices()?)
    }

    /// Scrive un evento nella sequenza autorevole dell'Hub.
    ///
    /// Il soggetto e' l'identificativo del dispositivo, che non e' un segreto:
    /// il gettone e la sua impronta non compaiono mai (ADR-0086).
    fn pubblica(
        &mut self,
        kind: HubEventKind,
        device_id: &DeviceId,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let evento = NewHubEvent {
            kind,
            subject: HubEventSubject::try_new(device_id.as_str())?,
            detail: None,
        };
        publish_event(&mut self.database, &evento, now)?;
        Ok(())
    }

    /// Il freno: quanti tentativi a vuoto ci sono stati nella finestra.
    ///
    /// Restituisce il rifiuto da opporre, o `None` se si può procedere.
    fn brake(&self, now: Timestamp) -> ServiceResult<Option<EnrollmentRefusal>> {
        let inizio = Timestamp::from_millis(now.as_millis() - FAILURE_WINDOW_MINUTES * MINUTO_MS);
        let quanti = self.database.enrollment_failures_since(inizio)?;
        if quanti < MAX_RECENT_FAILURES {
            return Ok(None);
        }

        // Fra quanto si riapre: quando il piu' vecchio dei tentativi esce dalla
        // finestra. Dirlo evita che chi ha diritto di arruolare provi a
        // ripetizione senza sapere per quanto.
        let riapertura = self
            .database
            .oldest_enrollment_failure_since(inizio)?
            .map_or(FAILURE_WINDOW_MINUTES, |piu_vecchio| {
                let trascorsi = (now.as_millis() - piu_vecchio.as_millis()) / MINUTO_MS;
                (FAILURE_WINDOW_MINUTES - trascorsi).max(1)
            });

        Ok(Some(EnrollmentRefusal::TooManyRecentFailures {
            retry_in_minutes: riapertura,
        }))
    }

    /// Registra un rifiuto, contandolo quando è un tentativo a vuoto.
    fn refuse(
        &self,
        request: &EnrollmentRequest,
        refusal: EnrollmentRefusal,
        now: Timestamp,
    ) -> ServiceResult<EnrollmentOutcome> {
        if refusal.counts_as_attempt() {
            self.database
                .record_enrollment_failure(refusal.audit_detail(), now)?;
        }

        self.registra_autorita(
            AUDIT_REFUSED,
            &format!(
                "dispositivo {}: {}",
                request.device_id,
                refusal.audit_detail()
            ),
            now,
        )?;

        Ok(EnrollmentOutcome::Refused(refusal))
    }

    /// Scrive una voce di audit per un atto compiuto dall'autorità.
    ///
    /// Non da una persona: vedere [`AUDIT_AUTHORITY`].
    fn registra_autorita(
        &self,
        azione: &str,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.scrivi(
            lisi_core::text::Actor::try_new(AUDIT_AUTHORITY)?,
            azione,
            dettaglio,
            now,
        )
    }

    /// Scrive una voce di audit per un atto compiuto da una persona.
    fn registra(
        &self,
        operator: &OperatorId,
        azione: &str,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.scrivi(operator.audit_actor()?, azione, dettaglio, now)
    }

    /// Scrive la voce, quale che sia il soggetto.
    fn scrivi(
        &self,
        actor: lisi_core::text::Actor,
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
    use std::path::Path;

    use lisi_core::Timestamp;
    use lisi_core::model::enrollment::{
        ENROLLMENT_CODE_BYTES, ENROLLMENT_CODE_MINUTES, EnrollmentCode, EnrollmentRefusal,
        EnrollmentRequest, EnrollmentSalt, FAILURE_WINDOW_MINUTES, MAX_RECENT_FAILURES,
    };
    use lisi_core::model::identity::{
        DEVICE_ID_BYTES, DEVICE_SECRET_BYTES, DeviceId, DeviceSecret, OperatorId,
    };
    use lisi_core::text::{DisplayName, Note};

    use super::{EnrollmentOutcome, HubEnrollmentService, MINUTO_MS};
    use crate::Database;

    /// Istante di riferimento delle prove.
    fn istante() -> Timestamp {
        Timestamp::from_millis(1_756_000_000_000)
    }

    /// Un istante spostato di tanti minuti.
    fn fra(minuti: i64) -> Timestamp {
        Timestamp::from_millis(istante().as_millis() + minuti * MINUTO_MS)
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(valore) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        valore
    }

    fn nota(testo: &str) -> Note {
        let Ok(valore) = Note::try_new(testo) else {
            panic!("la nota di prova deve essere valida");
        };
        valore
    }

    fn archivio() -> Database {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        database
    }

    fn autorita() -> HubEnrollmentService {
        HubEnrollmentService::new(archivio(), nome("Hub della centrale"))
    }

    fn autorita_su(percorso: &Path) -> HubEnrollmentService {
        let Ok(database) = Database::open(percorso) else {
            panic!("l'archivio su file deve potersi aprire");
        };
        HubEnrollmentService::new(database, nome("Hub della centrale"))
    }

    /// Una postazione che chiede di entrare, senza passare dal file protetto.
    ///
    /// Il lato client con DPAPI ha le proprie prove in `device_identity`; qui
    /// serve soltanto una richiesta ben formata, e costruirla a mano rende le
    /// prove dell'Hub indipendenti da Windows.
    fn richiesta(seme: u8, code: &EnrollmentCode) -> EnrollmentRequest {
        use lisi_core::model::enrollment::DeviceToken;

        let salt = EnrollmentSalt::from_random_bytes(&[seme; 16]);
        let secret = DeviceSecret::from_random_bytes([seme; DEVICE_SECRET_BYTES]);
        let token = DeviceToken::derive(&salt, &secret);

        EnrollmentRequest {
            device_id: DeviceId::from_random_bytes(&[seme; DEVICE_ID_BYTES]),
            label: nome("Postazione di prova"),
            code: code.clone(),
            salt,
            verifier: token.verifier(),
        }
    }

    fn emetti(hub: &HubEnrollmentService, quando: Timestamp) -> EnrollmentCode {
        let Ok(emesso) = hub.issue_code(&OperatorId::local(), quando) else {
            panic!("l'emissione deve riuscire");
        };
        emesso.code
    }

    fn rifiuto(esito: &EnrollmentOutcome) -> &EnrollmentRefusal {
        match esito {
            EnrollmentOutcome::Refused(refusal) => refusal,
            EnrollmentOutcome::Admitted(_) => panic!("il dispositivo doveva essere rifiutato"),
        }
    }

    // -----------------------------------------------------------------
    // Il percorso che funziona
    // -----------------------------------------------------------------

    /// **Un dispositivo entra con un'autorizzazione viva.**
    #[cfg(windows)]
    #[test]
    fn un_dispositivo_entra_con_un_codice_valido() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());

        let Ok(esito) = hub.admit(&richiesta(0x11, &codice), fra(1)) else {
            panic!("l'ammissione deve riuscire");
        };
        assert!(
            esito.is_admitted(),
            "il dispositivo non e' entrato: {esito:?}"
        );

        let EnrollmentOutcome::Admitted(grant) = &esito else {
            panic!("esito inatteso");
        };
        assert_eq!(grant.hub.as_str(), "Hub della centrale");
        assert!(
            esito.operator_message().contains("Hub della centrale"),
            "il messaggio non dice presso quale Hub: «{}»",
            esito.operator_message()
        );

        let Ok(elenco) = hub.enrolled() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(elenco.len(), 1);
        assert!(!elenco[0].is_revoked());
    }

    /// **Il codice mostrato all'amministratore dice tutto cio' che deve.**
    #[cfg(windows)]
    #[test]
    fn il_messaggio_dell_emissione_dice_i_tre_vincoli() {
        let hub = autorita();
        let Ok(emesso) = hub.issue_code(&OperatorId::local(), istante()) else {
            panic!("l'emissione deve riuscire");
        };
        let messaggio = emesso.administrator_message();

        assert!(
            messaggio.contains(emesso.code.reveal_to_administrator()),
            "il messaggio non contiene il codice: chi lo emette non potrebbe consegnarlo"
        );
        assert!(
            messaggio.contains("un solo dispositivo"),
            "il messaggio non dice che vale una volta sola: «{messaggio}»"
        );
        assert!(
            messaggio.contains(&ENROLLMENT_CODE_MINUTES.to_string()),
            "il messaggio non dice per quanto vale: «{messaggio}»"
        );
        assert!(
            messaggio.contains("non sullo stesso canale"),
            "il messaggio non dice di consegnarlo fuori banda: «{messaggio}»"
        );
    }

    // -----------------------------------------------------------------
    // I rifiuti
    // -----------------------------------------------------------------

    /// **Un codice vale una volta sola.**
    #[cfg(windows)]
    #[test]
    fn un_codice_fa_entrare_un_dispositivo_solo() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());

        let Ok(primo) = hub.admit(&richiesta(0x11, &codice), fra(1)) else {
            panic!("la prima ammissione deve riuscire");
        };
        assert!(primo.is_admitted());

        let Ok(secondo) = hub.admit(&richiesta(0x22, &codice), fra(2)) else {
            panic!("la seconda richiesta deve produrre un esito");
        };
        assert_eq!(rifiuto(&secondo), &EnrollmentRefusal::CodeAlreadyUsed);

        let Ok(elenco) = hub.enrolled() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(
            elenco.len(),
            1,
            "due dispositivi sono entrati con un'autorizzazione sola"
        );
    }

    /// **Un codice scaduto non fa entrare.**
    #[cfg(windows)]
    #[test]
    fn un_codice_scaduto_non_fa_entrare() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());

        let Ok(dentro) = hub.admit(&richiesta(0x33, &codice), fra(ENROLLMENT_CODE_MINUTES - 1))
        else {
            panic!("l'ammissione deve produrre un esito");
        };
        assert!(dentro.is_admitted(), "un codice ancora vivo ha fallito");

        // Un secondo codice, e il tempo che passa.
        let mut hub = autorita();
        let codice = emetti(&hub, istante());
        let Ok(tardi) = hub.admit(&richiesta(0x44, &codice), fra(ENROLLMENT_CODE_MINUTES + 1))
        else {
            panic!("l'ammissione deve produrre un esito");
        };
        assert_eq!(rifiuto(&tardi), &EnrollmentRefusal::CodeExpired);
    }

    /// **Un codice inventato non fa entrare, e non dice se esisteva.**
    #[cfg(windows)]
    #[test]
    fn un_codice_inventato_non_fa_entrare() {
        let mut hub = autorita();
        let _ = emetti(&hub, istante());
        let inventato = EnrollmentCode::from_random_bytes(&[0x7E; ENROLLMENT_CODE_BYTES]);

        let Ok(esito) = hub.admit(&richiesta(0x55, &inventato), fra(1)) else {
            panic!("l'ammissione deve produrre un esito");
        };
        assert_eq!(rifiuto(&esito), &EnrollmentRefusal::CodeNotRecognised);
    }

    /// **Un dispositivo gia' dentro non brucia una seconda autorizzazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Se la richiesta consumasse il codice prima di accorgersi che il
    /// dispositivo e' gia' ammesso, un doppio clic dell'operatore brucerebbe
    /// un'autorizzazione appena emessa. L'amministratore la dovrebbe riemettere
    /// senza capire perche', e la seconda volta potrebbe succedere di nuovo.
    #[cfg(windows)]
    #[test]
    fn un_dispositivo_gia_dentro_non_brucia_una_seconda_autorizzazione() {
        let mut hub = autorita();
        let primo = emetti(&hub, istante());
        let Ok(dentro) = hub.admit(&richiesta(0x66, &primo), fra(1)) else {
            panic!("la prima ammissione deve riuscire");
        };
        assert!(dentro.is_admitted());

        let secondo = emetti(&hub, fra(2));
        let Ok(esito) = hub.admit(&richiesta(0x66, &secondo), fra(3)) else {
            panic!("la seconda richiesta deve produrre un esito");
        };
        assert_eq!(rifiuto(&esito), &EnrollmentRefusal::DeviceAlreadyEnrolled);

        // La seconda autorizzazione e' ancora spendibile: un ALTRO dispositivo
        // la puo' usare.
        let Ok(altro) = hub.admit(&richiesta(0x77, &secondo), fra(4)) else {
            panic!("la terza richiesta deve produrre un esito");
        };
        assert!(
            altro.is_admitted(),
            "la seconda autorizzazione era stata bruciata da una richiesta che non \
             aveva fatto entrare nessuno"
        );
    }

    /// **Un dispositivo ritirato dall'Hub non rientra.**
    ///
    /// E' la revoca che conta: quella sulla postazione e' una copia che spiega,
    /// questa e' quella che il dispositivo non puo' riscrivere.
    #[cfg(windows)]
    #[test]
    fn un_dispositivo_ritirato_dall_hub_non_rientra() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());
        let domanda = richiesta(0x88, &codice);
        let Ok(dentro) = hub.admit(&domanda, fra(1)) else {
            panic!("l'ammissione deve riuscire");
        };
        assert!(dentro.is_admitted());

        let Ok(ritirato) = hub.revoke(
            &domanda.device_id,
            &OperatorId::local(),
            &nota("portatile smarrito"),
            fra(2),
        ) else {
            panic!("il ritiro deve riuscire");
        };
        assert!(ritirato);

        let nuovo = emetti(&hub, fra(3));
        let Ok(esito) = hub.admit(&richiesta(0x88, &nuovo), fra(4)) else {
            panic!("la richiesta deve produrre un esito");
        };
        let EnrollmentRefusal::DeviceRevoked { reason } = rifiuto(&esito) else {
            panic!("il rifiuto doveva essere per ritiro: {esito:?}");
        };
        assert_eq!(reason.as_str(), "portatile smarrito");

        // E la nuova autorizzazione non e' stata bruciata.
        let Ok(altro) = hub.admit(&richiesta(0x99, &nuovo), fra(5)) else {
            panic!("la richiesta deve produrre un esito");
        };
        assert!(altro.is_admitted());
    }

    /// **Ritirare due volte conserva la prima ragione.**
    #[cfg(windows)]
    #[test]
    fn ritirare_due_volte_conserva_la_prima_ragione() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());
        let domanda = richiesta(0xAA, &codice);
        let Ok(_) = hub.admit(&domanda, fra(1)) else {
            panic!("l'ammissione deve riuscire");
        };

        let Ok(primo) = hub.revoke(
            &domanda.device_id,
            &OperatorId::local(),
            &nota("prima ragione"),
            fra(2),
        ) else {
            panic!("il primo ritiro deve riuscire");
        };
        assert!(primo);

        let Ok(secondo) = hub.revoke(
            &domanda.device_id,
            &OperatorId::local(),
            &nota("seconda ragione"),
            fra(3),
        ) else {
            panic!("il secondo ritiro non deve fallire");
        };
        assert!(!secondo, "il secondo ritiro ha riscritto il primo");

        let Ok(elenco) = hub.enrolled() else {
            panic!("l'elenco deve potersi leggere");
        };
        let Some(ragione) = elenco[0].revoked_reason.as_ref() else {
            panic!("il dispositivo doveva risultare ritirato");
        };
        assert_eq!(ragione.as_str(), "prima ragione");
    }

    /// **Ritirare cio' che non e' mai entrato e' un errore.**
    ///
    /// **L'ingresso e il ritiro entrano nella sequenza autorevole** (ADR-0086).
    ///
    /// Sono i primi fatti che un client in modalita' squadra deve poter
    /// ricostruire senza chiedere «chi c'e' adesso»: chi e' entrato, chi e'
    /// stato ritirato, e in quale ordine.
    #[cfg(windows)]
    #[test]
    fn lingresso_e_il_ritiro_entrano_nella_sequenza() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());
        let richiesta = richiesta(0x42, &codice);
        let Ok(esito) = hub.admit(&richiesta, istante()) else {
            panic!("la richiesta deve produrre un esito");
        };
        assert!(esito.is_admitted());
        let Ok(true) = hub.revoke(
            &richiesta.device_id,
            &OperatorId::local(),
            &nota("postazione dismessa"),
            fra(1),
        ) else {
            panic!("il ritiro deve riuscire");
        };

        let Ok(eventi) = hub.database().hub_events_after(0, 10) else {
            panic!("lettura della sequenza");
        };
        let fatti: Vec<(u64, &str, &str)> = eventi
            .iter()
            .map(|evento| {
                (
                    evento.sequence,
                    evento.kind.as_str(),
                    evento.subject.as_str(),
                )
            })
            .collect();
        assert_eq!(
            fatti,
            vec![
                (1, "dispositivo_ammesso", richiesta.device_id.as_str()),
                (2, "dispositivo_ritirato", richiesta.device_id.as_str()),
            ]
        );
        // Nessun evento porta il gettone o la sua impronta.
        for evento in &eventi {
            let dettaglio = evento
                .detail
                .as_ref()
                .map(lisi_core::text::HubEventDetail::as_str)
                .unwrap_or_default();
            assert!(!dettaglio.contains(richiesta.verifier.as_str()));
            assert!(
                !evento
                    .subject
                    .as_str()
                    .contains(richiesta.verifier.as_str())
            );
        }
    }

    /// Un successo silenzioso lascerebbe credere di aver chiuso una porta che
    /// non c'era — e chi lo ha fatto smetterebbe di cercare quella vera.
    #[cfg(windows)]
    #[test]
    fn ritirare_cio_che_non_e_mai_entrato_e_un_errore() {
        let mut hub = autorita();
        assert!(
            hub.revoke(
                &DeviceId::from_random_bytes(&[0xBB; DEVICE_ID_BYTES]),
                &OperatorId::local(),
                &nota("qualunque"),
                istante(),
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------
    // Il freno
    // -----------------------------------------------------------------

    /// **Troppi tentativi a vuoto chiudono l'arruolamento, e poi lo riaprono.**
    #[cfg(windows)]
    #[test]
    fn troppi_tentativi_a_vuoto_chiudono_e_poi_riaprono_l_arruolamento() {
        let mut hub = autorita();
        let buono = emetti(&hub, istante());
        let inventato = EnrollmentCode::from_random_bytes(&[0x01; ENROLLMENT_CODE_BYTES]);

        for tentativo in 0..MAX_RECENT_FAILURES {
            let Ok(esito) = hub.admit(&richiesta(0xC0, &inventato), fra(1)) else {
                panic!("il tentativo {tentativo} deve produrre un esito");
            };
            assert_eq!(rifiuto(&esito), &EnrollmentRefusal::CodeNotRecognised);
        }

        // Ora nemmeno un codice VALIDO passa: e' il punto del freno.
        let Ok(bloccato) = hub.admit(&richiesta(0xC1, &buono), fra(2)) else {
            panic!("la richiesta deve produrre un esito");
        };
        let EnrollmentRefusal::TooManyRecentFailures { retry_in_minutes } = rifiuto(&bloccato)
        else {
            panic!("il rifiuto doveva essere il freno: {bloccato:?}");
        };
        assert!(
            *retry_in_minutes > 0,
            "il freno non dice fra quanto si riapre"
        );

        // Passata la finestra, l'arruolamento riprende.
        //
        // Il codice serve nuovo, e non e' un dettaglio della prova: la finestra
        // dei tentativi e la durata di un codice sono lunghe uguali, quindi un
        // codice emesso prima di un attacco e' scaduto quando il freno si
        // riapre. E' voluto — un'autorizzazione che sopravvivesse a un quarto
        // d'ora di tentativi sarebbe un'autorizzazione piu' longeva di quanto
        // dichiara — e la conseguenza per l'ufficio e' che dopo un attacco il
        // codice si riemette. Sta in ADR-0047 fra i rischi residui.
        let dopo = fra(FAILURE_WINDOW_MINUTES + 2);
        let nuovo = emetti(&hub, dopo);
        let Ok(riaperto) = hub.admit(&richiesta(0xC1, &nuovo), dopo) else {
            panic!("la richiesta deve produrre un esito");
        };
        assert!(
            riaperto.is_admitted(),
            "l'arruolamento non si e' riaperto dopo la finestra: {riaperto:?}"
        );

        // E il codice buono non e' stato consumato dal tentativo bloccato: il
        // freno rifiuta prima di toccare qualunque autorizzazione.
        let Ok(elenco) = hub.enrolled() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(
            elenco.len(),
            1,
            "il freno ha lasciato entrare qualcuno, o ha consumato un'autorizzazione"
        );
        let Ok(esito) = hub.admit(&richiesta(0xC2, &buono), dopo) else {
            panic!("la richiesta deve produrre un esito");
        };
        assert_eq!(
            rifiuto(&esito),
            &EnrollmentRefusal::CodeExpired,
            "il codice buono risulta gia' usato: il tentativo bloccato lo aveva consumato"
        );
    }

    /// **Il freno non si accende per errori in buona fede.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Se un dispositivo gia' ammesso che riprova contasse come tentativo, una
    /// postazione configurata per ritentare da sola bloccherebbe l'arruolamento
    /// di tutte le altre. Sarebbe un guasto costruito con le proprie mani, e si
    /// manifesterebbe come un attacco che non c'e'.
    #[cfg(windows)]
    #[test]
    fn il_freno_non_si_accende_per_errori_in_buona_fede() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());
        let Ok(_) = hub.admit(&richiesta(0xD0, &codice), fra(1)) else {
            panic!("l'ammissione deve riuscire");
        };

        // Molte piu' ripetizioni di quante ne servirebbero a far scattare il
        // freno, se contassero.
        for _ in 0..(MAX_RECENT_FAILURES * 3) {
            let Ok(esito) = hub.admit(&richiesta(0xD0, &codice), fra(2)) else {
                panic!("la richiesta deve produrre un esito");
            };
            assert_eq!(rifiuto(&esito), &EnrollmentRefusal::DeviceAlreadyEnrolled);
        }

        let nuovo = emetti(&hub, fra(3));
        let Ok(altro) = hub.admit(&richiesta(0xD1, &nuovo), fra(4)) else {
            panic!("la richiesta deve produrre un esito");
        };
        assert!(
            altro.is_admitted(),
            "un errore ripetuto in buona fede ha chiuso l'arruolamento a tutti: {altro:?}"
        );
    }

    // -----------------------------------------------------------------
    // Che cosa l'Hub non conserva
    // -----------------------------------------------------------------

    /// **Nell'archivio dell'Hub non c'e' nulla di riutilizzabile.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un archivio che conservasse il codice conterrebbe **autorizzazioni vive**:
    /// chi lo leggesse potrebbe farci entrare un dispositivo proprio. Un archivio
    /// che conservasse il gettone conterrebbe **credenziali**: chi lo leggesse
    /// potrebbe presentarsi al posto di un dispositivo ammesso.
    ///
    /// La prova guarda i byte del file, non le colonne: una colonna nuova
    /// aggiunta domani finirebbe comunque sotto questo sguardo.
    #[cfg(windows)]
    #[test]
    fn l_archivio_dell_hub_non_contiene_ne_il_codice_ne_il_gettone() {
        use lisi_core::model::enrollment::DeviceToken;

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("hub.sqlite3");

        let (codice_in_chiaro, gettone_in_chiaro) = {
            let mut hub = autorita_su(&percorso);
            let codice = emetti(&hub, istante());
            let domanda = richiesta(0xE0, &codice);
            let Ok(dentro) = hub.admit(&domanda, fra(1)) else {
                panic!("l'ammissione deve riuscire");
            };
            assert!(dentro.is_admitted());

            let secret = DeviceSecret::from_random_bytes([0xE0; DEVICE_SECRET_BYTES]);
            let token = DeviceToken::derive(&domanda.salt, &secret);
            let mut esadecimale = String::new();
            for byte in token.expose() {
                esadecimale.push_str(&format!("{byte:02x}"));
            }
            (codice.reveal_to_administrator().to_owned(), esadecimale)
        };

        // Chiuso l'archivio, si guardano i byte del file.
        let Ok(byte) = std::fs::read(&percorso) else {
            panic!("il file dell'archivio deve potersi leggere");
        };
        let contenuto = String::from_utf8_lossy(&byte).into_owned();

        assert!(
            !contenuto.contains(&codice_in_chiaro),
            "l'archivio dell'Hub contiene il codice di arruolamento in chiaro: e' \
             un'autorizzazione viva depositata su disco"
        );
        let cifre: String = codice_in_chiaro
            .chars()
            .filter(|carattere| *carattere != '-')
            .collect();
        assert!(
            !contenuto.contains(&cifre),
            "l'archivio contiene il codice senza separatori"
        );
        assert!(
            !contenuto.contains(&gettone_in_chiaro),
            "l'archivio dell'Hub contiene il gettone del dispositivo: chi lo leggesse \
             potrebbe presentarsi al posto suo"
        );
    }

    /// **L'audit registra che cosa e' successo e mai il codice.**
    #[cfg(windows)]
    #[test]
    fn l_audit_registra_l_ammissione_e_mai_il_codice() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());
        let domanda = richiesta(0xF0, &codice);
        let Ok(_) = hub.admit(&domanda, fra(1)) else {
            panic!("l'ammissione deve riuscire");
        };

        let Ok(voci) = hub.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let righe: Vec<String> = voci
            .iter()
            .map(|voce| {
                format!(
                    "{}|{}|{}",
                    voce.action.as_str(),
                    voce.entity.as_str(),
                    voce.detail
                        .as_ref()
                        .map_or("", lisi_core::text::AuditDetail::as_str)
                )
            })
            .collect();

        assert!(
            righe
                .iter()
                .any(|riga| riga.contains("codice_arruolamento_emesso")),
            "l'emissione non e' stata registrata: {righe:?}"
        );
        assert!(
            righe
                .iter()
                .any(|riga| riga.contains("dispositivo_ammesso")),
            "l'ammissione non e' stata registrata: {righe:?}"
        );
        assert!(
            righe
                .iter()
                .any(|riga| riga.contains(domanda.device_id.as_str())),
            "l'audit non nomina il dispositivo ammesso: {righe:?}"
        );

        let cifre: String = codice
            .reveal_to_administrator()
            .chars()
            .filter(|carattere| *carattere != '-')
            .collect();
        for riga in &righe {
            assert!(
                !riga.contains(codice.reveal_to_administrator()) && !riga.contains(&cifre),
                "una voce di audit contiene il codice di arruolamento: «{riga}»"
            );
        }
    }

    /// **Chi emette e' una persona; chi ammette e' il processo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un'ammissione la chiede una **macchina**, e la decide questo processo
    /// applicando una regola. Registrarla a nome dell'operatore locale
    /// attribuirebbe a una persona un atto che non ha compiuto — che e'
    /// esattamente il danno che ADR-0042 decisione 2 esiste per impedire, e
    /// sarebbe ironico farlo proprio nel modulo che quella decisione attua.
    ///
    /// Emissione e ritiro restano atti di una persona, e devono continuare a
    /// portarne l'identificativo.
    #[cfg(windows)]
    #[test]
    fn l_audit_distingue_cio_che_fa_una_persona_da_cio_che_fa_il_processo() {
        let mut hub = autorita();
        let codice = emetti(&hub, istante());
        let domanda = richiesta(0x0B, &codice);
        let Ok(_) = hub.admit(&domanda, fra(1)) else {
            panic!("l'ammissione deve riuscire");
        };
        let Ok(_) = hub.revoke(
            &domanda.device_id,
            &OperatorId::local(),
            &nota("sostituito"),
            fra(2),
        ) else {
            panic!("il ritiro deve riuscire");
        };

        let Ok(voci) = hub.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let attore_di = |azione: &str| -> String {
            voci.iter()
                .find(|voce| voce.action.as_str() == azione)
                .map_or_else(
                    || panic!("l'azione «{azione}» non e' stata registrata"),
                    |voce| voce.actor.as_str().to_owned(),
                )
        };

        assert_eq!(
            attore_di("dispositivo_ammesso"),
            super::AUDIT_AUTHORITY,
            "un'ammissione risulta compiuta da una persona che non l'ha compiuta"
        );
        assert_eq!(
            attore_di("codice_arruolamento_emesso"),
            OperatorId::local().as_str(),
            "l'emissione, che e' l'atto di una persona, risulta compiuta dal processo"
        );
        assert_eq!(
            attore_di("dispositivo_ritirato_dall_hub"),
            OperatorId::local().as_str(),
            "il ritiro, che e' l'atto di una persona, risulta compiuto dal processo"
        );
    }

    /// **Anche un rifiuto lascia traccia, e dice quale controllo e' fallito.**
    #[cfg(windows)]
    #[test]
    fn anche_un_rifiuto_lascia_traccia() {
        let mut hub = autorita();
        let inventato = EnrollmentCode::from_random_bytes(&[0x02; ENROLLMENT_CODE_BYTES]);
        let Ok(_) = hub.admit(&richiesta(0x0A, &inventato), istante()) else {
            panic!("la richiesta deve produrre un esito");
        };

        let Ok(voci) = hub.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let trovato = voci.iter().any(|voce| {
            voce.action.as_str() == "arruolamento_rifiutato"
                && voce
                    .detail
                    .as_ref()
                    .is_some_and(|dettaglio| dettaglio.as_str().contains("codice_non_riconosciuto"))
        });
        assert!(
            trovato,
            "un tentativo rifiutato non ha lasciato traccia: chi indaga non saprebbe \
             che qualcuno ha provato"
        );
    }

    // -----------------------------------------------------------------
    // La corsa
    // -----------------------------------------------------------------

    /// **Due richieste concorrenti sullo stesso codice ne fanno entrare una.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Fra il controllo «questo codice e' libero» e la scrittura che lo consuma
    /// c'e' una finestra. Due richieste che vi cadessero dentro deciderebbero
    /// entrambe che il codice e' libero, e **due dispositivi entrerebbero con
    /// un'autorizzazione sola** — mentre chi l'ha emessa ne conta uno.
    ///
    /// La chiusura non e' un controllo piu' attento: e' la condizione dentro
    /// l'aggiornamento, e la lettura di quante righe sono state toccate.
    #[cfg(windows)]
    #[test]
    fn due_richieste_concorrenti_sullo_stesso_codice_ne_fanno_entrare_una() {
        /// Quante volte si ripete la corsa.
        ///
        /// # Perché non basta una volta
        ///
        /// La finestra fra la lettura e la scrittura e' stretta, e su una
        /// macchina scarica i due fili si succedono invece di sovrapporsi: la
        /// prova resterebbe verde senza aver mai corso.
        ///
        /// E' successo davvero. Questa prova e' passata per otto esecuzioni di
        /// fila e poi e' diventata rossa quando la macchina era carica — con un
        /// errore tecnico invece che con un esito, ed era un **difetto del
        /// prodotto**, non della prova (vedere il commento su `IMMEDIATE` in
        /// `lisi-storage::repository::enrollment`).
        ///
        /// Ripetere la corsa la rende una prova invece che una coincidenza.
        const GIRI: u8 = 25;

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("hub.sqlite3");

        for giro in 0..GIRI {
            let codice = {
                let hub = autorita_su(&percorso);
                emetti(&hub, istante())
            };
            // Due dispositivi nuovi a ogni giro: gli altri sono gia' dentro, e
            // un dispositivo gia' ammesso non correrebbe per l'autorizzazione.
            let (primo_seme, secondo_seme) = (giro.wrapping_mul(2), giro.wrapping_mul(2) + 1);

            let (uno, due) = std::thread::scope(|ambito| {
                let primo = ambito.spawn(|| {
                    let mut hub = autorita_su(&percorso);
                    hub.admit(&richiesta(primo_seme, &codice), fra(1))
                });
                let secondo = ambito.spawn(|| {
                    let mut hub = autorita_su(&percorso);
                    hub.admit(&richiesta(secondo_seme, &codice), fra(1))
                });
                let (Ok(uno), Ok(due)) = (primo.join(), secondo.join()) else {
                    panic!("entrambi i fili devono terminare, al giro {giro}");
                };
                (uno, due)
            });

            // Un errore tecnico **non** e' un esito accettabile. Un
            // arruolamento deve riuscire o essere rifiutato con una ragione: se
            // fallisce con «archivio occupato», chi ha tentato non sa se e'
            // entrato, e riproverebbe bruciando la propria autorizzazione.
            let (Ok(uno), Ok(due)) = (uno, due) else {
                panic!(
                    "al giro {giro} una richiesta e' fallita con un errore tecnico invece \
                     che con un esito"
                );
            };

            let entrati = usize::from(uno.is_admitted()) + usize::from(due.is_admitted());
            assert_eq!(
                entrati, 1,
                "al giro {giro}, con un'autorizzazione sola sono entrati {entrati} \
                 dispositivi: {uno:?} / {due:?}"
            );
        }

        let hub = autorita_su(&percorso);
        let Ok(elenco) = hub.enrolled() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(
            elenco.len(),
            usize::from(GIRI),
            "dopo {GIRI} autorizzazioni l'archivio conta {} dispositivi",
            elenco.len()
        );
    }
}

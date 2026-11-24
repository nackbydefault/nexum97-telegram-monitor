//! Gestione dei profili di credenziali API e degli account Telegram.
//!
//! # Che cosa questo servizio custodisce, e che cosa no
//!
//! Un [`crate::config::TelegramCredentials`] (API id/hash) e un account Telegram
//! sono due cose distinte, come vuole il modello multi-account (ADR-0019): un
//! **profilo** serve **N** account. Dal 2026-11-13 le credenziali sono quelle
//! dell'applicazione, arrivate con la distribuzione (ADR-0204,
//! [`crate::app_credentials`]): nessuno le scrive da qui. I nuovi account usano
//! il profilo dell'applicazione, che [`AccountService::application_profile`]
//! crea da sé; i profili scritti prima restano per gli account che li usano.
//!
//! **Nessun segreto passa da qui.** Il numero, i codici e le chiavi non compaiono
//! affatto in questo modulo: il numero è persistito solo **mascherato** dal
//! runtime, e l'identità stabile di un account è il suo **UUID**, generato con
//! il generatore crittografico di sistema, mai il numero di telefono.
//!
//! Ogni azione lascia una traccia d'audit con un'etichetta stabile
//! (`profilo_api_creato`, `account_aggiunto`, `account_rimosso`, …). Il
//! dettaglio non contiene mai un segreto: al più l'etichetta scelta
//! dall'operatore, che segreto non è.

use lisi_core::model::{
    AccountUuid, ApiCredentialProfile, MaskedPhoneNumber, NewApiCredentialProfile, NewAuditEntry,
    NewTelegramAccount, PersistedAuthStatus, PersistedConnectionStatus, TelegramAccount,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, DisplayName};
use lisi_core::{ApiCredentialProfileId, TelegramAccountId, Timestamp};
use lisi_security::{SecurityError, random_bytes};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Byte casuali che compongono un [`AccountUuid`] (sedici byte, 32 cifre esa).
const UUID_BYTES: usize = 16;

/// Azione d'audit: creazione di un profilo di credenziali API.
const ACTION_PROFILE_CREATED: &str = "profilo_api_creato";
/// Azione registrata quando un profilo di credenziali viene rimosso.
const ACTION_PROFILE_REMOVED: &str = "profilo_api_rimosso";
/// Azione d'audit: registrazione di un account.
const ACTION_ACCOUNT_ADDED: &str = "account_aggiunto";
/// Azione d'audit: rimozione di un account.
const ACTION_ACCOUNT_REMOVED: &str = "account_rimosso";
/// Azione registrata come prima riga di un archivio appena azzerato.
const ACTION_ARCHIVE_RESET: &str = "archivio_azzerato";
/// Entita' interessata dalla riga di continuita'.
const ENTITY_ARCHIVE: &str = "archivio";

/// Azione d'audit: la configurazione dell'applicazione è stata importata.
const ACTION_APPLICATION_IMPORTED: &str = "configurazione_applicazione_importata";
/// Azione d'audit: importata, ma il file di distribuzione non si è cancellato.
const ACTION_APPLICATION_NOT_REMOVED: &str = "configurazione_applicazione_non_cancellata";
/// Azione d'audit: il file di distribuzione non conteneva credenziali valide.
const ACTION_APPLICATION_INVALID: &str = "configurazione_applicazione_non_valida";
/// Entità d'audit: la configurazione dell'applicazione.
const ENTITY_APPLICATION: &str = "applicazione";

/// Nome del profilo dell'applicazione, che i nuovi account usano (ADR-0204).
pub const APPLICATION_PROFILE_LABEL: &str = "Applicazione NEXUM/97";

/// Entità d'audit: profilo di credenziali API.
const ENTITY_PROFILE: &str = "api_profile";
/// Entità d'audit: account Telegram.
const ENTITY_ACCOUNT: &str = "telegram_account";

/// Servizio che orchestra profili di credenziali e account.
///
/// Possiede il [`Database`] come gli altri servizi: passarlo dall'uno all'altro
/// è il modo in cui la sequenza si compone, così che un account registrato qui
/// sia visibile al runtime che dovrà usarlo.
#[derive(Debug)]
pub struct AccountService {
    database: Database,
}

impl AccountService {
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

    /// Quanti monitoraggi in corso non hanno un account registrato
    /// (MULTI-ACCOUNT-02, ADR-0173): con più account collegati non ricevono
    /// niente, e la schermata Account lo dice.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn running_monitorings_without_account(&self) -> ServiceResult<usize> {
        Ok(self.database.running_sessions_without_account()?)
    }

    /// Restituisce il database, consumando il servizio.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Registra un nuovo profilo di credenziali API, ancora **non configurato**.
    ///
    /// Il segreto (API id/hash) si salva a parte con
    /// [`Self::save_api_credentials`]: qui nasce solo l'etichetta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura o la registrazione d'audit non
    /// riescono.
    pub fn create_api_profile(
        &self,
        label: &DisplayName,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<ApiCredentialProfileId> {
        let id = self.database.insert_api_profile(
            &NewApiCredentialProfile {
                label: label.clone(),
            },
            now,
        )?;
        self.record_audit(
            actor,
            ACTION_PROFILE_CREATED,
            ENTITY_PROFILE,
            id.get(),
            Some(label.as_str()),
            now,
        )?;
        Ok(id)
    }

    /// Il profilo dell'applicazione, creato la prima volta che serve.
    ///
    /// Le sue credenziali non stanno in un file del profilo: sono quelle della
    /// distribuzione ([`crate::app_credentials`]). Il profilo esiste perché
    /// ogni account ne ha uno (ADR-0019) e perché archivio e sessioni scritte
    /// prima non cambino.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura, la scrittura o la registrazione
    /// d'audit non riescono.
    pub fn application_profile(
        &self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<ApiCredentialProfileId> {
        if let Some(profile) = self
            .api_profiles()?
            .into_iter()
            .find(|profile| profile.label.as_str() == APPLICATION_PROFILE_LABEL)
        {
            return Ok(profile.id);
        }
        let label = DisplayName::try_new(APPLICATION_PROFILE_LABEL)?;
        let id = self.create_api_profile(&label, actor, now)?;
        self.database.set_api_profile_configured(id, true, now)?;
        Ok(id)
    }

    /// Registra che cosa è successo al file di distribuzione, senza i valori.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la registrazione d'audit non riesce.
    pub fn record_application_configuration(
        &self,
        outcome: crate::app_credentials::ImportOutcome,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        use crate::app_credentials::ImportOutcome;
        let action = match outcome {
            ImportOutcome::Absent => return Ok(()),
            ImportOutcome::Imported => ACTION_APPLICATION_IMPORTED,
            ImportOutcome::ImportedNotRemoved => ACTION_APPLICATION_NOT_REMOVED,
            ImportOutcome::Invalid => ACTION_APPLICATION_INVALID,
        };
        self.record_audit(actor, action, ENTITY_APPLICATION, 0, None, now)
    }

    /// Tutti i profili di credenziali, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn api_profiles(&self) -> ServiceResult<Vec<ApiCredentialProfile>> {
        Ok(self.database.api_profiles()?)
    }

    /// Un singolo profilo di credenziali, per identificatore.
    ///
    /// Serve all'orchestrazione della modalità reale, che deve accertare
    /// l'esistenza del profilo dell'account prima di tentare l'accesso. Restituisce
    /// solo i metadati non segreti: l'API hash non passa di qui.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::SessionUnavailable`] se il profilo non esiste, e
    /// un errore se la lettura non riesce.
    pub fn api_profile(&self, id: ApiCredentialProfileId) -> ServiceResult<ApiCredentialProfile> {
        self.api_profiles()?
            .into_iter()
            .find(|profile| profile.id == id)
            .ok_or(ServiceError::SessionUnavailable {
                reason: String::from(
                    "il profilo delle credenziali di Telegram selezionato non esiste",
                ),
            })
    }

    /// Registra un account su un profilo, generandone l'UUID locale.
    ///
    /// L'UUID nasce da sedici byte del generatore crittografico di sistema
    /// ([`random_bytes`]): è l'identità stabile da cui il runtime deriva le
    /// cartelle e la chiave dell'account, **mai** dal numero di telefono. Il
    /// numero non è ancora noto: comparirà solo mascherato, dopo il primo
    /// accesso.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il generatore di sistema rifiuta (fuori da
    /// Windows non è disponibile), se il profilo non esiste, se l'UUID collide o
    /// se la scrittura non riesce.
    pub fn add_account(
        &self,
        label: &DisplayName,
        profile_id: ApiCredentialProfileId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<TelegramAccount> {
        let uuid = generate_uuid()?;
        let id = self.database.insert_telegram_account(
            &NewTelegramAccount {
                uuid,
                label: label.clone(),
                profile_id,
            },
            now,
        )?;
        self.record_audit(
            actor,
            ACTION_ACCOUNT_ADDED,
            ENTITY_ACCOUNT,
            id.get(),
            Some(label.as_str()),
            now,
        )?;
        Ok(self.database.telegram_account(id)?)
    }

    /// Tutti gli account, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn accounts(&self) -> ServiceResult<Vec<TelegramAccount>> {
        Ok(self.database.telegram_accounts()?)
    }

    /// Un singolo account, per identificatore.
    ///
    /// Serve all'interfaccia per ricomporre l'account selezionato da cui aprire il
    /// runtime, senza che la GUI conosca la persistenza. Restituisce solo i
    /// metadati non segreti.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'account non esiste o se la lettura non riesce.
    pub fn account(&self, id: TelegramAccountId) -> ServiceResult<TelegramAccount> {
        Ok(self.database.telegram_account(id)?)
    }

    /// Rimuove un account.
    ///
    /// Un account con fonti associate **non** si cancella: il vincolo
    /// `ON DELETE RESTRICT` dello schema lo impedisce, così che i contenuti
    /// acquisiti restino riconducibili al loro account d'origine. In quel caso la
    /// rimozione fallisce e nessuna traccia d'audit di rimozione viene scritta,
    /// perché la rimozione non è avvenuta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'account non esiste, se ha fonti associate o se
    /// la scrittura non riesce.
    /// Rimuove un profilo di credenziali API.
    ///
    /// Il file protetto con le credenziali cifrate **non** viene toccato qui:
    /// vive sul disco e lo rimuove chi conosce la cartella base (vedere
    /// [`crate::reset`]). Separare le due cose evita che questo servizio, che
    /// non tocca mai il filesystem, cominci a farlo per un solo caso.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il profilo non esiste, se un account vi fa
    /// ancora riferimento o se la scrittura dell'audit non riesce.
    /// Registra nell'audit appena creato che cosa è stato archiviato.
    ///
    /// È la prima riga del nuovo volume, e dichiara quale ha chiuso: quante
    /// voci sono state archiviate e con quale impronta. Se il file archiviato
    /// venisse distrutto, questa riga continuerebbe a dire che esisteva.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn record_reset_continuity(
        &self,
        record: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.record_audit(
            actor,
            ACTION_ARCHIVE_RESET,
            ENTITY_ARCHIVE,
            0,
            Some(record),
            now,
        )
    }

    pub fn remove_api_profile(
        &self,
        profile_id: ApiCredentialProfileId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.delete_api_profile(profile_id)?;
        self.record_audit(
            actor,
            ACTION_PROFILE_REMOVED,
            ENTITY_PROFILE,
            profile_id.get(),
            None,
            now,
        )
    }

    pub fn remove_account(
        &self,
        account_id: TelegramAccountId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.delete_telegram_account(account_id)?;
        self.record_audit(
            actor,
            ACTION_ACCOUNT_REMOVED,
            ENTITY_ACCOUNT,
            account_id.get(),
            None,
            now,
        )
    }

    /// Aggiorna gli stati conservati di un account e, se noto, il numero
    /// mascherato.
    ///
    /// È il passo di persistenza dell'orchestrazione dell'accesso
    /// ([`crate::telegram_runtime`]): il runtime traduce lo stato fine
    /// dell'autorizzazione nelle sintesi conservate e le scrive qui, così che lo
    /// stato dell'account non diverga da quello reale fra un avvio e l'altro. Il
    /// numero è passato **già mascherato**; il numero pieno non attraversa questo
    /// metodo. Un numero ancora ignoto (`None`) non cancella quello già scritto,
    /// come impone lo schema.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'account non esiste o se la scrittura non
    /// riesce.
    pub fn record_account_state(
        &self,
        account_id: TelegramAccountId,
        auth: PersistedAuthStatus,
        connection: PersistedConnectionStatus,
        masked_phone: Option<&MaskedPhoneNumber>,
        connected_at: Option<Timestamp>,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.update_account_state(
            account_id,
            auth,
            connection,
            masked_phone,
            connected_at,
            now,
        )?;
        Ok(())
    }

    /// Registra una voce nell'audit append-only.
    ///
    /// Il dettaglio, quando presente, è l'etichetta scelta dall'operatore, che
    /// segreto non è. Numero, codici, hash e chiavi non compaiono mai.
    fn record_audit(
        &self,
        actor: &Actor,
        action: &str,
        entity: &str,
        entity_id: i64,
        detail: Option<&str>,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = match detail {
            Some(text) if !text.trim().is_empty() => Some(AuditDetail::try_new(text)?),
            _ => None,
        };

        let entry = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new(entity)?,
            entity_id: Some(entity_id),
            // La gestione degli account non conosce la modalità operativa, che
            // vive nel servizio dei dizionari: `None` significa «non registrata».
            actor_mode: None,
            detail,
            recorded_at: now,
        };

        self.database.append_audit(&entry)?;
        Ok(())
    }
}

/// Genera un [`AccountUuid`] da sedici byte del generatore di sistema.
///
/// Il dominio non conosce l'entropia, solo la forma: la generazione avviene qui,
/// dove il generatore sicuro è disponibile.
fn generate_uuid() -> ServiceResult<AccountUuid> {
    let mut bytes = [0_u8; UUID_BYTES];
    random_bytes(&mut bytes).map_err(map_security_error)?;
    Ok(AccountUuid::from_bytes(bytes))
}

/// Traduce un errore della protezione locale, senza trasportarne alcun dettaglio
/// riservato.
fn map_security_error(error: SecurityError) -> ServiceError {
    ServiceError::SessionUnavailable {
        reason: String::from(error.operator_message()),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::AccountUuid;
    use lisi_core::model::{NewApiCredentialProfile, NewTelegramAccount, PersistedAuthStatus};
    use lisi_core::text::{Actor, DisplayName};
    use lisi_core::{ApiCredentialProfileId, Timestamp};
    use lisi_storage::Database;

    use super::AccountService;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn actor() -> Actor {
        let Ok(actor) = Actor::try_new("responsabile.ufficio") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn label(text: &str) -> DisplayName {
        let Ok(name) = DisplayName::try_new(text) else {
            panic!("l'etichetta di prova deve essere valida");
        };
        name
    }

    fn service() -> AccountService {
        let Ok(database) = Database::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire");
        };
        AccountService::new(database)
    }

    /// Inserisce un account con un UUID fisso, senza passare dal generatore di
    /// sistema: rende i test indipendenti dalla piattaforma.
    fn seed_account(
        service: &AccountService,
        profile_id: ApiCredentialProfileId,
        byte: u8,
    ) -> lisi_core::TelegramAccountId {
        let Ok(id) = service.database().insert_telegram_account(
            &NewTelegramAccount {
                uuid: AccountUuid::from_bytes([byte; 16]),
                label: label("Account di prova"),
                profile_id,
            },
            now(),
        ) else {
            panic!("l'account di prova deve potersi inserire");
        };
        id
    }

    fn seed_profile(service: &AccountService) -> ApiCredentialProfileId {
        let Ok(id) = service.database().insert_api_profile(
            &NewApiCredentialProfile {
                label: label("Profilo ufficio"),
            },
            now(),
        ) else {
            panic!("il profilo di prova deve potersi inserire");
        };
        id
    }

    #[test]
    fn a_created_profile_starts_unconfigured_and_is_audited() {
        let service = service();
        let Ok(id) = service.create_api_profile(&label("Profilo ufficio"), &actor(), now()) else {
            panic!("la creazione del profilo deve riuscire");
        };

        let Ok(profiles) = service.api_profiles() else {
            panic!("i profili devono potersi leggere");
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, id);
        assert!(!profiles[0].configured, "un profilo nasce non configurato");

        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            audit
                .iter()
                .any(|entry| entry.action.as_str() == "profilo_api_creato")
        );
    }

    #[test]
    fn a_single_profile_is_found_by_id_and_a_missing_one_is_reported() {
        let service = service();
        let id = seed_profile(&service);

        let Ok(found) = service.api_profile(id) else {
            panic!("il profilo appena creato deve potersi leggere per id");
        };
        assert_eq!(found.id, id);

        assert!(
            service
                .api_profile(ApiCredentialProfileId::new(9_999))
                .is_err(),
            "un profilo inesistente deve essere segnalato"
        );
    }

    #[test]
    fn a_single_account_is_read_by_id_and_a_missing_one_is_reported() {
        let service = service();
        let profile_id = seed_profile(&service);
        let id = seed_account(&service, profile_id, 0xcd);

        let Ok(account) = service.account(id) else {
            panic!("l'account appena creato deve potersi leggere per id");
        };
        assert_eq!(account.id, id);

        assert!(
            service
                .account(lisi_core::TelegramAccountId::new(9_999))
                .is_err(),
            "un account inesistente deve essere segnalato"
        );
    }

    #[test]
    fn an_account_is_listed_and_removed_and_both_are_audited() {
        let service = service();
        let profile_id = seed_profile(&service);
        let account_id = seed_account(&service, profile_id, 0xab);

        let Ok(accounts) = service.accounts() else {
            panic!("gli account devono potersi leggere");
        };
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].auth_status, PersistedAuthStatus::Fresh);

        let Ok(()) = service.remove_account(account_id, &actor(), now()) else {
            panic!("la rimozione deve riuscire");
        };
        assert_eq!(service.accounts().map(|all| all.len()).ok(), Some(0));

        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            audit
                .iter()
                .any(|entry| entry.action.as_str() == "account_rimosso")
        );
    }

    #[test]
    fn removing_a_missing_account_is_reported_without_panic() {
        let service = service();
        assert!(
            service
                .remove_account(lisi_core::TelegramAccountId::new(404), &actor(), now())
                .is_err()
        );
    }

    #[test]
    fn no_audit_detail_ever_carries_a_masked_or_full_number() {
        // Le azioni sugli account non scrivono mai un numero nel dettaglio: al
        // più l'etichetta, che segreto non è.
        let service = service();
        let profile_id = seed_profile(&service);
        let _ = seed_account(&service, profile_id, 0x01);

        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for entry in audit {
            if let Some(detail) = entry.detail {
                assert!(!detail.as_str().contains('+'));
                assert!(!detail.as_str().chars().any(|c| c.is_ascii_digit()));
            }
        }
    }

    #[test]
    fn il_profilo_dell_applicazione_nasce_una_volta_configurato() {
        let service = service();
        let (Ok(primo), Ok(secondo)) = (
            service.application_profile(&actor(), now()),
            service.application_profile(&actor(), now()),
        ) else {
            panic!("il profilo dell'applicazione deve potersi avere");
        };
        assert_eq!(primo, secondo, "uno solo, riusato");
        let Ok(profiles) = service.api_profiles() else {
            panic!("i profili devono potersi leggere");
        };
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].configured);
        assert_eq!(profiles[0].label.as_str(), super::APPLICATION_PROFILE_LABEL);
    }

    #[test]
    fn l_importazione_si_registra_senza_valori_e_l_assenza_non_si_registra() {
        use crate::app_credentials::ImportOutcome;
        let service = service();
        for outcome in [
            ImportOutcome::Absent,
            ImportOutcome::Imported,
            ImportOutcome::ImportedNotRemoved,
            ImportOutcome::Invalid,
        ] {
            assert!(
                service
                    .record_application_configuration(outcome, &actor(), now())
                    .is_ok()
            );
        }
        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let azioni: Vec<&str> = audit.iter().map(|entry| entry.action.as_str()).collect();
        assert_eq!(
            azioni,
            [
                "configurazione_applicazione_importata",
                "configurazione_applicazione_non_cancellata",
                "configurazione_applicazione_non_valida"
            ]
        );
        assert!(audit.iter().all(|entry| entry.detail.is_none()));
    }

    // ---- Percorsi che richiedono il generatore di sistema o DPAPI (Windows) ----

    #[cfg(windows)]
    #[test]
    fn a_generated_account_gets_a_thirty_two_hex_uuid_and_starts_fresh() {
        let service = service();
        let profile_id = seed_profile(&service);

        let Ok(account) = service.add_account(&label("Account reale"), profile_id, &actor(), now())
        else {
            panic!("l'aggiunta dell'account deve riuscire");
        };
        assert_eq!(account.uuid.as_str().len(), AccountUuid::HEX_LEN);
        assert!(AccountUuid::from_hex(account.uuid.as_str()).is_ok());
        assert_eq!(account.auth_status, PersistedAuthStatus::Fresh);
        assert!(
            account.masked_phone.is_none(),
            "nessun numero prima dell'accesso"
        );

        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            audit
                .iter()
                .any(|entry| entry.action.as_str() == "account_aggiunto")
        );
    }

    #[cfg(windows)]
    #[test]
    fn two_generated_accounts_have_distinct_uuids() {
        let service = service();
        let profile_id = seed_profile(&service);

        let (Ok(first), Ok(second)) = (
            service.add_account(&label("Primo"), profile_id, &actor(), now()),
            service.add_account(&label("Secondo"), profile_id, &actor(), now()),
        ) else {
            panic!("entrambe le aggiunte devono riuscire");
        };
        assert_ne!(
            first.uuid, second.uuid,
            "due account non condividono l'UUID"
        );
    }
}

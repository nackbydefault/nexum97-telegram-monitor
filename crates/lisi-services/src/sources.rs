//! Gestione delle fonti monitorate.
//!
//! # Il vincolo fondamentale del prodotto
//!
//! Si monitorano **soltanto fonti già accessibili all'account d'ufficio**.
//! Questo servizio non offre alcuna operazione per cercare chat sulla
//! piattaforma né per entrare in un gruppo: l'assenza è deliberata. La ricerca
//! offerta all'operatore **filtra l'elenco già ottenuto**, in locale, e non
//! interroga la piattaforma.
//!
//! L'accessibilità è verificata **prima** del salvataggio, e non dopo: salvare
//! una fonte inaccessibile e scoprirlo all'avvio del monitoraggio produrrebbe
//! una sessione che non acquisisce nulla senza spiegare perché.

use lisi_core::model::{NewAuditEntry, NewSource, Source};
use lisi_core::text::{
    Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, SourceIdentifier,
};
use lisi_core::{SourceId, Timestamp};
use lisi_storage::{Database, StorageError};
use lisi_telegram::{AccessibleChat, ChatKind, TelegramConnector};

use crate::error::{ServiceError, ServiceResult};
use crate::telegram_runtime::AccountRuntime;

/// Esito della rimozione di una fonte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalOutcome {
    /// La fonte non era mai stata usata: è stata rimossa davvero.
    Deleted,
    /// La fonte era già stata usata in una sessione: è stata **disattivata**.
    ///
    /// Cancellarla renderebbe lo storico non più interpretabile, perché i
    /// contenuti acquisiti non sarebbero più riconducibili alla loro origine.
    Deactivated,
}

impl RemovalOutcome {
    /// Messaggio destinato all'operatore.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::Deleted => "La fonte è stata rimossa dall'elenco.",
            Self::Deactivated => {
                "La fonte è stata disattivata e non sarà più usata in nuove sessioni. \
                 Non è stata cancellata perché ha già partecipato a un monitoraggio: \
                 i contenuti acquisiti devono restare riconducibili alla loro origine."
            }
        }
    }
}

/// Chat accessibile, arricchita con lo stato della configurazione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableSource {
    /// Chat a cui l'account ha accesso.
    pub chat: AccessibleChat,
    /// Se è già configurata come fonte.
    pub already_configured: bool,
    /// Perché non è selezionabile, quando non lo è.
    pub unavailable_reason: Option<&'static str>,
}

impl AvailableSource {
    /// Se può essere aggiunta alle fonti.
    #[must_use]
    pub const fn can_be_added(&self) -> bool {
        self.unavailable_reason.is_none() && !self.already_configured
    }
}

/// Servizio che configura le fonti.
#[derive(Debug)]
pub struct SourceService {
    database: Database,
}

impl SourceService {
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
    ///
    /// I servizi possiedono il database invece di condividerlo: passarlo
    /// dall'uno all'altro è il modo in cui la sequenza si compone. Senza,
    /// ciascuno scriverebbe in un archivio proprio, e una fonte configurata qui
    /// sarebbe invisibile al monitoraggio che dovrebbe usarla.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Elenca le chat accessibili, indicando quali siano già configurate.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'account non è autorizzato o se la lettura
    /// delle fonti configurate non riesce.
    pub fn available(
        &self,
        connector: &mut dyn TelegramConnector,
    ) -> ServiceResult<Vec<AvailableSource>> {
        let chats = connector.accessible_chats()?;
        let configured = self.database.sources()?;
        let adesso = Timestamp::now().ok();

        let mut available = Vec::with_capacity(chats.len());
        for chat in chats {
            let identifier = chat.chat_id.get().to_string();
            let kind = map_kind(chat.kind);

            let configurata = configured
                .iter()
                .find(|source| source.kind == kind && source.identifier.as_str() == identifier);
            let already_configured = configurata.is_some();
            // L'INDIRIZZO PUBBLICO, COME LO SI VEDE ADESSO (ADR-0165).
            if let (Some(fonte), Some(adesso)) = (configurata, adesso) {
                record_address(&self.database, fonte.id, chat.username.as_deref(), adesso);
            }

            let unavailable_reason = if chat.is_monitorable() {
                None
            } else {
                Some(
                    "L'account non può leggere lo storico di questa chat: \
                     non è monitorabile in modo utile.",
                )
            };

            available.push(AvailableSource {
                chat,
                already_configured,
                unavailable_reason,
            });
        }

        Ok(available)
    }

    /// Come [`Self::available`], ma ricevendo il **runtime** dell'account.
    ///
    /// È la facade che tiene il connettore dentro i servizi: l'interfaccia
    /// possiede il runtime dell'account autorizzato, non il connettore, e lo
    /// passa qui. Il confine ADR-0010 resta intatto — la GUI non conosce TDLib.
    ///
    /// # Errori
    ///
    /// Come [`Self::available`].
    pub fn available_for(
        &self,
        runtime: &mut AccountRuntime,
    ) -> ServiceResult<Vec<AvailableSource>> {
        self.available(runtime.connector_mut())
    }

    /// Filtra un elenco già ottenuto.
    ///
    /// **Non interroga la piattaforma.** È una ricerca locale su ciò che
    /// l'account già vede, non una ricerca su Telegram.
    #[must_use]
    pub fn search(available: &[AvailableSource], query: &str) -> Vec<AvailableSource> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return available.to_vec();
        }

        available
            .iter()
            .filter(|entry| {
                entry.chat.title.to_lowercase().contains(&needle)
                    || entry.chat.chat_id.get().to_string().contains(&needle)
            })
            .cloned()
            .collect()
    }

    /// Fonti già configurate.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn configured(&self) -> ServiceResult<Vec<Source>> {
        Ok(self.database.sources()?)
    }

    /// Per ogni fonte, gli account d'ufficio con cui è stata seguita
    /// (MULTI-ACCOUNT-02, DEC-441), per dire nella schermata Fonti da quale
    /// account una chat è stata raggiunta.
    ///
    /// Si ricava dai monitoraggi: una fonte che nessun monitoraggio legato a
    /// un account ha incluso non compare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn accounts_of_sources(
        &self,
    ) -> ServiceResult<
        std::collections::BTreeMap<i64, Vec<lisi_core::model::monitoring_account::SourceAccount>>,
    > {
        Ok(self.database.source_accounts()?)
    }

    /// Aggiunge una fonte, verificandone prima l'accessibilità.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::SourceNotAccessible`] se la chat non risulta
    /// accessibile all'account o se non ne è leggibile lo storico, e
    /// [`ServiceError::SourceAlreadyConfigured`] se è già presente.
    pub fn add(
        &self,
        connector: &mut dyn TelegramConnector,
        chat_identifier: i64,
        authorized_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<SourceId> {
        // Verifica di accessibilita' PRIMA del salvataggio: l'elenco viene
        // dall'account, non dal chiamante.
        let accessible = connector.accessible_chats()?;
        let Some(chat) = accessible
            .into_iter()
            .find(|candidate| candidate.chat_id.get() == chat_identifier)
        else {
            return Err(ServiceError::SourceNotAccessible);
        };

        if !chat.is_monitorable() {
            return Err(ServiceError::SourceNotAccessible);
        }

        let kind = map_kind(chat.kind);
        let identifier = chat.chat_id.get().to_string();

        // Deduplicazione esplicita, per poter distinguere "gia' presente" da un
        // errore generico di vincolo.
        if self.database.find_source(kind, &identifier)?.is_some() {
            return Err(ServiceError::SourceAlreadyConfigured);
        }

        let new_source = NewSource {
            kind,
            identifier: SourceIdentifier::try_new(&identifier)?,
            display_name: DisplayName::try_new(&chat.title)?,
            authorized_by: authorized_by.clone(),
            active: true,
        };

        let id = match self.database.insert_source(&new_source, now) {
            Ok(id) => id,
            // Corsa fra la verifica e l'inserimento: il vincolo dello schema
            // resta l'autorita' finale.
            Err(StorageError::DuplicateSource) => {
                return Err(ServiceError::SourceAlreadyConfigured);
            }
            Err(other) => return Err(ServiceError::Storage(other)),
        };

        record_address(&self.database, id, chat.username.as_deref(), now);
        self.record_audit(authorized_by, "fonte_aggiunta", id, &chat.title, now)?;
        Ok(id)
    }

    /// Attiva o disattiva una fonte.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la fonte non esiste o se la scrittura non
    /// riesce.
    pub fn set_active(
        &self,
        id: SourceId,
        active: bool,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.set_source_active(id, active, now)?;

        let action = if active {
            "fonte_attivata"
        } else {
            "fonte_disattivata"
        };
        self.record_audit(actor, action, id, "", now)
    }

    /// Rimuove una fonte, o la disattiva se ha già partecipato a un
    /// monitoraggio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la fonte non esiste o se la scrittura non
    /// riesce.
    pub fn remove(
        &self,
        id: SourceId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<RemovalOutcome> {
        if self.database.source_is_used(id)? {
            self.database.set_source_active(id, false, now)?;
            self.record_audit(actor, "fonte_disattivata_perche_usata", id, "", now)?;
            return Ok(RemovalOutcome::Deactivated);
        }

        self.database.delete_unused_source(id)?;
        self.record_audit(actor, "fonte_rimossa", id, "", now)?;
        Ok(RemovalOutcome::Deleted)
    }

    /// Registra la modifica nell'audit append-only.
    ///
    /// Il dettaglio riporta il nome della fonte, che non è un segreto, e mai
    /// dati riservati.
    fn record_audit(
        &self,
        actor: &Actor,
        action: &str,
        id: SourceId,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = if detail.trim().is_empty() {
            None
        } else {
            Some(AuditDetail::try_new(detail)?)
        };

        let entry = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new("source")?,
            entity_id: Some(id.get()),
            // La gestione delle fonti non conosce la modalita' operativa, che
            // vive nel servizio dei dizionari: registrarne una qui sarebbe
            // inventarla. `None` significa «non registrata».
            actor_mode: None,
            detail,
            recorded_at: now,
        };

        self.database.append_audit(&entry)?;
        Ok(())
    }
}

/// Tipo di fonte, riesportato perché l'interfaccia possa mostrarlo senza
/// dipendere dalla persistenza.
pub use lisi_core::model::SourceKind;

/// Apre un database in memoria per la configurazione delle fonti.
///
/// In esercizio il database sarà quello persistente dell'applicazione. Esiste
/// qui perché l'interfaccia possa ottenerne uno senza dipendere da
/// `lisi-storage`, che il confine di ADR-0010 le vieta.
///
/// **Privato della connessione che lo apre**: due chiamate a questa funzione
/// restituiscono due archivi indipendenti. Per i test, dove serve una sola
/// connessione isolata, è la scelta giusta. Per il ripiego di avvio, dove più
/// servizi devono vedere gli stessi dati, non lo è: vedere
/// [`open_fallback_database`].
///
/// # Errori
///
/// Restituisce un errore se il database non è apribile.
pub fn open_in_memory_database() -> ServiceResult<Database> {
    Ok(Database::open_in_memory()?)
}

/// Registra l'indirizzo pubblico visto per una fonte (CONTEXT-02, ADR-0165),
/// soltanto se ha la forma di un indirizzo pubblico. Un errore non ferma chi
/// lo chiede: l'indirizzo serve ad «Apri la fonte», non alla fonte.
fn record_address(database: &Database, source: SourceId, username: Option<&str>, now: Timestamp) {
    let Some(indirizzo) = username.and_then(lisi_core::model::discovery::PublicAddress::try_new)
    else {
        return;
    };
    if let Err(errore) = database.record_source_address(source, indirizzo.as_str(), now) {
        tracing::warn!(errore = %errore, "indirizzo pubblico della fonte non registrato");
    }
}

/// Nome del database in memoria condiviso usato dal ripiego di avvio.
const FALLBACK_DATABASE_NAME: &str = "lisi-avvio-ripiego";

/// Apre una connessione al database condiviso di ripiego, usato quando
/// l'archivio persistente non è apribile all'avvio.
///
/// A differenza di [`open_in_memory_database`], connessioni diverse ottenute
/// da questa funzione **nello stesso processo** vedono lo stesso contenuto:
/// serve perché i servizi dipendenti dall'archivio (Account, Fonti, ...)
/// restino coerenti fra loro quando degradano insieme, invece di scrivere
/// ciascuno in un archivio isolato e reciprocamente invisibile. Il contenuto
/// non sopravvive alla chiusura dell'applicazione, come ogni archivio in
/// memoria.
///
/// # Errori
///
/// Restituisce un errore se la connessione non può essere aperta o
/// configurata.
pub fn open_fallback_database() -> ServiceResult<Database> {
    Ok(Database::open_shared_in_memory(FALLBACK_DATABASE_NAME)?)
}

/// Nome del file di archivio dell'applicazione.
pub const DATABASE_FILE: &str = "monitor.sqlite";

/// Apre l'archivio dell'applicazione, creandolo se manca.
///
/// Sta nella stessa cartella protetta dal profilo dove vivono le altre
/// configurazioni locali. Il nome della cartella viene da `lisi-core` ed è un
/// identificatore persistente.
///
/// # Perché un file e non la memoria, di norma
///
/// In memoria, ogni chiusura dell'applicazione perderebbe le fonti
/// configurate e i dizionari composti: è una ragione che l'operatore vede, e
/// vale sempre, a prescindere da quante connessioni condividano lo stesso
/// contenuto. Il file resta quindi la scelta normale; l'archivio condiviso in
/// memoria di [`open_fallback_database`] esiste solo per non lasciare
/// l'applicazione senza servizi quando il file non è apribile.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati non è determinabile o se
/// l'archivio non è apribile.
pub fn open_application_database() -> ServiceResult<Database> {
    let path = crate::data_directory::application_directory()?.join(DATABASE_FILE);
    Ok(Database::open(&path)?)
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
///
/// Un orologio non leggibile è una condizione remota ma reale; farne cadere
/// l'applicazione sarebbe sproporzionato. Prima qui si scriveva l'epoca, e
/// il commento diceva che un istante zero «è riconoscibile come anomalo in
/// un rapporto»: lo è, ma intanto era stato scritto
/// (FINAL-FPR-ALL-16, FPR-10). Ora l'istante viene dall'ancora dell'avvio,
/// che è lo stesso orologio contato in un altro modo.
fn now_or_epoch() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Costruisce l'attore dell'audit dal nome indicato.
fn actor_of(name: &str) -> ServiceResult<Actor> {
    Ok(Actor::try_new(name)?)
}

/// Aggiunge una fonte usando il nome di attore indicato.
///
/// # Errori
///
/// Come [`SourceService::add`].
pub fn add_with_default_actor(
    service: &SourceService,
    connector: &mut dyn TelegramConnector,
    chat_identifier: i64,
    actor_name: &str,
) -> ServiceResult<SourceId> {
    let actor = actor_of(actor_name)?;
    service.add(connector, chat_identifier, &actor, now_or_epoch())
}

/// Come [`add_with_default_actor`], ma ricevendo il **runtime** dell'account.
///
/// La facade che l'interfaccia usa: il connettore dell'account autorizzato resta
/// dentro i servizi e non attraversa il livello grafico (ADR-0010).
///
/// # Errori
///
/// Come [`SourceService::add`].
pub fn add_with_default_actor_for(
    service: &SourceService,
    runtime: &mut AccountRuntime,
    chat_identifier: i64,
    actor_name: &str,
) -> ServiceResult<SourceId> {
    let actor = actor_of(actor_name)?;
    service.add(
        runtime.connector_mut(),
        chat_identifier,
        &actor,
        now_or_epoch(),
    )
}

/// Attiva o disattiva una fonte usando il nome di attore indicato.
///
/// # Errori
///
/// Come [`SourceService::set_active`].
pub fn set_active_with_default_actor(
    service: &SourceService,
    source_id: i64,
    active: bool,
    actor_name: &str,
) -> ServiceResult<()> {
    let actor = actor_of(actor_name)?;
    service.set_active(SourceId::new(source_id), active, &actor, now_or_epoch())
}

/// Rimuove una fonte usando il nome di attore indicato.
///
/// # Errori
///
/// Come [`SourceService::remove`].
pub fn remove_with_default_actor(
    service: &SourceService,
    source_id: i64,
    actor_name: &str,
) -> ServiceResult<RemovalOutcome> {
    let actor = actor_of(actor_name)?;
    service.remove(SourceId::new(source_id), &actor, now_or_epoch())
}

/// Traduce la natura della chat nel tipo di fonte del dominio.
///
/// Le due enumerazioni vivono in crate diversi e non devono conoscersi: la
/// traduzione sta qui, in un solo punto, ed è coperta da un test.
const fn map_kind(kind: ChatKind) -> SourceKind {
    match kind {
        ChatKind::Channel => SourceKind::Channel,
        ChatKind::Group => SourceKind::Group,
        ChatKind::Supergroup => SourceKind::Supergroup,
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::SourceKind;
    use lisi_core::text::Actor;
    use lisi_core::{SourceId, Timestamp};
    use lisi_storage::Database;
    use lisi_telegram::{
        AccessibleChat, ChatId, ChatKind, ClientParameters, LoginCode, MockTelegramConnector,
        PhoneNumber, TelegramConnector,
    };

    use super::{RemovalOutcome, SourceService, map_kind};
    use crate::error::ServiceError;

    const READABLE_CHANNEL: i64 = -1_001_000_000_001;
    const UNREADABLE: i64 = -1_003_000_000_002;
    const NOT_ACCESSIBLE: i64 = -1_009_999_999_999;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn actor() -> Actor {
        let Ok(value) = Actor::try_new("responsabile.ufficio") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    fn service() -> SourceService {
        let Ok(database) = Database::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire");
        };
        SourceService::new(database)
    }

    /// Connettore simulato portato allo stato autorizzato.
    fn authorised_connector() -> MockTelegramConnector {
        let mut connector = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (
            lisi_telegram::ApiId::try_new(1),
            lisi_telegram::ApiHash::try_new("00000000000000000000000000000000"),
        ) else {
            panic!("i valori fittizi devono essere validi");
        };
        let parameters = ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("prova"),
            use_test_datacenter: true,
            application_version: String::from("0.1.0"),
            system_language_code: String::from("it"),
        };

        let (Ok(phone), Ok(code)) = (
            PhoneNumber::try_new("+390612345678"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori fittizi devono essere validi");
        };

        let (Ok(()), Ok(()), Ok(())) = (
            connector.start(&parameters),
            connector.submit_phone_number(&phone),
            connector.submit_code(&code),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };
        connector
    }

    #[test]
    fn two_services_on_the_same_file_see_the_same_sources() {
        // Il difetto che questo test impedisce di ripetere: ogni servizio
        // apriva un archivio *in memoria*, che e' privato della connessione che
        // lo ha creato. Fonti e Dizionari scrivevano in archivi diversi, e una
        // fonte configurata era invisibile al wizard che doveva monitorarla.
        let path = std::env::temp_dir().join(format!(
            "lisi-archivio-condiviso-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let (Ok(first), Ok(second)) = (Database::open(&path), Database::open(&path)) else {
            panic!("due connessioni allo stesso file devono potersi aprire");
        };

        let writer = SourceService::new(first);
        let reader = SourceService::new(second);
        let mut connector = authorised_connector();

        let Ok(_) = writer.add(&mut connector, READABLE_CHANNEL, &actor(), now()) else {
            panic!("la fonte deve potersi aggiungere");
        };

        let Ok(configured) = reader.configured() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(
            configured.len(),
            1,
            "il secondo servizio deve vedere la fonte scritta dal primo"
        );

        drop(writer);
        drop(reader);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn two_services_on_the_shared_fallback_database_see_the_same_sources() {
        // Il ripiego di avvio (M3B.2): quando l'archivio persistente non e'
        // apribile, i servizi devono condividere lo stesso archivio in
        // memoria invece di ottenerne ciascuno uno privato e isolato — lo
        // stesso difetto del test precedente, ma per il ripiego invece che
        // per il file. Solo questo test in tutto il crate usa
        // `open_fallback_database`: il nome condiviso e' fisso, e una
        // seconda chiamata concorrente da un altro test lo contaminerebbe.
        let (Ok(first), Ok(second)) = (
            super::open_fallback_database(),
            super::open_fallback_database(),
        ) else {
            panic!("due connessioni al ripiego condiviso devono potersi aprire");
        };

        let writer = SourceService::new(first);
        let reader = SourceService::new(second);
        let mut connector = authorised_connector();

        let Ok(_) = writer.add(&mut connector, READABLE_CHANNEL, &actor(), now()) else {
            panic!("la fonte deve potersi aggiungere");
        };

        let Ok(configured) = reader.configured() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(
            configured.len(),
            1,
            "il secondo servizio deve vedere la fonte scritta dal primo"
        );
    }

    #[test]
    fn every_chat_kind_maps_to_a_source_kind() {
        assert_eq!(map_kind(ChatKind::Channel), SourceKind::Channel);
        assert_eq!(map_kind(ChatKind::Group), SourceKind::Group);
        assert_eq!(map_kind(ChatKind::Supergroup), SourceKind::Supergroup);
    }

    #[test]
    fn available_for_lists_the_chats_of_the_mock_authorised_account() {
        use lisi_core::model::{AccountUuid, NewApiCredentialProfile, NewTelegramAccount};
        use lisi_core::text::DisplayName;

        use crate::accounts::AccountService;
        use lisi_security::ProtectedStore;

        use crate::acquisition_authority::StationAuthorityService;
        use crate::hub_client::HubConnectionStore;
        use crate::telegram_runtime::{AccountRuntime, RuntimeMode};

        // Un account fittizio nel servizio account, con il suo profilo.
        let Ok(accounts_db) = Database::open_in_memory() else {
            panic!("l'archivio degli account deve potersi aprire");
        };
        let accounts = AccountService::new(accounts_db);
        let Ok(label) = DisplayName::try_new("Account di prova") else {
            panic!("l'etichetta di prova deve essere valida");
        };
        let Ok(profile_id) = accounts.database().insert_api_profile(
            &NewApiCredentialProfile {
                label: label.clone(),
            },
            now(),
        ) else {
            panic!("il profilo di prova deve potersi inserire");
        };
        let Ok(account_id) = accounts.database().insert_telegram_account(
            &NewTelegramAccount {
                uuid: AccountUuid::from_bytes([0x33; 16]),
                label,
                profile_id,
            },
            now(),
        ) else {
            panic!("l'account di prova deve potersi inserire");
        };
        let Ok(account) = accounts.account(account_id) else {
            panic!("l'account deve potersi rileggere");
        };

        // Runtime mock portato fino ad autorizzato.
        let base = std::path::Path::new("base");
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let servizio_autorita = StationAuthorityService::new(HubConnectionStore::at(
            ProtectedStore::at(cartella.path().join("hub-client.protetto")),
        ));
        let (Ok(esito), ()) = (
            servizio_autorita.acquisition_authority(&crate::run_mode::operational_for_tests()),
            (),
        ) else {
            panic!("l'esito dell'autorità deve esserci");
        };
        let Some(autorita) = esito.into_granted() else {
            panic!("una postazione senza Hub configurato deve poter acquisire");
        };
        let Ok(mut runtime) =
            AccountRuntime::open(&accounts, &account, RuntimeMode::Mock, base, &autorita)
        else {
            panic!("il runtime mock deve potersi aprire");
        };
        let (Ok(phone), Ok(code)) = (
            PhoneNumber::try_new("+390612345678"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori fittizi devono essere validi");
        };
        let (Ok(()), Ok(()), Ok(())) = (
            runtime.start(&accounts, now()),
            runtime.submit_phone_number(phone, &accounts, now()),
            runtime.submit_code(code, &accounts, now()),
        ) else {
            panic!("il ciclo mock deve riuscire");
        };

        // Fonti ottiene le chat accessibili via la facade, senza toccare il
        // connettore: l'account autorizzato del login è lo stesso usato qui.
        let sources = service();
        let Ok(available) = sources.available_for(&mut runtime) else {
            panic!("le chat accessibili dell'account autorizzato devono arrivare");
        };
        assert!(
            !available.is_empty(),
            "l'account mock autorizzato espone le chat sintetiche"
        );
    }

    #[test]
    fn the_available_list_comes_from_the_account_and_marks_what_is_unusable() {
        let service = service();
        let mut connector = authorised_connector();

        let Ok(available) = service.available(&mut connector) else {
            panic!("l'elenco deve potersi ottenere");
        };
        assert_eq!(available.len(), 5);

        let unusable: Vec<_> = available
            .iter()
            .filter(|entry| entry.unavailable_reason.is_some())
            .collect();
        assert_eq!(unusable.len(), 1, "una sola chat e' senza storico");
        assert!(!unusable[0].can_be_added());
    }

    #[test]
    fn the_available_list_requires_an_authorised_account() {
        let service = service();
        let mut connector = MockTelegramConnector::new();

        // Senza accesso non esiste nulla a cui l'account abbia accesso.
        assert!(service.available(&mut connector).is_err());
    }

    #[test]
    fn a_source_is_added_and_appears_as_configured() {
        let service = service();
        let mut connector = authorised_connector();

        let Ok(id) = service.add(&mut connector, READABLE_CHANNEL, &actor(), now()) else {
            panic!("l'aggiunta deve riuscire");
        };

        let Ok(configured) = service.configured() else {
            panic!("l'elenco configurato deve potersi leggere");
        };
        assert_eq!(configured.len(), 1);
        assert_eq!(configured[0].id, id);
        assert_eq!(configured[0].kind, SourceKind::Channel);
        assert!(configured[0].active);
        assert_eq!(configured[0].authorized_by.as_str(), "responsabile.ufficio");

        let Ok(available) = service.available(&mut connector) else {
            panic!("l'elenco deve potersi ottenere");
        };
        let entry = available
            .iter()
            .find(|entry| entry.chat.chat_id.get() == READABLE_CHANNEL);
        assert!(entry.is_some_and(|entry| entry.already_configured));
    }

    #[test]
    fn a_chat_not_accessible_to_the_account_is_refused() {
        let service = service();
        let mut connector = authorised_connector();

        assert!(matches!(
            service.add(&mut connector, NOT_ACCESSIBLE, &actor(), now()),
            Err(ServiceError::SourceNotAccessible)
        ));
        assert_eq!(service.configured().map(|list| list.len()).ok(), Some(0));
    }

    #[test]
    fn a_chat_without_readable_history_is_refused() {
        let service = service();
        let mut connector = authorised_connector();

        assert!(matches!(
            service.add(&mut connector, UNREADABLE, &actor(), now()),
            Err(ServiceError::SourceNotAccessible)
        ));
    }

    #[test]
    fn adding_the_same_source_twice_is_reported_as_already_configured() {
        let service = service();
        let mut connector = authorised_connector();

        let Ok(_) = service.add(&mut connector, READABLE_CHANNEL, &actor(), now()) else {
            panic!("la prima aggiunta deve riuscire");
        };

        assert!(matches!(
            service.add(&mut connector, READABLE_CHANNEL, &actor(), now()),
            Err(ServiceError::SourceAlreadyConfigured)
        ));
        assert_eq!(service.configured().map(|list| list.len()).ok(), Some(1));
    }

    #[test]
    fn all_three_kinds_can_be_configured() {
        let service = service();
        let mut connector = authorised_connector();

        for chat in [READABLE_CHANNEL, -1_002_000_000_001, -1_003_000_000_001] {
            let Ok(_) = service.add(&mut connector, chat, &actor(), now()) else {
                panic!("la fonte {chat} deve potersi aggiungere");
            };
        }

        let Ok(configured) = service.configured() else {
            panic!("l'elenco deve potersi leggere");
        };
        let kinds: Vec<SourceKind> = configured.iter().map(|source| source.kind).collect();
        assert!(kinds.contains(&SourceKind::Channel));
        assert!(kinds.contains(&SourceKind::Group));
        assert!(kinds.contains(&SourceKind::Supergroup));
    }

    #[test]
    fn a_source_can_be_deactivated_and_reactivated() {
        let service = service();
        let mut connector = authorised_connector();
        let Ok(id) = service.add(&mut connector, READABLE_CHANNEL, &actor(), now()) else {
            panic!("l'aggiunta deve riuscire");
        };

        let Ok(()) = service.set_active(id, false, &actor(), now()) else {
            panic!("la disattivazione deve riuscire");
        };
        let Ok(configured) = service.configured() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert!(!configured[0].active);

        let Ok(()) = service.set_active(id, true, &actor(), now()) else {
            panic!("la riattivazione deve riuscire");
        };
        assert_eq!(
            service.configured().map(|list| list[0].active).ok(),
            Some(true)
        );
    }

    #[test]
    fn an_unused_source_is_really_removed() {
        let service = service();
        let mut connector = authorised_connector();
        let Ok(id) = service.add(&mut connector, READABLE_CHANNEL, &actor(), now()) else {
            panic!("l'aggiunta deve riuscire");
        };

        assert_eq!(
            service.remove(id, &actor(), now()).ok(),
            Some(RemovalOutcome::Deleted)
        );
        assert_eq!(service.configured().map(|list| list.len()).ok(), Some(0));
    }

    #[test]
    fn removing_a_missing_source_is_reported() {
        let service = service();
        assert!(service.remove(SourceId::new(404), &actor(), now()).is_err());
    }

    #[test]
    fn every_change_is_recorded_in_the_audit() {
        let service = service();
        let mut connector = authorised_connector();

        let Ok(id) = service.add(&mut connector, READABLE_CHANNEL, &actor(), now()) else {
            panic!("l'aggiunta deve riuscire");
        };
        let Ok(()) = service.set_active(id, false, &actor(), now()) else {
            panic!("la disattivazione deve riuscire");
        };
        let Ok(_) = service.remove(id, &actor(), now()) else {
            panic!("la rimozione deve riuscire");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();

        assert_eq!(
            actions,
            ["fonte_aggiunta", "fonte_disattivata", "fonte_rimossa"]
        );
        for entry in &entries {
            assert_eq!(entry.entity.as_str(), "source");
            assert_eq!(entry.actor.as_str(), "responsabile.ufficio");
        }
    }

    #[test]
    fn the_search_filters_locally_and_does_not_query_the_platform() {
        let service = service();
        let mut connector = authorised_connector();
        let Ok(available) = service.available(&mut connector) else {
            panic!("l'elenco deve potersi ottenere");
        };

        let by_title = SourceService::search(&available, "supergruppo");
        assert_eq!(by_title.len(), 2);

        let by_identifier = SourceService::search(&available, "1002000000001");
        assert_eq!(by_identifier.len(), 1);

        let nothing = SourceService::search(&available, "termine-che-non-esiste");
        assert!(nothing.is_empty());

        // Una ricerca vuota restituisce tutto: non e' un filtro.
        assert_eq!(
            SourceService::search(&available, "   ").len(),
            available.len()
        );
    }

    #[test]
    fn the_search_is_case_insensitive() {
        let service = service();
        let mut connector = authorised_connector();
        let Ok(available) = service.available(&mut connector) else {
            panic!("l'elenco deve potersi ottenere");
        };

        assert_eq!(
            SourceService::search(&available, "CANALE").len(),
            SourceService::search(&available, "canale").len()
        );
    }

    #[test]
    fn an_invalid_chat_identifier_is_refused() {
        let service = service();
        // Un elenco che contenga uno zero non e' costruibile: ChatId lo rifiuta.
        assert!(ChatId::try_new(0).is_err());

        let mut connector = authorised_connector();
        assert!(matches!(
            service.add(&mut connector, 0, &actor(), now()),
            Err(ServiceError::SourceNotAccessible)
        ));
    }

    #[test]
    fn a_custom_accessible_list_is_honoured() {
        let service = service();
        let Ok(chat_id) = ChatId::try_new(-1_005_000_000_001) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let mut connector =
            MockTelegramConnector::new().with_accessible_chats(vec![AccessibleChat {
                chat_id,
                title: String::from("Fonte sintetica unica"),
                kind: ChatKind::Channel,
                username: None,
                can_read_history: true,
            }]);

        // Porta all'autorizzazione.
        let (Ok(api_id), Ok(api_hash)) = (
            lisi_telegram::ApiId::try_new(1),
            lisi_telegram::ApiHash::try_new("00000000000000000000000000000000"),
        ) else {
            panic!("i valori fittizi devono essere validi");
        };
        let parameters = ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("prova"),
            use_test_datacenter: true,
            application_version: String::from("0.1.0"),
            system_language_code: String::from("it"),
        };
        let (Ok(phone), Ok(code)) = (
            PhoneNumber::try_new("+390612345678"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori fittizi devono essere validi");
        };
        let (Ok(()), Ok(()), Ok(())) = (
            connector.start(&parameters),
            connector.submit_phone_number(&phone),
            connector.submit_code(&code),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };

        let Ok(available) = service.available(&mut connector) else {
            panic!("l'elenco deve potersi ottenere");
        };
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].chat.title, "Fonte sintetica unica");
    }

    #[test]
    fn each_removal_outcome_explains_itself_to_the_operator() {
        assert!(
            RemovalOutcome::Deleted
                .operator_message()
                .contains("rimossa")
        );
        let deactivated = RemovalOutcome::Deactivated.operator_message();
        assert!(deactivated.contains("disattivata"));
        assert!(deactivated.contains("riconducibili"));
    }

    /// **L'indirizzo pubblico si registra all'aggiunta e si aggiorna a ogni
    /// lettura dell'elenco; un nome che non ha la forma di un indirizzo
    /// pubblico non si registra** (CONTEXT-02, criterio 3).
    #[test]
    fn l_indirizzo_pubblico_si_registra_e_si_aggiorna() {
        let chat = |nome: Option<&str>| {
            let Ok(chat_id) = ChatId::try_new(READABLE_CHANNEL) else {
                panic!("identificativo valido");
            };
            AccessibleChat {
                chat_id,
                title: String::from("Canale di prova"),
                kind: ChatKind::Channel,
                username: nome.map(str::to_owned),
                can_read_history: true,
            }
        };
        let fonti = service();
        let mut connettore = authorised_connector().with_accessible_chats(vec![chat(Some("x"))]);
        let Ok(id) = fonti.add(&mut connettore, READABLE_CHANNEL, &actor(), now()) else {
            panic!("la fonte deve aggiungersi");
        };
        let mut connettore =
            authorised_connector().with_accessible_chats(vec![chat(Some("canale_cyber"))]);
        let Ok(_) = fonti.available(&mut connettore) else {
            panic!("l'elenco deve leggersi");
        };
        let archivio = fonti.into_database();
        let Ok(Some(visto)) = archivio.source_address(id) else {
            panic!("l'indirizzo visto nell'elenco deve esserci");
        };
        assert_eq!(visto.address, "canale_cyber");

        let fonti = SourceService::new(archivio);
        let mut connettore =
            authorised_connector().with_accessible_chats(vec![chat(Some("canale_nuovo"))]);
        let Ok(_) = fonti.available(&mut connettore) else {
            panic!("l'elenco deve leggersi");
        };
        let archivio = fonti.into_database();
        assert_eq!(
            archivio
                .source_address(id)
                .ok()
                .flatten()
                .map(|v| v.address),
            Some(String::from("canale_nuovo")),
            "l'ultimo nome visto sostituisce il precedente"
        );
    }
}

//! Apertura sicura dei collegamenti.
//!
//! L'URL arriva dall'interfaccia come stringa grezza — ha attraversato Slint —
//! e da un contenuto remoto, cioè ostile per ipotesi. Prima di aprirlo lo si
//! **rivalida attraverso `ContentUrl`**, la stessa validazione dell'acquisizione
//! (una sola fonte di verità), poi lo si apre nel browser predefinito e se ne
//! lascia traccia. Le scelte sono in `docs/adr/ADR-0018-SECURE-URL-OPENING.md`.
//!
//! Il destinatario dell'apertura è **iniettabile**: in esercizio quello di
//! sistema (`lisi-platform`), nei test uno che registra invece di aprire. Così
//! la validazione e l'audit sono provati senza aprire alcun browser.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, ContentUrl};
use lisi_platform::PlatformError;
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Destinatario dell'apertura di un collegamento.
pub trait LinkOpener {
    /// Apre l'URL indicato.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della piattaforma se l'apertura non riesce.
    fn open(&self, url: &str) -> Result<(), PlatformError>;
}

/// Apertura reale: nell'applicazione Telegram se il collegamento è a un
/// messaggio monitorato, altrimenti nel browser predefinito.
///
/// La scelta fra le due strade la fa `lisi-platform`, che riconosce la forma
/// prodotta dal calcolo del permalink e **rifiuta tutto il resto**. Un URL
/// trovato dentro un contenuto acquisito non può quindi far avviare alcun
/// programma diverso dal browser: la distinzione è di provenienza, non di
/// fiducia, ed è motivata nella revisione di ADR-0018.
#[derive(Debug, Default)]
pub struct SystemLinkOpener;

impl LinkOpener for SystemLinkOpener {
    fn open(&self, url: &str) -> Result<(), PlatformError> {
        lisi_platform::open_message(url)
    }
}

/// Servizio dei collegamenti.
#[derive(Debug)]
pub struct LinkService {
    database: Database,
}

impl LinkService {
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

    /// Apre un URL nel browser, dopo averlo validato, e ne lascia traccia.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::LinkNotOpened`] se l'URL non è un indirizzo
    /// web valido o se il sistema rifiuta l'apertura; un errore di persistenza
    /// se la registrazione non riesce.
    pub fn open_url(
        &self,
        url: &str,
        actor: &Actor,
        now: Timestamp,
        opener: &dyn LinkOpener,
    ) -> ServiceResult<()> {
        // Rivalida attraverso ContentUrl: schema web, niente spazi o caratteri
        // di controllo, lunghezza massima. Non si apre ciò che non passa.
        let validated = ContentUrl::try_new(url).map_err(|_| ServiceError::LinkNotOpened {
            reason: "non è un indirizzo web valido",
        })?;

        opener.open(validated.as_str()).map_err(map_platform)?;
        self.audit(validated.as_str(), actor, now)?;
        Ok(())
    }

    /// Registra nell'audit l'apertura di un collegamento.
    ///
    /// Il dettaglio è l'URL aperto: registrare *dove* è andato l'operatore è lo
    /// scopo della traccia. L'URL è già nell'archivio del contenuto, quindi non
    /// vi si aggiunge nulla di nuovo.
    fn audit(&self, url: &str, actor: &Actor, now: Timestamp) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("collegamento_aperto")?,
            entity: AuditEntity::try_new("collegamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(url)?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

/// Traduce un errore della piattaforma, con un motivo costante.
fn map_platform(error: PlatformError) -> ServiceError {
    let reason = match error {
        PlatformError::UnsupportedScheme => "schema non ammesso",
        PlatformError::MalformedUrl => "indirizzo malformato",
        PlatformError::LaunchFailed { .. } => "il sistema ha rifiutato l'apertura",
        PlatformError::Unsupported => "non supportato su questa postazione",
        // `open_message` ripiega da sé sul browser quando Telegram non è
        // installato, quindi questo errore non esce dalla piattaforma su
        // questo percorso. Se un giorno uscisse, il motivo dice la cosa giusta
        // all'operatore invece di un messaggio generico.
        PlatformError::NoAssociatedApplication => {
            "nessuna applicazione associata a questo collegamento"
        }
        // Errori che appartengono ad **altre** capacità della piattaforma — la
        // cornice della finestra, lo stato di sospensione — e che aprire un
        // collegamento non può produrre.
        //
        // Restano enumerati invece che raccolti in un `_`: il carattere
        // esaustivo di questo `match` ha già fermato la compilazione tre volte
        // mentre la piattaforma cresceva, e ogni volta ha costretto a decidere
        // che cosa dire all'operatore invece di lasciar passare in silenzio un
        // errore tradotto a caso. È un fastidio che vale il proprio prezzo, e
        // un `_` lo toglierebbe insieme alla protezione.
        PlatformError::WindowUnavailable
        | PlatformError::WindowAttributeRefused
        | PlatformError::WakefulnessRefused
        | PlatformError::AutostartUnavailable { .. }
        | PlatformError::AppIdentityRefused { .. }
        | PlatformError::ToastRefused { .. }
        | PlatformError::BackgroundService { .. }
        | PlatformError::NotAFolder => "il sistema ha rifiutato l'apertura",
    };
    ServiceError::LinkNotOpened { reason }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use lisi_core::Timestamp;
    use lisi_core::text::Actor;
    use lisi_platform::PlatformError;

    use super::{LinkOpener, LinkService};
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn service() -> LinkService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        LinkService::new(database)
    }

    /// Destinatario di prova: registra ciò che gli si chiede di aprire.
    #[derive(Default)]
    struct RecordingOpener {
        opened: RefCell<Vec<String>>,
    }

    impl LinkOpener for RecordingOpener {
        fn open(&self, url: &str) -> Result<(), PlatformError> {
            self.opened.borrow_mut().push(url.to_owned());
            Ok(())
        }
    }

    #[test]
    fn a_valid_url_is_opened_and_recorded() {
        let service = service();
        let opener = RecordingOpener::default();

        let Ok(()) = service.open_url("https://t.me/canale/1", &operator(), now(), &opener) else {
            panic!("un url valido deve potersi aprire");
        };

        assert_eq!(opener.opened.borrow().as_slice(), ["https://t.me/canale/1"]);

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            entries
                .iter()
                .any(|entry| entry.action.as_str() == "collegamento_aperto"),
            "l'apertura va registrata"
        );
    }

    #[test]
    fn a_non_web_url_is_never_handed_to_the_opener() {
        // La prova che conta: un url non-web non raggiunge nemmeno il
        // destinatario. La validazione lo ferma prima.
        let service = service();
        let opener = RecordingOpener::default();

        for dangerous in [
            "file:///C:/Windows/System32/cmd.exe",
            "javascript:alert(1)",
            "ftp://example.invalid/x",
            "C:\\Windows\\System32\\calc.exe",
            "non un url",
        ] {
            assert!(
                matches!(
                    service.open_url(dangerous, &operator(), now(), &opener),
                    Err(ServiceError::LinkNotOpened { .. })
                ),
                "'{dangerous}' doveva essere rifiutato"
            );
        }
        assert!(
            opener.opened.borrow().is_empty(),
            "nessun url non-web deve raggiungere il destinatario"
        );
    }

    #[test]
    fn a_failure_from_the_opener_is_reported_and_not_recorded() {
        // Se il sistema rifiuta l'apertura, si segnala e NON si registra un
        // successo che non è avvenuto.
        struct FailingOpener;
        impl LinkOpener for FailingOpener {
            fn open(&self, _url: &str) -> Result<(), PlatformError> {
                Err(PlatformError::LaunchFailed { code: 2 })
            }
        }

        let service = service();
        assert!(matches!(
            service.open_url("https://t.me/x", &operator(), now(), &FailingOpener),
            Err(ServiceError::LinkNotOpened { .. })
        ));

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            !entries
                .iter()
                .any(|entry| entry.action.as_str() == "collegamento_aperto"),
            "un'apertura non riuscita non va registrata come avvenuta"
        );
    }
}

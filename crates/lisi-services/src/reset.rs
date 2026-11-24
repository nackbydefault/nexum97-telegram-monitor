//! Rimozione di account e profili, e azzeramento dell'archivio.
//!
//! # Perché la cancellazione di una riga non basta
//!
//! Un account Telegram non vive solo nel database. Sul disco restano la chiave
//! di cifratura del suo archivio TDLib e — soprattutto — la cartella
//! `accounts/<uuid>/tdlib/` con `td.binlog`, cioè **la sessione Telegram
//! autorizzata**. Cancellare la riga e lasciare quei file produrrebbe una
//! sessione autorizzata orfana: un buco di sicurezza peggiore del problema che
//! il comando vuole risolvere, perché nessuna schermata la mostrerebbe più e
//! nessuno saprebbe che esiste.
//!
//! Le funzioni di questo modulo rimuovono quindi **prima i file, poi la riga**,
//! e riferiscono che cosa non sono riuscite a togliere invece di dichiarare un
//! successo parziale.
//!
//! # Perché l'archivio si azzera invece di essere ripulito
//!
//! Lo schema vieta di cancellare i contenuti registrati e le voci d'audit, con
//! trigger che abortiscono l'operazione (`content_versions_are_not_deleted`,
//! `audit_refuses_delete`). Non è una limitazione da aggirare: è la garanzia,
//! dichiarata nel rapporto di validazione, che un contenuto registrato non
//! possa essere alterato o fatto sparire.
//!
//! L'azzeramento non tocca quei trigger. **Chiude un archivio e ne apre un
//! altro**: l'immutabilità resta vera per tutta la vita di ciascun archivio, e
//! azzerare significa ricominciare da capo, non correggere il passato.
//!
//! # Perché un'esportazione con impronta non sostituisce l'append-only
//!
//! Il manifest di questo prodotto è **un'impronta, non una firma**: prova che
//! un file corrisponde al proprio manifest, non che quel file sia l'originale
//! completo. Chi cancellasse l'audit, ne esportasse una parte e ne calcolasse
//! l'impronta otterrebbe un manifest valido di un documento incompleto.
//!
//! La continuità si ottiene in un altro modo: l'audit viene **archiviato**, e
//! la prima riga del nuovo audit dichiara quante voci sono state archiviate e
//! con quale impronta. Se qualcuno distrugge il file archiviato, l'audit vivo
//! continua a dire che esisteva, quanto era grande e che impronta aveva. Non si
//! riscrive la storia: si chiude un volume e se ne apre un altro, e il nuovo
//! dichiara quale ha chiuso.

use std::path::{Path, PathBuf};

use lisi_core::text::Actor;
use lisi_core::{TelegramAccountId, Timestamp};

use crate::accounts::AccountService;
use crate::config::profile_store_path;
use crate::error::ServiceResult;
use crate::telegram_runtime::AccountPaths;

/// Esito della rimozione di uno o più account.
///
/// Riferisce anche ciò che **non** è stato rimosso: dichiarare un successo
/// quando un file protetto è rimasto sul disco sarebbe la cosa peggiore che
/// questo modulo possa fare, perché l'operatore smetterebbe di cercarlo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovalOutcome {
    /// Account rimossi dal database.
    pub accounts_removed: usize,
    /// Profili di credenziali rimossi.
    pub profiles_removed: usize,
    /// Cartelle di sessione TDLib rimosse dal disco.
    pub session_directories_removed: usize,
    /// File protetti che non è stato possibile rimuovere.
    ///
    /// Ogni voce è un **percorso**, non un segreto: i file protetti non vengono
    /// aperti né letti da questo modulo.
    pub files_left_behind: Vec<PathBuf>,
}

impl RemovalOutcome {
    /// Se qualcosa è rimasto sul disco.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.files_left_behind.is_empty()
    }

    /// Messaggio per l'operatore, che non promette piu' di quanto sia avvenuto.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let base = format!(
            "Rimossi {} account e {} profili, con {} sessioni Telegram dal disco.",
            self.accounts_removed, self.profiles_removed, self.session_directories_removed
        );
        if self.is_complete() {
            format!("{base} Il registro delle operazioni conserva la traccia delle rimozioni.")
        } else {
            format!(
                "{base} ATTENZIONE: {} file protetti non sono stati rimossi e restano sul \
                 disco. Vanno cancellati a mano.",
                self.files_left_behind.len()
            )
        }
    }
}

/// Rimuove dal disco i file di un singolo account.
///
/// Non tocca il database: la riga la cancella [`AccountService::remove_account`]
/// dopo, cosi' che un file rimasto non passi inosservato perche' la riga era
/// gia' sparita.
fn purge_account_files(
    base_dir: &Path,
    account: &lisi_core::model::TelegramAccount,
    outcome: &mut RemovalOutcome,
) {
    let paths = AccountPaths::new(base_dir, &account.uuid);

    // La radice contiene la cartella TDLib, quella dei file e la chiave: si
    // rimuove per intero, cosi' non resta nulla di parziale.
    if paths.root.exists() {
        if std::fs::remove_dir_all(&paths.root).is_ok() {
            outcome.session_directories_removed += 1;
        } else {
            outcome.files_left_behind.push(paths.root.clone());
        }
    }
}

/// Rimuove un solo account: i suoi file, la sua sessione e la sua riga.
///
/// Il profilo delle credenziali **non** viene toccato: puo' servire ad altri
/// account. Lo rimuove [`reset_accounts_and_profiles`], che sa di stare
/// azzerando tutto.
///
/// # Errori
///
/// Restituisce un errore se l'account non esiste o se la cancellazione della
/// riga non riesce. I file gia' rimossi restano rimossi: e' la direzione meno
/// dannosa, perche' un file di sessione che sopravvive a una riga cancellata
/// sarebbe invisibile.
pub fn remove_account(
    accounts: &AccountService,
    base_dir: &Path,
    account_id: TelegramAccountId,
    actor: &Actor,
    now: Timestamp,
) -> ServiceResult<RemovalOutcome> {
    let account = accounts.account(account_id)?;
    let mut outcome = RemovalOutcome::default();

    purge_account_files(base_dir, &account, &mut outcome);
    accounts.remove_account(account_id, actor, now)?;
    outcome.accounts_removed = 1;

    Ok(outcome)
}

/// Azzera tutti gli account e tutti i profili di credenziali.
///
/// L'ordine non e' indifferente: prima gli account con i loro file, poi i
/// profili. Un profilo rimosso mentre un account lo referenzia lascerebbe un
/// account senza credenziali invece di un archivio pulito.
///
/// # Errori
///
/// Restituisce un errore se la lettura o una cancellazione non riesce. L'esito
/// riferisce comunque quanto e' stato rimosso fino a quel punto.
pub fn reset_accounts_and_profiles(
    accounts: &AccountService,
    base_dir: &Path,
    actor: &Actor,
    now: Timestamp,
) -> ServiceResult<RemovalOutcome> {
    let mut outcome = RemovalOutcome::default();

    for account in accounts.accounts()? {
        purge_account_files(base_dir, &account, &mut outcome);
        accounts.remove_account(account.id, actor, now)?;
        outcome.accounts_removed += 1;
    }

    for profile in accounts.api_profiles()? {
        let stored = profile_store_path(base_dir, profile.id);
        if stored.exists() && std::fs::remove_file(&stored).is_err() {
            outcome.files_left_behind.push(stored);
        }
        accounts.remove_api_profile(profile.id, actor, now)?;
        outcome.profiles_removed += 1;
    }

    Ok(outcome)
}

/// Esito dell'archiviazione dell'audit prima di un azzeramento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditArchive {
    /// File in cui l'audit è stato scritto.
    pub path: PathBuf,
    /// Quante voci sono state archiviate.
    pub entries: usize,
    /// Impronta del file archiviato.
    pub digest: lisi_core::Sha256Digest,
}

impl AuditArchive {
    /// Riga che il nuovo audit conserva per dichiarare che cosa è stato chiuso.
    ///
    /// È il punto su cui poggia l'intera continuità: se il file archiviato
    /// venisse distrutto, l'audit vivo continuerebbe a dire che esisteva,
    /// quante voci conteneva e con quale impronta. Non si riscrive la storia,
    /// si chiude un volume e se ne apre un altro dichiarando quale.
    #[must_use]
    pub fn continuity_record(&self) -> String {
        format!(
            "audit archiviato: {} voci, impronta {}",
            self.entries,
            self.digest.as_str()
        )
    }
}

/// Scrive l'audit corrente in un file e ne calcola l'impronta.
///
/// **Non** azzera nulla: prepara la riga di continuità che il nuovo archivio
/// dovrà conservare. Separare le due cose fa sì che un'archiviazione fallita
/// impedisca l'azzeramento, invece di lasciare un archivio azzerato e nessuna
/// traccia di che cosa conteneva.
///
/// # Errori
///
/// Restituisce un errore se l'audit non è leggibile o se il file non è
/// scrivibile. In entrambi i casi l'azzeramento **non va eseguito**.
pub fn archive_audit(
    accounts: &AccountService,
    destination: &Path,
    now: Timestamp,
) -> ServiceResult<AuditArchive> {
    let entries = accounts.database().audit_entries()?;

    let mut rendered = String::from(
        "# Audit archiviato da NEXUM/97\n\
         # Ogni riga: istante, attore, azione, entità, identificativo.\n",
    );
    rendered.push_str(&format!("# Archiviato il {}\n", now.to_readable_utc()));
    for entry in &entries {
        rendered.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            entry.recorded_at.to_readable_utc(),
            entry.actor.as_str(),
            entry.action.as_str(),
            entry.entity.as_str(),
            entry.entity_id.unwrap_or(0)
        ));
    }

    let bytes = rendered.into_bytes();
    let digest = lisi_core::Sha256Digest::of_bytes(&bytes);

    // DEL SOLO UTENTE, O NIENTE (SEC-02, ADR-0157): è il registro intero di
    // chi ha fatto che cosa. Se non si protegge, non si scrive, e
    // l'azzeramento non avviene.
    let (Some(cartella), Some(nome)) = (
        destination.parent(),
        destination
            .file_name()
            .map(|nome| nome.to_string_lossy().into_owned()),
    ) else {
        return Err(crate::error::ServiceError::ExportNotWritten {
            reason: String::from("il percorso del registro non indica un file"),
        });
    };
    crate::protected_output::Delivery::begin(
        cartella,
        &nome,
        "Il registro delle operazioni NON è stato archiviato, e l'azzeramento non avverrà",
    )
    .and_then(|mut consegna| {
        consegna.write(&nome, &bytes)?;
        consegna.deliver(crate::protected_output::Existing::Replace)
    })
    .map_err(|errore| match errore {
        crate::error::ServiceError::ProtectionNotGuaranteed { .. } => errore,
        _ => crate::error::ServiceError::ExportNotWritten {
            reason: String::from(
                "il registro delle operazioni non è stato scritto nel file indicato",
            ),
        },
    })?;

    Ok(AuditArchive {
        path: destination.to_path_buf(),
        entries: entries.len(),
        digest,
    })
}

/// Nome del marcatore che chiede l'azzeramento al prossimo avvio.
const RESET_MARKER: &str = "azzeramento-richiesto.txt";

/// Nome del file in cui l'audit viene archiviato.
const AUDIT_ARCHIVE_PREFIX: &str = "audit-archiviato-";

/// Se un azzeramento è stato richiesto e non è ancora avvenuto.
///
/// Fra la richiesta e l'avvio successivo che la esegue può passare un tempo
/// qualunque, e in quell'intervallo nulla lo diceva: l'archivio appariva
/// intatto perché lo era, e la cancellazione arrivava dopo, magari a un avvio
/// provocato da qualcun altro. Un'operazione distruttiva in attesa deve
/// **vedersi** per tutto il tempo in cui è in attesa.
#[must_use]
pub fn reset_is_pending(data_dir: &Path) -> bool {
    data_dir.join(RESET_MARKER).exists()
}

/// Chiede l'azzeramento dell'archivio al prossimo avvio.
///
/// **Non azzera nulla adesso, ed è deliberato.** Ogni servizio
/// dell'applicazione tiene la propria connessione allo stesso file SQLite —
/// account, fonti, dizionari, monitoraggio, storico, notifiche, acquisizione.
/// Cancellare il file mentre sono aperte lascerebbe metà applicazione a
/// scrivere su un archivio che non esiste più, con una finestra in cui il
/// prodotto perde dati senza accorgersene. L'azzeramento avviene invece
/// all'avvio successivo, **prima** che qualunque servizio apra il file.
///
/// L'audit viene archiviato **ora**, mentre l'archivio è ancora leggibile: se
/// l'archiviazione non riesce, il marcatore non viene scritto e l'azzeramento
/// non avverrà. Meglio un azzeramento non eseguito che uno eseguito senza
/// traccia di che cosa conteneva.
///
/// # Errori
///
/// Restituisce un errore se l'audit non è archiviabile o se il marcatore non è
/// scrivibile. In entrambi i casi l'archivio resta intatto.
pub fn request_archive_reset(
    accounts: &AccountService,
    data_dir: &Path,
    now: Timestamp,
) -> ServiceResult<AuditArchive> {
    let archive_path = data_dir.join(format!(
        "{AUDIT_ARCHIVE_PREFIX}{}.txt",
        now.as_millis().max(0)
    ));
    let archive = archive_audit(accounts, &archive_path, now)?;

    // Il marcatore porta con sé la riga di continuità: al prossimo avvio
    // l'archivio sarà vuoto e nessuno potrebbe più ricavarla.
    std::fs::write(data_dir.join(RESET_MARKER), archive.continuity_record()).map_err(|_| {
        crate::error::ServiceError::ExportNotWritten {
            reason: String::from("la richiesta di azzeramento non è stata registrata"),
        }
    })?;

    Ok(archive)
}

/// Esegue l'azzeramento richiesto, se ce n'è uno in attesa.
///
/// Va chiamata **prima** di aprire l'archivio, all'avvio. Restituisce la riga
/// di continuità da registrare nel nuovo audit, o `None` se non c'era nulla da
/// azzerare.
///
/// Un marcatore illeggibile o un archivio non cancellabile non fermano l'avvio:
/// l'applicazione riparte con l'archivio che trova, e il marcatore resta perché
/// il tentativo si ripeta. Fermare l'avvio lascerebbe l'operatore senza
/// strumento e senza modo di rimediare.
#[must_use]
pub fn apply_pending_reset(data_dir: &Path) -> Option<String> {
    let marker = data_dir.join(RESET_MARKER);
    let record = std::fs::read_to_string(&marker).ok()?;

    // SQLite tiene accanto al file principale il journal e la cache condivisa:
    // lasciarne uno dei tre ricostruirebbe parte del contenuto appena
    // cancellato.
    let database = data_dir.join(crate::sources::DATABASE_FILE);
    for suffix in ["", "-wal", "-shm"] {
        let mut path = database.clone();
        if !suffix.is_empty() {
            let mut name = path.file_name()?.to_os_string();
            name.push(suffix);
            path.set_file_name(name);
        }
        if path.exists() && std::fs::remove_file(&path).is_err() {
            // Non si toglie il marcatore: il tentativo va ripetuto.
            return None;
        }
    }

    // I file degli account e i profili protetti vivono **fuori** dal database:
    // cancellare solo l'archivio lasciava sul disco le sessioni TDLib e le
    // credenziali di profilo, mentre l'interfaccia dichiarava che account e
    // profili erano stati cancellati. Una sessione TDLib rimasta non e' un
    // residuo qualunque: chi la copia rientra nell'account senza numero ne'
    // codice. Rilevato il 2026-08-04 confrontando la cartella dati con cio'
    // che il prodotto dichiarava.
    purge_account_and_profile_files(data_dir);

    let _ = std::fs::remove_file(&marker);
    Some(record)
}

/// Rimuove dal disco le cartelle degli account e i file protetti dei profili.
///
/// È chiamata all'avvio, quando il database non è più leggibile perché è
/// appena stato cancellato: gli elementi si riconoscono quindi per **posizione
/// e nome**, non interrogando l'archivio.
///
/// Non tocca il registro né gli audit archiviati: il primo non contiene dati
/// dell'archivio, e i secondi sono la catena di continuità che l'audit vivo
/// dichiara.
///
/// **Best-effort dichiarato:** un file che non si lascia cancellare — perché
/// aperto da un altro processo, o per i permessi — non ferma l'avvio, che
/// altrimenti lascerebbe l'operatore senza strumento e senza rimedio. Ciò che
/// resta viene registrato, perché un residuo silenzioso è il difetto che
/// questa funzione esiste per correggere.
fn purge_account_and_profile_files(data_dir: &Path) {
    let accounts = data_dir.join(crate::telegram_runtime::ACCOUNTS_DIR);
    if accounts.exists() && std::fs::remove_dir_all(&accounts).is_err() {
        tracing::warn!("azzeramento: la cartella degli account non e' stata rimossa per intero");
    }

    let Ok(entries) = std::fs::read_dir(data_dir) else {
        tracing::warn!("azzeramento: la cartella dati non e' leggibile, profili non rimossi");
        return;
    };

    let mut left_behind = 0_usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(crate::config::PROFILE_FILE_PREFIX)
            && name.ends_with(crate::config::PROFILE_FILE_SUFFIX)
            && std::fs::remove_file(entry.path()).is_err()
        {
            left_behind += 1;
        }
    }

    if left_behind > 0 {
        tracing::warn!(
            rimasti = left_behind,
            "azzeramento: alcuni file protetti di profilo non sono stati rimossi"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditArchive, RemovalOutcome, apply_pending_reset, remove_account, request_archive_reset,
        reset_accounts_and_profiles,
    };

    /// **SEC-02: il registro delle operazioni archiviato prima di un
    /// azzeramento è del solo utente, o non si scrive, e l'azzeramento non
    /// avviene** (ADR-0157). È il registro intero di chi ha fatto che cosa.
    /// Vista rossa il 2026-10-22 con la protezione tolta (mutazione di SEC-02).
    #[cfg(windows)]
    #[test]
    fn il_registro_archiviato_e_del_solo_utente_o_non_si_scrive() {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let accounts = crate::accounts::AccountService::new(database);
        let adesso = lisi_core::Timestamp::from_millis(1_700_000_000_000);
        crate::permessi_di_prova::prova_un_uscita("registro archiviato", |cartella| {
            let file = cartella.join("audit-archiviato.txt");
            super::archive_audit(&accounts, &file, adesso).map(|archivio| vec![archivio.path])
        });
    }

    #[test]
    fn an_incomplete_removal_never_reports_itself_as_done() {
        let complete = RemovalOutcome {
            accounts_removed: 2,
            profiles_removed: 1,
            session_directories_removed: 2,
            files_left_behind: Vec::new(),
        };
        assert!(complete.is_complete());
        assert!(
            !complete.operator_message().contains("ATTENZIONE"),
            "una rimozione completa non deve allarmare"
        );

        let partial = RemovalOutcome {
            accounts_removed: 1,
            profiles_removed: 0,
            session_directories_removed: 0,
            files_left_behind: vec![std::path::PathBuf::from("C:\\qualcosa\\rimasto")],
        };
        assert!(!partial.is_complete());
        let message = partial.operator_message();
        assert!(
            message.contains("ATTENZIONE") && message.contains("a mano"),
            "un file rimasto sul disco deve essere dichiarato, altrimenti \
             l'operatore smette di cercarlo: {message}"
        );
    }

    /// Il messaggio non deve promettere una cancellazione totale: l'audit
    /// resta, per scelta, e dirlo evita che l'operatore creda il contrario.
    #[test]
    fn the_message_says_that_the_audit_survives() {
        let outcome = RemovalOutcome {
            accounts_removed: 1,
            ..RemovalOutcome::default()
        };
        assert!(
            outcome
                .operator_message()
                .contains("registro delle operazioni")
        );
    }

    /// La riga di continuita' deve portare **entrambi** i dati che rendono
    /// verificabile cio' che e' stato chiuso: quante voci e con quale impronta.
    /// Solo il conteggio si potrebbe falsificare riscrivendo il file; solo
    /// l'impronta non direbbe se il file e' completo.
    #[test]
    fn the_continuity_record_carries_both_the_count_and_the_digest() {
        let digest = lisi_core::Sha256Digest::of_bytes(b"audit di prova");
        let archive = AuditArchive {
            path: std::path::PathBuf::from("audit.txt"),
            entries: 128,
            digest: digest.clone(),
        };

        let record = archive.continuity_record();
        assert!(
            record.contains("128"),
            "la riga deve dire quante voci sono state archiviate: {record}"
        );
        assert!(
            record.contains(digest.as_str()),
            "la riga deve portare l'impronta del file archiviato: {record}"
        );
    }

    /// Un audit vuoto non e' un errore, ed e' anzi il caso di un archivio
    /// appena creato: la riga di continuita' deve dirlo, non tacere.
    #[test]
    fn an_empty_audit_still_produces_a_declarable_record() {
        let archive = AuditArchive {
            path: std::path::PathBuf::from("audit.txt"),
            entries: 0,
            digest: lisi_core::Sha256Digest::of_bytes(b""),
        };
        let record = archive.continuity_record();
        assert!(record.contains('0'));
        assert!(!record.is_empty());
    }

    /// Cartella di prova, propria di ogni test.
    fn scratch(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "nexum-reset-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        let Ok(()) = std::fs::create_dir_all(&directory) else {
            panic!("la cartella di prova deve potersi creare");
        };
        directory
    }

    /// L'azzeramento deve togliere **anche** il journal e la cache condivisa di
    /// SQLite: lasciarne uno dei tre ricostruirebbe parte del contenuto appena
    /// cancellato, e l'operatore crederebbe di aver azzerato.
    #[test]
    fn the_reset_removes_the_journal_and_the_shared_cache_too() {
        let directory = scratch("wal");
        let database = directory.join(crate::sources::DATABASE_FILE);
        for suffix in ["", "-wal", "-shm"] {
            let mut path = database.clone();
            if !suffix.is_empty() {
                let Some(name) = path.file_name().map(std::ffi::OsStr::to_os_string) else {
                    panic!("il nome del file deve esistere");
                };
                let mut name = name;
                name.push(suffix);
                path.set_file_name(name);
            }
            let Ok(()) = std::fs::write(&path, b"contenuto") else {
                panic!("il file di prova deve potersi scrivere");
            };
        }
        let Ok(()) = std::fs::write(
            directory.join(super::RESET_MARKER),
            "audit archiviato: 7 voci",
        ) else {
            panic!("il marcatore deve potersi scrivere");
        };

        let Some(record) = apply_pending_reset(&directory) else {
            panic!("l'azzeramento richiesto deve essere eseguito");
        };
        assert!(
            record.contains("7 voci"),
            "la riga di continuita' deve sopravvivere all'azzeramento: {record}"
        );

        for suffix in ["", "-wal", "-shm"] {
            let name = format!("{}{suffix}", crate::sources::DATABASE_FILE);
            assert!(
                !directory.join(&name).exists(),
                "{name} doveva essere rimosso: lasciarlo ricostruirebbe il contenuto"
            );
        }
        assert!(
            !directory.join(super::RESET_MARKER).exists(),
            "il marcatore consumato non deve far azzerare di nuovo al prossimo avvio"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// L'azzeramento deve togliere anche ciò che vive **fuori** dal database:
    /// le sessioni TDLib degli account e i file protetti dei profili. Fino al
    /// 2026-08-04 restavano sul disco mentre l'interfaccia dichiarava che
    /// account e profili erano stati cancellati — e una sessione TDLib rimasta
    /// fa rientrare nell'account chi la copia, senza numero né codice.
    #[test]
    fn the_reset_removes_the_account_sessions_and_the_profile_files() {
        let directory = scratch("fuori-archivio");

        let account = directory
            .join(crate::telegram_runtime::ACCOUNTS_DIR)
            .join("6e3dc8358f091212a54bf3485d99dc98")
            .join("tdlib");
        let Ok(()) = std::fs::create_dir_all(&account) else {
            panic!("la cartella dell'account di prova deve potersi creare");
        };
        let Ok(()) = std::fs::write(account.join("td.binlog"), b"sessione") else {
            panic!("il binlog di prova deve potersi scrivere");
        };

        let profile = directory.join(format!(
            "{}8{}",
            crate::config::PROFILE_FILE_PREFIX,
            crate::config::PROFILE_FILE_SUFFIX
        ));
        let Ok(()) = std::fs::write(&profile, b"credenziali protette") else {
            panic!("il file di profilo di prova deve potersi scrivere");
        };

        // Ciò che deve **sopravvivere**: la catena di continuità e il registro.
        let audit = directory.join("audit-archiviato-1785835877745.txt");
        let Ok(()) = std::fs::write(&audit, b"audit archiviato") else {
            panic!("l'audit archiviato di prova deve potersi scrivere");
        };
        let logs = directory.join("logs");
        let Ok(()) = std::fs::create_dir_all(&logs) else {
            panic!("la cartella dei registri di prova deve potersi creare");
        };

        let Ok(()) = std::fs::write(
            directory.join(super::RESET_MARKER),
            "audit archiviato: 3 voci",
        ) else {
            panic!("il marcatore deve potersi scrivere");
        };

        assert!(
            apply_pending_reset(&directory).is_some(),
            "l'azzeramento richiesto deve essere eseguito"
        );

        assert!(
            !directory
                .join(crate::telegram_runtime::ACCOUNTS_DIR)
                .exists(),
            "la sessione TDLib doveva essere rimossa: chi la copia rientra nell'account"
        );
        assert!(
            !profile.exists(),
            "il file protetto del profilo doveva essere rimosso"
        );
        assert!(
            audit.exists(),
            "l'audit archiviato e' la catena di continuita' e non va toccato"
        );
        assert!(logs.exists(), "il registro non va toccato dall'azzeramento");

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Senza marcatore non si cancella nulla: l'avvio ordinario non deve
    /// nemmeno sfiorare l'archivio.
    #[test]
    fn without_a_marker_nothing_is_touched() {
        let directory = scratch("nomarker");
        let database = directory.join(crate::sources::DATABASE_FILE);
        let Ok(()) = std::fs::write(&database, b"archivio intatto") else {
            panic!("il file di prova deve potersi scrivere");
        };

        assert!(apply_pending_reset(&directory).is_none());
        assert!(database.exists(), "senza richiesta l'archivio non si tocca");

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Le funzioni restano raggiungibili dal resto del prodotto: un modulo
    /// di operazioni distruttive mai invocato sarebbe inutile, ed e' lo schema
    /// che in questa serie si e' ripetuto cinque volte.
    #[test]
    fn the_reset_request_keeps_its_shape() {
        let _request: fn(
            &crate::accounts::AccountService,
            &std::path::Path,
            lisi_core::Timestamp,
        ) -> crate::error::ServiceResult<AuditArchive> = request_archive_reset;
    }
    #[test]
    fn the_entry_points_exist_with_the_expected_shape() {
        let _remove: fn(
            &crate::accounts::AccountService,
            &std::path::Path,
            lisi_core::TelegramAccountId,
            &lisi_core::text::Actor,
            lisi_core::Timestamp,
        ) -> crate::error::ServiceResult<RemovalOutcome> = remove_account;
        let _reset: fn(
            &crate::accounts::AccountService,
            &std::path::Path,
            &lisi_core::text::Actor,
            lisi_core::Timestamp,
        ) -> crate::error::ServiceResult<RemovalOutcome> = reset_accounts_and_profiles;
    }
}

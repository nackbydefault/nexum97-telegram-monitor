//! **La classe di prova che il pilot ha insegnato a scrivere.**
//!
//! # Perché esiste
//!
//! Il 19-20 agosto 2026, durante il pilot manuale, l'ufficio ha trovato
//! ventidue difetti mentre millecinquecentouno prove automatiche erano verdi.
//! Tre di essi erano lo **stesso difetto**, in tre schermate diverse:
//!
//! - la schermata di benvenuto ricompariva a ogni riavvio, anche dopo aver
//!   salvato il profilo documentale;
//! - i campi del profilo risultavano vuoti dopo il riavvio;
//! - i campi delle credenziali apparivano vuoti in Impostazioni.
//!
//! Nessuna prova automatica li aveva visti, e la ragione è strutturale: le
//! prove verificavano che il salvataggio **scrivesse**, non che l'avvio
//! successivo **rileggesse**.
//!
//! # Perché serve un vero processo separato
//!
//! Una prova che riapre l'archivio nello stesso processo verifica meno di
//! quanto sembri. Restano fuori proprio le cose che rompono un riavvio vero:
//!
//! - il giornale WAL non assorbito alla chiusura;
//! - una connessione che sopravvive e tiene in vita una cache;
//! - un percorso risolto in modo diverso da un processo diverso;
//! - uno stato tenuto in memoria e scambiato per stato conservato.
//!
//! Qui il confine è reale. Il processo che scrive **termina**, e un processo
//! nuovo apre lo stesso file da zero.
//!
//! # Come funziona
//!
//! La prova rilancia sé stessa come sottoprocesso, con una variabile d'ambiente
//! che dice quale fase eseguire. È il modo standard di ottenere un processo
//! figlio da un test Rust senza aggiungere dipendenze né binari.
//!
//! ```text
//!   genitore ─┬─► figlio "scrivi"  ──► scrive la configurazione, ESCE
//!             └─► figlio "leggi"   ──► apre lo stesso file, rilegge, confronta
//! ```
//!
//! # Che cosa non fa
//!
//! Non tocca alcun segreto. Le credenziali di Telegram vivono sotto DPAPI, non
//! nell'archivio, e una prova che le scrivesse su disco per rileggerle sarebbe
//! un difetto travestito da verifica. Qui si coprono le configurazioni che
//! l'archivio conserva davvero.

use std::path::{Path, PathBuf};
use std::process::Command;

use lisi_core::Timestamp;
use lisi_core::model::destination::ExportDestination;
use lisi_core::model::language::InterfaceLanguage;
use lisi_core::model::motion::MotionPreference;
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};
use lisi_core::model::retention::{RetentionDays, RetentionPolicy};
use lisi_core::model::source::{NewSource, SourceKind};
use lisi_core::model::{NotificationPrivacy, NotificationSettings};
use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
use lisi_storage::Database;
use lisi_storage::repository::report::ProtectedProfileFields;

/// La variabile che distingue il genitore dai figli.
const FASE: &str = "NEXUM97_CICLO_DI_VITA_FASE";

/// La variabile che porta al figlio il percorso dell'archivio.
const PERCORSO: &str = "NEXUM97_CICLO_DI_VITA_PERCORSO";

/// Il nome esatto della prova, per rilanciarla da sola nel figlio.
const NOME_PROVA: &str = "la_configurazione_sopravvive_alla_chiusura_del_processo";

/// I valori che si scrivono e si rileggono.
///
/// Sono costanti e non generati: due esecuzioni devono confrontare le stesse
/// cose, e un valore casuale renderebbe un fallimento difficile da riprodurre.
mod atteso {
    pub const ORGANIZZAZIONE: &str = "Amministrazione di prova";
    pub const UFFICIO: &str = "Ufficio del ciclo di vita";
    pub const LUOGO: &str = "Roma";
    pub const FIRMATARIO: &str = "Mario Rossi";
    pub const QUALIFICA: &str = "Responsabile";
    pub const FONTE_ID: &str = "canale_ciclo_di_vita";
    pub const FONTE_NOME: &str = "Canale del ciclo di vita";
    pub const AUTORIZZATO_DA: &str = "responsabile.ufficio";
    pub const TETTO_NOTIFICHE: usize = 37;
    pub const LIVELLO_MINIMO: u8 = 3;
    pub const GIORNI_CONSERVAZIONE: u32 = 180;
}

/// Un attore di prova.
fn attore() -> Actor {
    let Ok(actor) = Actor::try_new("operatore.ciclo") else {
        panic!("l'attore di prova deve essere valido");
    };
    actor
}

/// Un istante fisso.
fn adesso() -> Timestamp {
    Timestamp::from_millis(1_700_000_000_000)
}

/// Un campo del profilo.
fn campo(testo: &str) -> Option<TemplateField> {
    match TemplateField::try_new(testo) {
        Ok(valore) => Some(valore),
        Err(errore) => panic!("«{testo}» deve essere un campo valido: {errore}"),
    }
}

// ===========================================================================
// FASE 1 — il processo che scrive, e poi termina
// ===========================================================================

/// Scrive la configurazione e restituisce, così che il processo termini.
///
/// Non chiama `wal_checkpoint` né alcuna forma di svuotamento esplicito: se
/// servisse, sarebbe un difetto del prodotto e non della prova. Il prodotto non
/// lo fa, quindi la prova non lo fa.
fn scrivi(percorso: &Path) {
    let Ok(database) = Database::open(percorso) else {
        panic!("l'archivio deve potersi creare");
    };

    // 1. Il profilo documentale — il difetto del pilot.
    let profilo = ReportTemplateProfile {
        version: 0,
        organisation: campo(atteso::ORGANIZZAZIONE),
        office: campo(atteso::UFFICIO),
        header_line: None,
        recipient: None,
        recipient_cc: None,
        place: campo(atteso::LUOGO),
        // Firmatario e qualifica si conservano soltanto cifrati (ADR-0160): qui
        // l'archivio riceve byte opachi, e deve restituirli uguali.
        signer_role: None,
        signer_name: None,
        footer_line: None,
        subject_base: None,
        emblem: None,
    };
    let cifrati = ProtectedProfileFields {
        signer_name: Some(atteso::FIRMATARIO.as_bytes().to_vec()),
        signer_role: Some(atteso::QUALIFICA.as_bytes().to_vec()),
        header_line: None,
    };
    let Ok(versione) = database.save_report_profile(&profilo, &cifrati, &attore(), adesso()) else {
        panic!("il profilo deve potersi salvare");
    };
    assert!(versione >= 1, "la versione del profilo deve crescere");

    // 2. Le impostazioni delle notifiche.
    let notifiche = NotificationSettings {
        privacy: NotificationPrivacy::Confidential,
        minimum_level: atteso::LIVELLO_MINIMO,
        max_per_session: atteso::TETTO_NOTIFICHE,
        include_url: true,
        cyber_enabled: true,
        cyber_minimum_contents: 5,
        cyber_minimum_sources: 3,
    };
    let Ok(()) = database.save_notification_settings(&notifiche) else {
        panic!("le impostazioni delle notifiche devono potersi salvare");
    };

    // 3. La cartella di destinazione.
    let cartella = percorso
        .parent()
        .map_or_else(|| PathBuf::from("C:/"), Path::to_path_buf);
    let Ok(destinazione) = ExportDestination::try_new(&cartella) else {
        panic!("la cartella temporanea deve essere una destinazione valida");
    };
    let Ok(()) =
        database.save_export_destination(Some(&destinazione), &attore(), adesso().as_millis())
    else {
        panic!("la destinazione deve potersi salvare");
    };

    // 4. La politica di conservazione.
    let Ok(giorni) = RetentionDays::try_new(atteso::GIORNI_CONSERVAZIONE) else {
        panic!("i giorni di prova devono essere ammessi");
    };
    let Ok(()) = database.save_retention_policy(
        RetentionPolicy::Days(giorni),
        &attore(),
        adesso().as_millis(),
    ) else {
        panic!("la politica di conservazione deve potersi salvare");
    };

    // 5. Una fonte configurata.
    let (Ok(identifier), Ok(display_name), Ok(authorized_by)) = (
        SourceIdentifier::try_new(atteso::FONTE_ID),
        DisplayName::try_new(atteso::FONTE_NOME),
        Actor::try_new(atteso::AUTORIZZATO_DA),
    ) else {
        panic!("i valori della fonte di prova devono essere validi");
    };
    let Ok(_) = database.insert_source(
        &NewSource {
            kind: SourceKind::Channel,
            identifier,
            display_name,
            authorized_by,
            active: true,
        },
        adesso(),
    ) else {
        panic!("la fonte deve potersi registrare");
    };

    // 6. La preferenza sul movimento.
    //
    // E' un'impostazione di ACCESSIBILITA': chi la sceglie perche' il movimento
    // gli da' fastidio non deve ritrovarselo acceso al riavvio.
    let Ok(()) =
        database.save_motion_preference(MotionPreference::Reduced, &attore(), adesso().as_millis())
    else {
        panic!("la preferenza sul movimento deve potersi salvare");
    };

    // 7. La lingua dell'interfaccia (I18N-01, ADR-0197).
    let Ok(()) = database.save_interface_language(
        InterfaceLanguage::English,
        &attore(),
        adesso().as_millis(),
    ) else {
        panic!("la lingua dell'interfaccia deve potersi salvare");
    };

    println!("[scrivi] configurazione scritta in {}", percorso.display());
    // Nessuna chiusura esplicita: il processo termina e con esso ogni
    // connessione, esattamente come quando l'operatore chiude il programma.
}

// ===========================================================================
// FASE 2 — il processo che rilegge, senza sapere nulla del primo
// ===========================================================================

/// Riapre l'archivio e verifica che tutto sia ancora lì.
fn leggi(percorso: &Path) {
    assert!(
        percorso.is_file(),
        "il processo che ha scritto non ha lasciato alcun file: {}",
        percorso.display()
    );

    let Ok(database) = Database::open(percorso) else {
        panic!("l'archivio scritto dal processo precedente deve potersi riaprire");
    };

    // 1. Il profilo documentale.
    //
    // Questa e' la verifica che il pilot ha reso necessaria. `None` qui
    // significa «la domanda non e' ancora stata posta», ed e' esattamente lo
    // stato che faceva ricomparire la schermata di benvenuto.
    let Ok(profilo) = database.report_profile() else {
        panic!("il profilo deve potersi leggere");
    };
    let Some(profilo) = profilo else {
        panic!(
            "il profilo documentale e' sparito con la chiusura del processo: \
             la schermata di benvenuto ricomparirebbe al prossimo avvio"
        );
    };

    assert_eq!(
        profilo.organisation.as_ref().map(TemplateField::as_str),
        Some(atteso::ORGANIZZAZIONE),
        "l'organizzazione non e' sopravvissuta"
    );
    assert_eq!(
        profilo.office.as_ref().map(TemplateField::as_str),
        Some(atteso::UFFICIO),
        "l'ufficio non e' sopravvissuto"
    );
    assert_eq!(
        profilo.place.as_ref().map(TemplateField::as_str),
        Some(atteso::LUOGO)
    );
    // Firmatario e qualifica si conservano soltanto cifrati (ADR-0160): qui
    // tornano i byte opachi che l'archivio aveva ricevuto, e il chiaro no.
    let Ok(Some(cifrati)) = database.report_profile_protected() else {
        panic!("i campi personali cifrati devono potersi rileggere");
    };
    assert_eq!(
        cifrati.signer_name.as_deref(),
        Some(atteso::FIRMATARIO.as_bytes()),
        "il nome di chi firma non e' sopravvissuto: comparirebbe una relazione \
         senza firma in calce"
    );
    assert_eq!(
        cifrati.signer_role.as_deref(),
        Some(atteso::QUALIFICA.as_bytes())
    );
    assert!(
        profilo.signer_name.is_none(),
        "il nome di chi firma e' tornato in chiaro"
    );
    assert!(
        profilo.version >= 1,
        "la versione del profilo e' tornata a zero: ogni pacchetto direbbe di \
         essere stato prodotto senza profilo"
    );

    // 2. Le impostazioni delle notifiche.
    let Ok(notifiche) = database.notification_settings() else {
        panic!("le impostazioni delle notifiche devono potersi leggere");
    };
    assert_eq!(notifiche.privacy, NotificationPrivacy::Confidential);
    assert_eq!(notifiche.minimum_level, atteso::LIVELLO_MINIMO);
    assert_eq!(notifiche.max_per_session, atteso::TETTO_NOTIFICHE);
    assert!(notifiche.include_url);

    // 3. La cartella di destinazione.
    let Ok(destinazione) = database.export_destination() else {
        panic!("la destinazione deve potersi leggere");
    };
    assert!(
        destinazione.is_some(),
        "la cartella scelta e' sparita: il pacchetto uscirebbe altrove senza \
         che nessuno lo abbia deciso"
    );

    // 4. La politica di conservazione.
    let Ok(politica) = database.retention_policy() else {
        panic!("la politica di conservazione deve potersi leggere");
    };
    assert_eq!(
        politica.days(),
        Some(atteso::GIORNI_CONSERVAZIONE),
        "la conservazione e' tornata al predefinito: l'ufficio crederebbe di \
         avere un limite che non ha"
    );

    // 5. La fonte configurata.
    let Ok(fonti) = database.sources() else {
        panic!("le fonti devono potersi leggere");
    };
    let Some(fonte) = fonti
        .iter()
        .find(|fonte| fonte.identifier.as_str() == atteso::FONTE_ID)
    else {
        panic!("la fonte configurata e' sparita con la chiusura del processo");
    };
    assert_eq!(fonte.display_name.as_str(), atteso::FONTE_NOME);
    assert_eq!(fonte.authorized_by.as_str(), atteso::AUTORIZZATO_DA);
    assert!(fonte.active);

    // 6. L'archivio riaperto e' anche INTEGRO, non solo leggibile.
    let Ok(rapporto) = database.verify_integrity() else {
        panic!("la verifica dell'integrita' deve riuscire su un archivio sano");
    };
    assert!(
        rapporto.is_healthy(),
        "l'archivio non e' integro dopo un ciclo di chiusura e riapertura: {}",
        rapporto.operator_message()
    );

    // 6. La preferenza sul movimento.
    let Ok(movimento) = database.motion_preference() else {
        panic!("la preferenza sul movimento deve potersi leggere");
    };
    assert_eq!(
        movimento,
        MotionPreference::Reduced,
        "la preferenza di accessibilita' e' tornata al predefinito: chi l'aveva \
         scelta perche' il movimento gli da' fastidio se lo ritroverebbe acceso"
    );

    // 7. La lingua dell'interfaccia.
    let Ok(lingua) = database.interface_language() else {
        panic!("la lingua dell'interfaccia deve potersi leggere");
    };
    assert_eq!(
        lingua,
        InterfaceLanguage::English,
        "la lingua scelta e' tornata all'italiano: chi non lo legge ritroverebbe \
         un'interfaccia che non capisce"
    );

    println!("[leggi] tutta la configurazione e' sopravvissuta");
}

// ===========================================================================
// Il genitore
// ===========================================================================

/// Esegue una fase in un processo figlio e attende che termini.
fn esegui_fase(fase: &str, percorso: &Path) {
    let Ok(exe) = std::env::current_exe() else {
        panic!("il percorso della prova deve essere leggibile");
    };

    let esito = Command::new(&exe)
        .args([NOME_PROVA, "--exact", "--nocapture", "--test-threads=1"])
        .env(FASE, fase)
        .env(PERCORSO, percorso)
        .status();

    let Ok(stato) = esito else {
        panic!("la fase «{fase}» non e' stata eseguibile come processo figlio");
    };
    assert!(
        stato.success(),
        "la fase «{fase}» e' fallita nel processo figlio (codice {:?})",
        stato.code()
    );
}

/// **La configurazione deve sopravvivere alla chiusura del processo.**
///
/// Il genitore crea una cartella, lancia il figlio che scrive, **attende che
/// termini**, poi lancia il figlio che rilegge.
#[test]
fn la_configurazione_sopravvive_alla_chiusura_del_processo() {
    // I figli entrano da qui: la variabile d'ambiente decide chi sono.
    if let Ok(fase) = std::env::var(FASE) {
        let Ok(percorso) = std::env::var(PERCORSO) else {
            panic!("il figlio deve ricevere il percorso dell'archivio");
        };
        let percorso = PathBuf::from(percorso);

        match fase.as_str() {
            "scrivi" => scrivi(&percorso),
            "leggi" => leggi(&percorso),
            altro => panic!("fase sconosciuta: «{altro}»"),
        }
        return;
    }

    let Ok(cartella) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    let percorso = cartella.path().join("archivio.sqlite3");

    esegui_fase("scrivi", &percorso);

    // La premessa della prova, verificata e non presunta: se il file non
    // esistesse, la fase di lettura fallirebbe per la ragione sbagliata.
    assert!(
        percorso.is_file(),
        "il processo che scrive non ha lasciato alcun archivio"
    );

    esegui_fase("leggi", &percorso);
}

/// **Un archivio mai configurato non deve fingere di esserlo.**
///
/// È l'altra metà della distinzione che regge la schermata di benvenuto:
/// *nessuna riga* significa «la domanda non è ancora stata posta», e va
/// distinta da una riga vuota, che significa «gliela si è posta e ha risposto
/// di no».
///
/// Se questa prova fallisse, il benvenuto non comparirebbe mai su una
/// postazione nuova — cioè il difetto opposto e altrettanto grave.
#[test]
fn un_archivio_nuovo_dichiara_che_la_domanda_non_e_stata_posta() {
    let Ok(cartella) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    let percorso = cartella.path().join("nuovo.sqlite3");

    let Ok(database) = Database::open(&percorso) else {
        panic!("l'archivio deve potersi creare");
    };
    let Ok(profilo) = database.report_profile() else {
        panic!("il profilo deve potersi leggere");
    };

    assert!(
        profilo.is_none(),
        "un archivio nuovo dichiara un profilo che nessuno ha inserito: la \
         schermata di benvenuto non comparirebbe mai"
    );

    // E il predefinito prudente della conservazione vale anche qui.
    let Ok(politica) = database.retention_policy() else {
        panic!("la politica deve potersi leggere");
    };
    assert_eq!(politica, RetentionPolicy::Unlimited);
}

/// **Un profilo salvato vuoto è una risposta, non un'assenza.**
///
/// Chi ha premuto «Non inserirli» non deve sentirselo chiedere di nuovo al
/// prossimo avvio. La distinzione vive nello schema (una riga esiste, i campi
/// sono nulli) e questa prova la attraversa.
#[test]
fn un_rifiuto_registrato_resta_un_rifiuto() {
    let Ok(cartella) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    let percorso = cartella.path().join("rifiuto.sqlite3");

    {
        let Ok(database) = Database::open(&percorso) else {
            panic!("l'archivio deve potersi creare");
        };
        let vuoto = ReportTemplateProfile {
            version: 0,
            organisation: None,
            office: None,
            header_line: None,
            recipient: None,
            recipient_cc: None,
            place: None,
            signer_role: None,
            signer_name: None,
            footer_line: None,
            subject_base: None,
            emblem: None,
        };
        let Ok(_) = database.save_report_profile(
            &vuoto,
            &ProtectedProfileFields::default(),
            &attore(),
            adesso(),
        ) else {
            panic!("un profilo vuoto deve potersi salvare: e' la forma del rifiuto");
        };
    }

    let Ok(database) = Database::open(&percorso) else {
        panic!("l'archivio deve potersi riaprire");
    };
    let Ok(profilo) = database.report_profile() else {
        panic!("il profilo deve potersi leggere");
    };

    let Some(profilo) = profilo else {
        panic!(
            "il rifiuto non e' stato conservato: la domanda tornerebbe a ogni \
             avvio a chi aveva gia' risposto di no"
        );
    };
    assert!(
        profilo.organisation.is_none() && profilo.office.is_none(),
        "il profilo del rifiuto non deve contenere dati"
    );
}

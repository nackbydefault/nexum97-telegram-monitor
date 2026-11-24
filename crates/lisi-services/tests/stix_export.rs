//! Il pacchetto STIX realmente prodotto, dall'archivio al file.
//!
//! I test per modulo provano che la matrice semantica sia applicata. Questo
//! prova la cosa che nessuno di quelli può provare: che **un messaggio vero**,
//! con dentro un nome, un username, un numero di telefono e un codice usa e
//! getta, produca un file da cui quelle cose sono assenti.
//!
//! # Perché si cercano le stringhe nei byte del file
//!
//! Perché è il file che esce dall'ufficio. Un test che guardasse la struttura
//! in memoria proverebbe che il codice intende non scriverle; qui si legge ciò
//! che è stato scritto. È l'opposto del caso `.docx`, dove cercare nei byte
//! sarebbe stato inutile perché lo ZIP comprime: il JSON è testo, e ciò che
//! non c'è nei byte non c'è.

use std::path::PathBuf;

use lisi_core::model::AcquisitionOrigin;
use lisi_core::model::dictionary::{
    ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
};
use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
use lisi_core::text::{
    Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier, TermCategory,
    TermText,
};
use lisi_core::{SessionId, Timestamp};
use lisi_services::ServiceError;
use lisi_services::analysis::{AnalysisService, NewContentDraft};
use lisi_services::export::verify_manifest_file;
use lisi_services::sources::open_in_memory_database;
use lisi_services::stix_export::StixExportService;
use lisi_storage::Database;

/// Il nome che compare nel messaggio e non deve comparire nel pacchetto.
const NOME_PERSONA: &str = "Mario Rossi";
/// L'username Telegram di chi scrive.
const USERNAME: &str = "mario_rossi_97";
/// Un numero di telefono citato nel testo.
const TELEFONO: &str = "+39 333 1234567";
/// Un codice usa e getta citato nel testo.
const CODICE: &str = "codice 84213";
/// Il collegamento a una persona su Telegram.
const LINK_TELEGRAM: &str = "https://t.me/mario_rossi_97";

fn now() -> Timestamp {
    Timestamp::from_millis(1_757_000_000_000)
}

fn operator() -> Actor {
    let Ok(value) = Actor::try_new("operatore.prova") else {
        panic!("l'attore di prova deve essere valido");
    };
    value
}

fn configuration() -> ResolvedDictionaryConfiguration {
    let mut resolver = ConfigurationResolver::new();
    let (Ok(text), Ok(category), Ok(language)) = (
        TermText::try_new("molotov"),
        TermCategory::try_new("oggetto"),
        LanguageTag::try_new("it"),
    ) else {
        panic!("i valori del termine devono essere validi");
    };
    let Ok(()) = resolver.add(
        text,
        category,
        language,
        MatchMode::NormalizedWord,
        3,
        TermProvenance::ad_hoc(),
    ) else {
        panic!("il termine doveva essere accettato");
    };
    resolver.finish()
}

/// Archivio con una sessione e i contenuti indicati.
fn archive(bodies: &[&str]) -> (Database, SessionId) {
    let Ok(mut database) = open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };

    let (Ok(identifier), Ok(title), Ok(label)) = (
        SourceIdentifier::try_new("canale_autorizzato"),
        DisplayName::try_new("Canale di prova"),
        DisplayName::try_new("Monitoraggio di prova"),
    ) else {
        panic!("i valori di prova devono essere validi");
    };
    let Ok(source_id) = database.insert_source(
        &NewSource {
            kind: SourceKind::Channel,
            identifier,
            display_name: title,
            authorized_by: operator(),
            active: true,
        },
        now(),
    ) else {
        panic!("la fonte deve potersi registrare");
    };
    let Ok(session_id) = database.insert_session(
        &NewSession {
            label,
            started_by: operator(),
            duration: SessionDuration::Preset { seconds: 3_600 },
            source_ids: vec![source_id],
        },
        now(),
    ) else {
        panic!("la sessione deve potersi creare");
    };

    let configuration = configuration();
    let mut analysis = AnalysisService::new(database);
    for (index, testo) in bodies.iter().enumerate() {
        let Ok(index) = i64::try_from(index) else {
            panic!("l'indice deve stare in un intero");
        };
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new(&format!("m{index}")),
            ContentBody::try_new(testo),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let Ok(_) = analysis.analyse_and_record(
            &NewContentDraft {
                session_id,
                source_id,
                remote_message_id: remote,
                author: Actor::try_new(NOME_PERSONA).ok(),
                author_identifier: Some(String::from("1234567890")),
                author_username: Some(String::from(USERNAME)),
                body,
                url: None,
                published_at: now(),
                acquired_at: now(),
                origin: AcquisitionOrigin::Observed,
            },
            &configuration,
            &operator(),
            now(),
        ) else {
            panic!("l'analisi deve riuscire");
        };
    }

    (analysis.into_database(), session_id)
}

/// Un monitoraggio con dentro tutto ciò che non deve uscire.
fn archivio_completo() -> (Database, SessionId) {
    archive(&[
        &format!(
            "attenzione a esempio.test e all'indirizzo 198.51.100.3, \
             riferimento CVE-2026-1234, telefono {TELEFONO}, {CODICE}"
        ),
        &format!(
            "scrivetemi su {LINK_TELEGRAM} — impronta \
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
    ])
}

/// Cartella temporanea in cui una prova può scrivere.
fn temporary_directory(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("nexum-stix-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// **Il pacchetto prodotto non contiene alcun dato personale né segreto.**
///
/// È la prova di §8 della politica: minimizzazione verificata sul file, non
/// sull'intenzione.
#[test]
fn il_pacchetto_non_porta_dati_personali_ne_segreti() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let directory = temporary_directory("minimizzazione");

    let Ok(esito) = service.export(session_id, &directory, &operator(), now()) else {
        panic!("l'esportazione deve riuscire");
    };
    let Ok(json) = std::fs::read_to_string(&esito.bundle) else {
        panic!("il pacchetto deve essere leggibile");
    };

    for vietato in [
        NOME_PERSONA,
        USERNAME,
        TELEFONO,
        CODICE,
        "84213",
        "1234567890",
        "t.me",
        "mario_rossi",
        "Monitoraggio di prova",
        "Canale di prova",
        "canale_autorizzato",
        "operatore.prova",
        "attenzione a",
        "scrivetemi",
    ] {
        assert!(
            !json.contains(vietato),
            "il pacchetto non deve contenere «{vietato}»:\n{json}"
        );
    }

    let _ = std::fs::remove_dir_all(&directory);
}

/// Ciò che invece deve esserci, c'è: gli osservabili e la vulnerabilità.
#[test]
fn il_pacchetto_porta_cio_che_regge_la_semantica() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let directory = temporary_directory("contenuto");

    let Ok(esito) = service.export(session_id, &directory, &operator(), now()) else {
        panic!("l'esportazione deve riuscire");
    };
    let Ok(json) = std::fs::read_to_string(&esito.bundle) else {
        panic!("il pacchetto deve essere leggibile");
    };
    let Ok(valore) = serde_json::from_str::<serde_json::Value>(&json) else {
        panic!("il pacchetto deve essere JSON valido");
    };

    let Some(oggetti) = valore["objects"].as_array() else {
        panic!("il pacchetto deve portare un elenco di oggetti");
    };
    let tipi: Vec<&str> = oggetti
        .iter()
        .filter_map(|oggetto| oggetto["type"].as_str())
        .collect();

    for atteso in ["domain-name", "ipv4-addr", "file", "vulnerability", "note"] {
        assert!(
            tipi.contains(&atteso),
            "manca un oggetto {atteso}: {tipi:?}"
        );
    }
    assert!(json.contains("esempio.test"));
    assert!(json.contains("198.51.100.3"));
    assert!(json.contains("CVE-2026-1234"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **L'omissione del riferimento Telegram è dichiarata, non silenziosa.**
#[test]
fn il_riferimento_telegram_e_omesso_e_il_motivo_sta_nel_manifest() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let directory = temporary_directory("omissione");

    let Ok(esito) = service.export(session_id, &directory, &operator(), now()) else {
        panic!("l'esportazione deve riuscire");
    };
    assert!(
        esito
            .plan
            .omitted
            .iter()
            .any(|omission| omission.indicator.value.contains("t.me")),
        "il riferimento Telegram doveva essere omesso"
    );

    let Ok(manifest) = std::fs::read_to_string(&esito.manifest) else {
        panic!("il manifest deve essere leggibile");
    };
    assert!(manifest.contains("identificativo personale"));
    assert!(manifest.contains("NON fa parte del pacchetto STIX"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// Il manifest verifica il pacchetto con il verificatore già esistente.
///
/// È la ragione per cui il manifest ha la stessa forma di quello dello Storico:
/// un secondo formato avrebbe richiesto un secondo verificatore, e due
/// verificatori divergono.
#[test]
fn il_manifest_esistente_sa_verificare_il_pacchetto() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let directory = temporary_directory("manifest");

    let Ok(esito) = service.export(session_id, &directory, &operator(), now()) else {
        panic!("l'esportazione deve riuscire");
    };

    let verifica = verify_manifest_file(&esito.manifest);
    assert!(
        verifica.status.is_intact(),
        "il verificatore doveva riconoscere il pacchetto: {:?}",
        verifica.status
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Due esportazioni della stessa selezione danno gli stessi byte.**
#[test]
fn due_esportazioni_della_stessa_selezione_danno_gli_stessi_byte() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let prima = temporary_directory("determinismo-1");
    let seconda = temporary_directory("determinismo-2");

    let (Ok(uno), Ok(due)) = (
        service.export(session_id, &prima, &operator(), now()),
        service.export(session_id, &seconda, &operator(), now()),
    ) else {
        panic!("entrambe le esportazioni devono riuscire");
    };

    let (Ok(bytes_uno), Ok(bytes_due)) = (std::fs::read(&uno.bundle), std::fs::read(&due.bundle))
    else {
        panic!("i pacchetti devono essere leggibili");
    };
    assert_eq!(bytes_uno, bytes_due);
    assert_eq!(uno.digest.as_str(), due.digest.as_str());

    let _ = std::fs::remove_dir_all(&prima);
    let _ = std::fs::remove_dir_all(&seconda);
}

/// **Ciò che l'anteprima mostra è ciò che l'esportazione scrive.**
#[test]
fn l_anteprima_non_scrive_nulla_e_dice_la_stessa_cosa() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let directory = temporary_directory("anteprima");

    let Ok(anteprima) = service.preview(session_id) else {
        panic!("l'anteprima deve riuscire");
    };
    assert!(
        !directory.exists(),
        "l'anteprima non deve creare alcuna cartella"
    );

    let Ok(esito) = service.export(session_id, &directory, &operator(), now()) else {
        panic!("l'esportazione deve riuscire");
    };
    assert_eq!(anteprima, esito.plan);

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un monitoraggio senza nulla di rappresentabile non produce un pacchetto
/// vuoto.**
#[test]
fn un_monitoraggio_senza_nulla_di_rappresentabile_non_scrive_un_pacchetto() {
    let (database, session_id) = archive(&["buongiorno a tutti, ci vediamo domani"]);
    let service = StixExportService::new(&database);
    let directory = temporary_directory("vuoto");

    let esito = service.export(session_id, &directory, &operator(), now());
    assert!(matches!(esito, Err(ServiceError::StixNothingToExport)));
    assert!(
        !directory.exists(),
        "nessun file deve essere scritto quando non c'è nulla da dire"
    );
}

/// L'atto resta nell'audit, con l'impronta di ciò che è uscito.
#[test]
fn l_esportazione_lascia_una_voce_di_audit_con_l_impronta() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let directory = temporary_directory("audit");

    let Ok(esito) = service.export(session_id, &directory, &operator(), now()) else {
        panic!("l'esportazione deve riuscire");
    };

    let Ok(voci) = database.audit_entries() else {
        panic!("l'audit deve essere leggibile");
    };
    let Some(voce) = voci
        .iter()
        .find(|voce| voce.action.as_str() == "stix_esportato")
    else {
        panic!("l'esportazione deve lasciare una voce di audit");
    };
    assert_eq!(voce.entity_id, Some(session_id.get()));
    let Some(dettaglio) = voce.detail.as_ref() else {
        panic!("la voce deve dire che cosa è uscito");
    };
    assert!(dettaglio.as_str().contains(esito.digest.as_str()));

    let _ = std::fs::remove_dir_all(&directory);
}

/// Un pacchetto già presente non viene sostituito in silenzio.
#[test]
fn un_pacchetto_gia_presente_non_viene_sostituito() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let directory = temporary_directory("sovrascrittura");

    let Ok(_) = service.export(session_id, &directory, &operator(), now()) else {
        panic!("la prima esportazione deve riuscire");
    };
    let secondo = service.export(session_id, &directory, &operator(), now());
    assert!(matches!(
        secondo,
        Err(ServiceError::ExportNotWritten { .. })
    ));

    let _ = std::fs::remove_dir_all(&directory);
}

/// Chiude una cartella come una chiavetta che non conserva i permessi, e ne
/// controlla la premessa su un file testimone. È la forma di
/// `permessi_di_prova::rifiuta_i_permessi` del crate, che una prova di
/// integrazione non vede: le ragioni (niente `icacls`, niente `PSModulePath`)
/// stanno lì e in DEC-513.
#[cfg(windows)]
fn rifiuta_i_permessi(cartella: &std::path::Path) {
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
         $p = $env:NEXUM_PROVA_PERCORSO; \
         $ds = New-Object System.Security.AccessControl.DirectorySecurity; \
         $ds.SetAccessRuleProtection($true, $false); \
         foreach ($s in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, \
             (New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')))) { \
           $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule( \
             $s, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }; \
         [System.IO.Directory]::SetAccessControl($p, $ds); \
         $t = [System.IO.Path]::Combine($p, 'testimone.txt'); \
         [System.IO.File]::WriteAllText($t, 'testimone'); \
         $cambiati = $true; \
         try { $f = [System.IO.File]::GetAccessControl($t); \
               $f.SetAccessRuleProtection($true, $true); \
               [System.IO.File]::SetAccessControl($t, $f) } catch { $cambiati = $false }; \
         [System.IO.File]::Delete($t); \
         'TESTIMONE|' + $cambiati";
    let Ok(uscita) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            SCRIPT,
        ])
        .env("NEXUM_PROVA_PERCORSO", cartella)
        .env_remove("PSModulePath")
        .output()
    else {
        panic!("PowerShell deve potersi avviare per chiudere la cartella");
    };
    let testo = String::from_utf8_lossy(&uscita.stdout);
    assert!(
        uscita.status.success() && testo.lines().any(|riga| riga.trim() == "TESTIMONE|False"),
        "la premessa non regge: la cartella che rifiuta i permessi li accetta ({testo} {})",
        String::from_utf8_lossy(&uscita.stderr)
    );
}

/// **SEC-02: pacchetto STIX e manifest del solo utente, o niente** (ADR-0157).
///
/// In una cartella aperta a `Users` e ad `Authenticated Users` i due file
/// arrivano del solo utente, e accanto non resta altro; in una cartella che
/// toglie all'utente il diritto di cambiare i permessi (voce `OWNER RIGHTS`,
/// come una chiavetta FAT32) l'esportazione è rifiutata e non lascia nulla.
/// I permessi li rilegge il controllo del prodotto: il lettore indipendente
/// (.NET) prova lo stesso componente comune nelle prove di
/// `protected_output`. Vista rossa il 2026-10-22 con la protezione tolta (mutazione di SEC-02).
#[cfg(windows)]
#[test]
fn l_esportazione_stix_e_del_solo_utente_o_non_si_scrive() {
    let (database, session_id) = archivio_completo();
    let service = StixExportService::new(&database);
    let Ok(utente) = lisi_security::owner_only::current_user() else {
        panic!("l'utente corrente deve potersi leggere");
    };
    let icacls = |cartella: &std::path::Path, concessioni: &[String]| {
        let Ok(uscita) = std::process::Command::new("icacls")
            .arg(cartella)
            .args(concessioni)
            .output()
        else {
            panic!("icacls deve potersi avviare");
        };
        assert!(
            uscita.status.success(),
            "la cartella di prova non si è preparata"
        );
    };
    let nomi_in = |cartella: &std::path::Path| -> Vec<String> {
        let Ok(voci) = std::fs::read_dir(cartella) else {
            panic!("la cartella deve potersi elencare");
        };
        let mut nomi: Vec<String> = voci
            .filter_map(Result::ok)
            .map(|voce| voce.file_name().to_string_lossy().into_owned())
            .collect();
        nomi.sort();
        nomi
    };

    // Aperta come nel collaudo.
    let Ok(aperta) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    icacls(
        aperta.path(),
        &[
            String::from("/grant"),
            String::from("*S-1-5-32-545:(OI)(CI)(RX)"),
            String::from("/grant"),
            String::from("*S-1-5-11:(OI)(CI)(M)"),
        ],
    );
    let Ok(esito) = service.export(session_id, aperta.path(), &operator(), now()) else {
        panic!("l'esportazione in una cartella aperta deve riuscire");
    };
    for file in [&esito.bundle, &esito.manifest] {
        let accesso = lisi_security::owner_only::verify_current_user_only(file);
        assert!(
            accesso.is_owner_only(),
            "«{}» non è del solo utente: {accesso:?}",
            file.display()
        );
    }
    assert_eq!(
        nomi_in(aperta.path()).len(),
        2,
        "accanto all'esportazione è rimasto altro"
    );
    assert_eq!(esito.owner.sid, utente.sid);

    // Una cartella che rifiuta i permessi.
    let Ok(chiusa) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    rifiuta_i_permessi(chiusa.path());
    let rifiuto = service.export(session_id, chiusa.path(), &operator(), now());
    assert!(
        matches!(rifiuto, Err(ServiceError::ProtectionNotGuaranteed { .. })),
        "in una cartella che rifiuta i permessi l'esportazione STIX si è scritta: {rifiuto:?}"
    );
    assert!(
        nomi_in(chiusa.path()).is_empty(),
        "il rifiuto ha lasciato qualcosa"
    );
}

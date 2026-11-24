//! Il catalogo CISA KEV, dal file all'archivio, e i due esiti asimmetrici.
//!
//! I test per modulo provano che il servizio non **nomini** i campi che
//! obbligano qualcun altro. Questo prova le due cose che nessuno di quelli può
//! provare: che **un ordine presente nel file non arrivi nell'archivio**, e che
//! **il catalogo vero di CISA** si legga per intero.
//!
//! # Perché la prova sul file vero è `ignored`
//!
//! Perché richiede un file che il repository **non conserva**: la politica sta in
//! `kev.lock.json`, i dati no (ADR-0061). Si esegue dopo
//! `scripts/fetch-kev.ps1`, con
//! `cargo test -p lisi-services --test kev_snapshot -- --ignored`.

use std::path::{Path, PathBuf};

use lisi_core::model::cve::CveId;
use lisi_core::model::kev::{KevOmissionReason, KevResolution, RansomwareUse};
use lisi_core::text::Actor;
use lisi_core::{Sha256Digest, Timestamp};
use lisi_services::ServiceError;
use lisi_services::kev_snapshot::{
    ACQUIRED_DIGEST_FILE, CATALOGUE_FILE, KevSnapshotService, MAX_CATALOGUE_BYTES,
};
use lisi_services::sources::open_in_memory_database;
use lisi_storage::Database;

fn now() -> Timestamp {
    Timestamp::from_millis(1_757_000_000_000)
}

fn operator() -> Actor {
    let Ok(value) = Actor::try_new("operatore.prova") else {
        panic!("l'attore di prova deve essere valido");
    };
    value
}

fn archivio() -> Database {
    let Ok(database) = open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };
    database
}

fn identificativo(raw: &str) -> CveId {
    let Ok(id) = CveId::try_new(raw) else {
        panic!("l'identificativo di prova deve essere valido");
    };
    id
}

fn temporary_directory(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("nexum-kev-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let Ok(()) = std::fs::create_dir_all(&directory) else {
        panic!("la cartella di prova deve potersi creare");
    };
    directory
}

/// Una voce come CISA la pubblica, **con** l'ordine che il prodotto non prende.
///
/// I tre campi che obbligano le agenzie federali statunitensi ci sono tutti, e
/// nessuno di essi deve arrivare nell'archivio.
fn voce(id: &str, descrizione: &str, ransomware: &str) -> String {
    format!(
        r#"{{
          "cveID": "{id}",
          "vendorProject": "MikroTik",
          "product": "RouterOS",
          "vulnerabilityName": "MikroTik RouterOS Argument Delimiters Vulnerability",
          "dateAdded": "2026-09-10",
          "shortDescription": "{descrizione}",
          "requiredAction": "Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA BOD 26-04.",
          "dueDate": "2026-09-13",
          "knownRansomwareCampaignUse": "{ransomware}",
          "forensicTriage": "Yes",
          "notes": " ; BOD 26-04: https://esempio.test/direttiva ; https://esempio.test/avviso",
          "cwes": [ "CWE-88" ]
        }}"#
    )
}

/// Scrive un catalogo e il file di impronta, coerenti fra loro.
fn scrivi_catalogo(directory: &Path, voci: &[String]) {
    scrivi_catalogo_con_conteggio(directory, voci, voci.len() as u64);
}

/// Scrive un catalogo che **dichiara** il conteggio indicato.
fn scrivi_catalogo_con_conteggio(directory: &Path, voci: &[String], dichiarate: u64) {
    let contenuto = format!(
        r#"{{
          "title": "CISA Catalog of Known Exploited Vulnerabilities",
          "catalogVersion": "2026.09.10",
          "dateReleased": "2026-09-10T19:00:05.1949Z",
          "count": {dichiarate},
          "vulnerabilities": [ {corpo} ]
        }}"#,
        corpo = voci.join(",\n")
    );

    let catalogo = directory.join(CATALOGUE_FILE);
    let Ok(()) = std::fs::write(&catalogo, &contenuto) else {
        panic!("il catalogo di prova deve potersi scrivere");
    };

    let impronta = Sha256Digest::of_bytes(contenuto.as_bytes());
    scrivi_impronta(directory, impronta.as_str());
}

/// Scrive il file di impronta, nella forma che lo script produce.
fn scrivi_impronta(directory: &Path, impronta: &str) {
    let percorso = directory.join(ACQUIRED_DIGEST_FILE);
    let testo = format!(
        "# Impronta di CIO' CHE E' STATO ACQUISITO.\r\n\
         # CALCOLATA DA NEXUM/97, NON DICHIARATA DA CISA.\r\n\
         calcolata_da:NEXUM/97\r\n\
         acquisito_il:2026-09-11T08:00:00Z\r\n\
         sha256:{}\r\n",
        impronta.to_uppercase()
    );
    let Ok(()) = std::fs::write(&percorso, testo) else {
        panic!("il file di impronta di prova deve potersi scrivere");
    };
}

/// Rilegge dall'archivio tutto ciò che è pubblicamente raggiungibile.
fn scarica_fotografia(database: &Database, identificativi: &[&str]) -> String {
    let Ok(fotografie) = database.kev_snapshots() else {
        panic!("le fotografie devono potersi rileggere");
    };
    let mut dump = format!("{fotografie:?}");
    for fotografia in &fotografie {
        // Le voci si rileggono attraverso la risoluzione, che e' l'unica strada
        // pubblica: se un campo vietato fosse entrato, uscirebbe di qui.
        for grezzo in identificativi {
            let Ok(id) = CveId::try_new(grezzo) else {
                continue;
            };
            if let Ok(esito) = database.resolve_kev(fotografia.id, &id) {
                dump.push_str(&format!("{esito:?}"));
                dump.push_str(&esito.as_sentence(&id));
            }
        }
    }
    dump
}

/// **L'ordine c'è nel file e non arriva nell'archivio.**
///
/// È la prova che il modulo non può dare da sé: la struttura di lettura dice che
/// il codice intende non prenderlo; qui si guarda il database, e la frase che un
/// operatore leggerebbe.
#[test]
fn l_ordine_del_file_non_arriva_nell_archivio() {
    let directory = temporary_directory("ordine");
    scrivi_catalogo(
        &directory,
        &[voce(
            "CVE-2026-86060",
            "RouterOS contiene un difetto.",
            RansomwareUse::UNKNOWN,
        )],
    );
    let mut database = archivio();

    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };
    assert_eq!(esito.entries, 1);
    assert_eq!(esito.declared_count, 1);

    let dump = scarica_fotografia(&database, &["CVE-2026-86060"]);
    for vietato in [
        "2026-09-13",
        "BOD 26-04",
        "Apply mitigations",
        "forensicTriage",
        "CWE-88",
        "esempio.test",
    ] {
        assert!(
            !dump.contains(vietato),
            "l'archivio non deve contenere «{vietato}»: è un ordine rivolto alle \
             agenzie federali statunitensi, oppure un collegamento che il prodotto \
             non segue"
        );
    }

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un catalogo il cui conteggio non corrisponde non si importa.**
///
/// È l'unica integrità che la fonte offre **di sé**: se il numero dichiarato non
/// torna, il file è stato troncato, tagliato o modificato.
#[test]
fn un_conteggio_che_non_corrisponde_ferma_l_importazione() {
    let directory = temporary_directory("conteggio");
    scrivi_catalogo_con_conteggio(
        &directory,
        &[voce(
            "CVE-2026-86060",
            "RouterOS contiene un difetto.",
            RansomwareUse::UNKNOWN,
        )],
        1705,
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    assert!(matches!(esito, Err(ServiceError::KevImportRefused { .. })));

    let Ok(fotografie) = database.kev_snapshots() else {
        panic!("le fotografie devono potersi rileggere");
    };
    assert!(
        fotografie.is_empty(),
        "un catalogo rifiutato non deve lasciare una fotografia in archivio"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un catalogo cambiato dopo l'acquisizione non si importa.**
#[test]
fn un_catalogo_cambiato_dopo_l_acquisizione_si_rifiuta() {
    let directory = temporary_directory("impronta");
    scrivi_catalogo(
        &directory,
        &[voce(
            "CVE-2026-86060",
            "RouterOS contiene un difetto.",
            RansomwareUse::UNKNOWN,
        )],
    );
    // Si riscrive l'impronta con quella di un altro contenuto.
    scrivi_impronta(&directory, Sha256Digest::of_text("qualcos'altro").as_str());

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    assert!(matches!(esito, Err(ServiceError::KevImportRefused { .. })));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un file di impronta senza impronta ferma tutto**: è ciò contro cui si
/// verifica.
#[test]
fn un_file_di_impronta_senza_impronta_ferma_l_importazione() {
    let directory = temporary_directory("impronta-vuota");
    scrivi_catalogo(
        &directory,
        &[voce(
            "CVE-2026-86060",
            "RouterOS contiene un difetto.",
            RansomwareUse::UNKNOWN,
        )],
    );
    let percorso = directory.join(ACQUIRED_DIGEST_FILE);
    let Ok(()) = std::fs::write(&percorso, "calcolata_da:NEXUM/97\r\n") else {
        panic!("il file di prova deve potersi scrivere");
    };

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    assert!(matches!(esito, Err(ServiceError::KevImportRefused { .. })));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un catalogo che non dice di quando è non si importa.**
///
/// Senza la propria identità, l'esito negativo della risoluzione sarebbe
/// inesprimibile: «non elencata» senza un confine si legge come «non sfruttata».
#[test]
fn un_catalogo_senza_identita_ferma_l_importazione() {
    let directory = temporary_directory("senza-identita");
    let contenuto = r#"{
      "catalogVersion": "",
      "dateReleased": "",
      "count": 0,
      "vulnerabilities": []
    }"#;
    let catalogo = directory.join(CATALOGUE_FILE);
    let Ok(()) = std::fs::write(&catalogo, contenuto) else {
        panic!("il catalogo di prova deve potersi scrivere");
    };
    scrivi_impronta(
        &directory,
        Sha256Digest::of_bytes(contenuto.as_bytes()).as_str(),
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    assert!(matches!(esito, Err(ServiceError::KevImportRefused { .. })));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Una voce deformata si omette con il motivo, e non ferma il catalogo.**
///
/// Una fotografia a cui manca una voce senza dirlo risponde «non elencata» a una
/// domanda a cui CISA risponde di sì.
#[test]
fn una_voce_deformata_si_omette_con_il_motivo() {
    let directory = temporary_directory("deformata");
    scrivi_catalogo(
        &directory,
        &[
            voce(
                "CVE-2026-86060",
                "RouterOS contiene un difetto.",
                RansomwareUse::UNKNOWN,
            ),
            voce("NON-UN-IDENTIFICATIVO", "qualcosa", RansomwareUse::UNKNOWN),
        ],
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };
    assert_eq!(esito.entries, 1);
    assert_eq!(esito.omitted.len(), 1);
    assert_eq!(
        esito.omitted[0].reason,
        KevOmissionReason::MalformedIdentifier
    );
    assert_eq!(esito.omitted[0].declared_id, "NON-UN-IDENTIFICATIVO");

    let _ = std::fs::remove_dir_all(&directory);
}

/// **I due esiti, letti come li leggerebbe una persona.**
///
/// È la milestone: «non elencata» deve dire per esteso che non significa «non
/// sfruttata», e «elencata» deve attribuire l'affermazione a CISA.
#[test]
fn i_due_esiti_si_leggono_come_li_leggerebbe_una_persona() {
    let directory = temporary_directory("due-esiti");
    scrivi_catalogo(
        &directory,
        &[voce(
            "CVE-2026-86060",
            "RouterOS contiene un difetto.",
            RansomwareUse::KNOWN,
        )],
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };

    let service = KevSnapshotService::new(&mut database);

    let elencato = identificativo("CVE-2026-86060");
    let Ok(trovata) = service.resolve(esito.snapshot_id, &elencato) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(trovata, KevResolution::Listed(_)));
    let frase = trovata.as_sentence(&elencato);
    assert!(frase.contains("CISA dichiara di aver constatato"));
    assert!(frase.contains("CISA dichiara noto un impiego"));

    let assente = identificativo("CVE-2019-1234");
    let Ok(non_elencata) = service.resolve(esito.snapshot_id, &assente) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(non_elencata, KevResolution::NotListed { .. }));
    let frase = non_elencata.as_sentence(&assente);
    assert!(frase.contains("Non significa che non sia stata sfruttata"));
    assert!(frase.contains("2026.09.10"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **«Unknown» non diventa «no» nemmeno attraversando l'archivio.**
#[test]
fn unknown_resta_unknown_anche_dopo_l_archivio() {
    let directory = temporary_directory("unknown");
    scrivi_catalogo(
        &directory,
        &[voce(
            "CVE-2026-86060",
            "RouterOS contiene un difetto.",
            RansomwareUse::UNKNOWN,
        )],
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };

    let service = KevSnapshotService::new(&mut database);
    let id = identificativo("CVE-2026-86060");
    let Ok(trovata) = service.resolve(esito.snapshot_id, &id) else {
        panic!("la risoluzione deve riuscire");
    };
    let frase = trovata.as_sentence(&id);
    assert!(frase.contains("Non significa che non sia avvenuto"));
    assert!(!frase.contains("nessun impiego"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un identificativo ripetuto si omette con il motivo, e non sparisce.**
///
/// È l'unica strada per cui una voce potrebbe non entrare senza dirlo: la
/// chiave primaria della fotografia non ammette la seconda riga.
#[test]
fn un_identificativo_ripetuto_si_omette_con_il_motivo() {
    let directory = temporary_directory("duplicato");
    scrivi_catalogo(
        &directory,
        &[
            voce(
                "CVE-2026-86060",
                "RouterOS contiene un difetto.",
                RansomwareUse::UNKNOWN,
            ),
            voce(
                "CVE-2026-86060",
                "la stessa voce, una seconda volta.",
                RansomwareUse::KNOWN,
            ),
        ],
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };
    assert_eq!(esito.entries, 1);
    assert_eq!(esito.omitted.len(), 1);
    assert_eq!(
        esito.omitted[0].reason,
        KevOmissionReason::DuplicateIdentifier
    );
    // OGNI VOCE DEL CATALOGO E' CONTATA: o entra, o e' omessa con il motivo.
    assert_eq!(
        esito.entries + esito.omitted.len() as u64,
        esito.declared_count
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un catalogo oltre la misura non viene nemmeno interpretato.**
///
/// È questo tetto, non quello sulle voci, a limitare davvero la memoria: il
/// tetto sulle voci si può controllare solo dopo aver interpretato il documento.
#[test]
fn un_catalogo_oltre_la_misura_non_si_interpreta() {
    let directory = temporary_directory("misura");
    let riempitivo = "a".repeat(usize::try_from(MAX_CATALOGUE_BYTES).unwrap_or(usize::MAX));
    let contenuto = format!(
        r#"{{"catalogVersion":"2026.09.10","dateReleased":"2026-09-10T19:00:05Z","count":0,"vulnerabilities":[],"riempitivo":"{riempitivo}"}}"#
    );
    let catalogo = directory.join(CATALOGUE_FILE);
    let Ok(()) = std::fs::write(&catalogo, &contenuto) else {
        panic!("il catalogo di prova deve potersi scrivere");
    };
    scrivi_impronta(
        &directory,
        Sha256Digest::of_bytes(contenuto.as_bytes()).as_str(),
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };

    // SI CONTROLLA IL MOTIVO, NON SOLTANTO IL RIFIUTO.
    //
    // Un file oltre la misura viene troncato in lettura, quindi anche senza
    // alcun tetto l'impronta non corrisponderebbe e l'importazione fallirebbe
    // lo stesso: una prova che guardasse solo il rifiuto sarebbe verde anche
    // con la guardia tolta, e non dimostrerebbe nulla.
    let Err(ServiceError::KevImportRefused { reason }) = esito else {
        panic!("un catalogo oltre la misura doveva essere rifiutato");
    };
    assert!(
        reason.contains("oltre la misura ammessa"),
        "il rifiuto deve venire dal tetto sui byte, non da altro: «{reason}»"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Il file di impronta si legge come lo legge lo script: vince la prima.**
///
/// Se qui vincesse l'ultima, un file con due impronte supererebbe una verifica e
/// fallirebbe l'altra: due verità sulla stessa catena.
#[test]
fn il_file_di_impronta_si_legge_come_lo_legge_lo_script() {
    let directory = temporary_directory("due-impronte");
    scrivi_catalogo(
        &directory,
        &[voce(
            "CVE-2026-86060",
            "RouterOS contiene un difetto.",
            RansomwareUse::UNKNOWN,
        )],
    );

    // La prima riga porta l'impronta giusta; la seconda una sbagliata.
    let percorso = directory.join(ACQUIRED_DIGEST_FILE);
    let Ok(esistente) = std::fs::read_to_string(&percorso) else {
        panic!("il file di impronta di prova deve potersi rileggere");
    };
    let Some(giusta) = esistente
        .lines()
        .find_map(|riga| riga.strip_prefix("sha256:"))
    else {
        panic!("il file di impronta di prova deve dichiarare un'impronta");
    };
    let testo = format!(
        "calcolata_da:NEXUM/97\r\nsha256:{giusta}\r\nsha256:{sbagliata}\r\n",
        sbagliata = Sha256Digest::of_text("qualcos'altro").as_str(),
    );
    let Ok(()) = std::fs::write(&percorso, testo) else {
        panic!("il file di impronta di prova deve potersi scrivere");
    };

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&directory, &operator(), now())
    };
    assert!(
        esito.is_ok(),
        "vince la prima riga, come nello script: l'importazione deve riuscire"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Il catalogo vero di CISA si legge per intero.**
///
/// `ignored` perché richiede un file che il repository non conserva. Si esegue
/// con `cargo test -p lisi-services --test kev_snapshot -- --ignored`, dopo
/// `scripts\fetch-kev.ps1`.
#[test]
#[ignore = "richiede il catalogo KEV reale, scaricato da scripts/fetch-kev.ps1"]
fn il_catalogo_reale_di_cisa_si_importa() {
    let radice = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let cartella = radice.join("assets/kev");
    assert!(
        cartella.join(CATALOGUE_FILE).exists(),
        "il catalogo non c'è: eseguire prima scripts/fetch-kev.ps1"
    );

    let mut database = archivio();
    let esito = {
        let mut service = KevSnapshotService::new(&mut database);
        service.import(&cartella, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("il catalogo reale deve potersi importare");
    };

    assert!(
        esito.entries > 1_000,
        "il catalogo reale ha più di mille voci, ne sono entrate {}",
        esito.entries
    );
    assert_eq!(
        esito.entries + esito.omitted.len() as u64,
        esito.declared_count
    );
    assert!(!esito.catalog.version().is_empty());
    assert!(!esito.catalog.released_at().is_empty());

    // Una vulnerabilita' che CISA elenca davvero, e una che non elenca.
    let service = KevSnapshotService::new(&mut database);
    let Ok(elencata) = service.resolve(esito.snapshot_id, &identificativo("CVE-2021-44228")) else {
        panic!("la risoluzione deve riuscire");
    };
    let KevResolution::Listed(voce) = elencata else {
        panic!("CVE-2021-44228 (Log4Shell) doveva essere elencata da CISA");
    };
    assert!(!voce.short_description().is_empty());
    assert!(!voce.vendor_project().is_empty());

    let Ok(assente) = service.resolve(esito.snapshot_id, &identificativo("CVE-2003-99999")) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(assente, KevResolution::NotListed { .. }));
}

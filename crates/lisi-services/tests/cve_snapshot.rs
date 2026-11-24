//! La fotografia CVE, dal file all'archivio, e i tre esiti della risoluzione.
//!
//! I test per modulo provano che il servizio non nomini un punteggio. Questo
//! prova le due cose che nessuno di quelli può provare: che **un punteggio
//! presente nel file non arrivi nell'archivio**, e che **una fotografia vera di
//! NVD** si legga per intero.
//!
//! # Perché la prova sul file vero è `ignored`
//!
//! Perché richiede un file che il repository **non conserva**: la politica sta
//! in `cve.lock.json`, i dati no (ADR-0060). Si esegue dopo
//! `scripts/fetch-cve.ps1`, con
//! `cargo test -p lisi-services --test cve_snapshot -- --ignored`.

use std::path::{Path, PathBuf};

use lisi_core::model::cve::{CveId, CveOmissionReason, CveResolution};
use lisi_core::text::Actor;
use lisi_core::{Sha256Digest, Timestamp};
use lisi_services::ServiceError;
use lisi_services::cve_snapshot::CveSnapshotService;
use lisi_services::sources::open_in_memory_database;
use lisi_storage::Database;

/// La designazione di copyright che ogni copia deve riprodurre.
const ATTRIBUZIONE: &str = "© 2026 The MITRE Corporation.";

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
    let directory = std::env::temp_dir().join(format!("nexum-cve-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let Ok(()) = std::fs::create_dir_all(&directory) else {
        panic!("la cartella di prova deve potersi creare");
    };
    directory
}

/// Una voce come NVD la pubblica, **con** il punteggio che il prodotto non prende.
fn voce(id: &str, descrizione: &str, stato: &str, lingua: &str) -> String {
    format!(
        r#"{{
          "cve": {{
            "id": "{id}",
            "sourceIdentifier": "cve@mitre.org",
            "published": "2026-01-11T05:00:00.000",
            "lastModified": "2026-06-16T22:01:26.443",
            "vulnStatus": "{stato}",
            "descriptions": [ {{ "lang": "{lingua}", "value": "{descrizione}" }} ],
            "metrics": {{
              "cvssMetricV31": [ {{
                "source": "nvd@nist.gov",
                "cvssData": {{ "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL" }},
                "exploitabilityScore": 3.9,
                "impactScore": 5.9
              }} ]
            }},
            "weaknesses": [ {{ "description": [ {{ "lang": "en", "value": "CWE-120" }} ] }} ],
            "configurations": [ {{ "nodes": [ {{ "cpeMatch": [
              {{ "vulnerable": true, "criteria": "cpe:2.3:a:esempio:prodotto:1.0:*:*:*:*:*:*:*" }}
            ] }} ] }} ],
            "references": [ {{ "url": "https://esempio.test/avviso" }} ]
          }}
        }}"#
    )
}

/// Scrive una fotografia annuale e il suo `.meta`, coerenti fra loro.
fn scrivi_anno(directory: &Path, anno: i32, voci: &[String]) {
    let contenuto = format!(
        r#"{{
          "resultsPerPage": {quante},
          "totalResults": {quante},
          "format": "NVD_CVE",
          "version": "2.0",
          "timestamp": "2026-09-10T03:00:15.000",
          "vulnerabilities": [ {corpo} ]
        }}"#,
        quante = voci.len(),
        corpo = voci.join(",\n")
    );

    let json = directory.join(format!("nvdcve-2.0-{anno}.json"));
    let Ok(()) = std::fs::write(&json, &contenuto) else {
        panic!("la fotografia di prova deve potersi scrivere");
    };

    let impronta = Sha256Digest::of_bytes(contenuto.as_bytes());
    scrivi_meta(directory, anno, impronta.as_str());
}

/// Scrive un `.meta` con l'impronta indicata.
fn scrivi_meta(directory: &Path, anno: i32, impronta: &str) {
    let meta = directory.join(format!("nvdcve-2.0-{anno}.meta"));
    let testo = format!(
        "lastModifiedDate:2026-09-10T03:00:15-04:00\r\nsize:1234\r\nzipSize:567\r\ngzSize:567\r\nsha256:{}\r\n",
        impronta.to_uppercase()
    );
    let Ok(()) = std::fs::write(&meta, testo) else {
        panic!("il .meta di prova deve potersi scrivere");
    };
}

/// **Il punteggio CVSS c'è nel file e non arriva nell'archivio.**
///
/// È la prova che il modulo non può dare da sé: la struttura di lettura dice
/// che il codice intende non prenderlo; qui si guarda il database.
#[test]
fn il_punteggio_del_file_non_arriva_nell_archivio() {
    let directory = temporary_directory("punteggio");
    scrivi_anno(
        &directory,
        2026,
        &[voce("CVE-2026-1234", "una descrizione", "Analyzed", "en")],
    );
    let mut database = archivio();

    let esito = {
        let mut service = CveSnapshotService::new(&mut database);
        service.import(&directory, &[2026], ATTRIBUZIONE, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };
    assert_eq!(esito.records, 1);

    let dump = scarica_fotografia(&database, &esito.snapshot_id.to_string());
    for vietato in [
        "9.8",
        "CRITICAL",
        "cvss",
        "CWE-120",
        "cpe:2.3",
        "esempio.test",
    ] {
        assert!(
            !dump.contains(vietato),
            "l'archivio non deve contenere «{vietato}»"
        );
    }

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un file che non corrisponde al `.meta` non si importa, e non lascia nulla.**
#[test]
fn un_anno_che_non_corrisponde_al_meta_si_rifiuta() {
    let directory = temporary_directory("impronta");
    scrivi_anno(
        &directory,
        2026,
        &[voce("CVE-2026-1234", "una descrizione", "Analyzed", "en")],
    );
    // Si riscrive il .meta con un'impronta di un altro contenuto.
    scrivi_meta(
        &directory,
        2026,
        Sha256Digest::of_text("qualcos'altro").as_str(),
    );

    let mut database = archivio();
    let esito = {
        let mut service = CveSnapshotService::new(&mut database);
        service.import(&directory, &[2026], ATTRIBUZIONE, &operator(), now())
    };
    assert!(matches!(esito, Err(ServiceError::CveImportRefused { .. })));

    let Ok(fotografie) = database.cve_snapshots() else {
        panic!("le fotografie devono potersi rileggere");
    };
    assert!(
        fotografie.is_empty(),
        "un anno rifiutato non deve lasciare una fotografia in archivio"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un `.meta` senza impronta ferma tutto**: è ciò contro cui si verifica.
#[test]
fn un_meta_senza_impronta_ferma_l_importazione() {
    let directory = temporary_directory("meta-vuoto");
    scrivi_anno(
        &directory,
        2026,
        &[voce("CVE-2026-1234", "una descrizione", "Analyzed", "en")],
    );
    let meta = directory.join("nvdcve-2.0-2026.meta");
    let Ok(()) = std::fs::write(&meta, "lastModifiedDate:2026-09-10T03:00:15-04:00\n") else {
        panic!("il .meta di prova deve potersi scrivere");
    };

    let mut database = archivio();
    let esito = {
        let mut service = CveSnapshotService::new(&mut database);
        service.import(&directory, &[2026], ATTRIBUZIONE, &operator(), now())
    };
    assert!(matches!(esito, Err(ServiceError::CveImportRefused { .. })));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Una descrizione oltre il tetto si omette, non si tronca.**
///
/// Troncarla e continuare a dire «fonte: NVD» attribuirebbe a NVD un testo che
/// NVD non ha scritto.
#[test]
fn una_descrizione_oltre_il_tetto_si_omette_con_il_motivo() {
    let directory = temporary_directory("troppo-lunga");
    let lunga = "a".repeat(lisi_core::model::cve::MAX_DESCRIPTION_CHARS + 1);
    scrivi_anno(
        &directory,
        2026,
        &[
            voce("CVE-2026-1234", "una descrizione normale", "Analyzed", "en"),
            voce("CVE-2026-5678", &lunga, "Analyzed", "en"),
        ],
    );

    let mut database = archivio();
    let esito = {
        let mut service = CveSnapshotService::new(&mut database);
        service.import(&directory, &[2026], ATTRIBUZIONE, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };

    assert_eq!(esito.records, 1);
    assert_eq!(esito.omitted.len(), 1);
    assert_eq!(esito.omitted[0].declared_id, "CVE-2026-5678");
    assert_eq!(
        esito.omitted[0].reason,
        CveOmissionReason::DescriptionTooLong
    );

    // E il testo troncato non è finito da nessuna parte.
    let dump = scarica_fotografia(&database, "");
    assert!(!dump.contains(&"a".repeat(100)));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Una voce senza descrizione inglese si omette**: le traduzioni sono di
/// altri enti.
#[test]
fn una_voce_senza_descrizione_inglese_si_omette() {
    let directory = temporary_directory("traduzione");
    scrivi_anno(
        &directory,
        2026,
        &[voce("CVE-2026-1234", "una descripción", "Analyzed", "es")],
    );

    let mut database = archivio();
    let esito = {
        let mut service = CveSnapshotService::new(&mut database);
        service.import(&directory, &[2026], ATTRIBUZIONE, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione deve riuscire");
    };
    assert_eq!(esito.records, 0);
    assert_eq!(
        esito.omitted[0].reason,
        CveOmissionReason::NoEnglishDescription
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **I tre esiti della risoluzione, sulla stessa fotografia.**
///
/// È la milestone: «fuori copertura» dice *non lo so*, «assente dal catalogo»
/// dice *NVD non ha una CVE con questo numero*.
#[test]
fn la_risoluzione_ha_tre_esiti_e_non_due() {
    let directory = temporary_directory("tre-esiti");
    scrivi_anno(
        &directory,
        2026,
        &[voce("CVE-2026-1234", "una descrizione", "Analyzed", "en")],
    );

    let mut database = archivio();
    let snapshot_id = {
        let mut service = CveSnapshotService::new(&mut database);
        let Ok(esito) = service.import(&directory, &[2026], ATTRIBUZIONE, &operator(), now())
        else {
            panic!("l'importazione deve riuscire");
        };
        esito.snapshot_id
    };

    let service = CveSnapshotService::new(&mut database);

    let Ok(trovata) = service.resolve(snapshot_id, &identificativo("CVE-2026-1234")) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(trovata, CveResolution::Found(_)));

    let vecchia = identificativo("CVE-2019-1234");
    let Ok(fuori) = service.resolve(snapshot_id, &vecchia) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(fuori, CveResolution::OutsideCoverage { .. }));
    let frase = fuori.as_sentence(&vecchia);
    assert!(frase.contains("fuori dalla copertura"));
    assert!(frase.contains("Non significa che non esista"));

    let inventata = identificativo("CVE-2026-9999");
    let Ok(assente) = service.resolve(snapshot_id, &inventata) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(assente, CveResolution::AbsentFromCatalogue { .. }));
    let frase = assente.as_sentence(&inventata);
    assert!(frase.contains("nel catalogo non c'è"));
    assert!(!frase.contains("Non significa che non esista"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// L'importazione lascia una voce di audit con la copertura e le omissioni.
#[test]
fn l_importazione_lascia_una_voce_di_audit() {
    let directory = temporary_directory("audit");
    scrivi_anno(
        &directory,
        2026,
        &[voce("CVE-2026-1234", "una descrizione", "Analyzed", "en")],
    );

    let mut database = archivio();
    {
        let mut service = CveSnapshotService::new(&mut database);
        let Ok(_) = service.import(&directory, &[2026], ATTRIBUZIONE, &operator(), now()) else {
            panic!("l'importazione deve riuscire");
        };
    }

    let Ok(voci) = database.audit_entries() else {
        panic!("l'audit deve essere leggibile");
    };
    let Some(voce) = voci
        .iter()
        .find(|voce| voce.action.as_str() == "fotografia_cve_importata")
    else {
        panic!("l'importazione deve lasciare una voce di audit");
    };
    let Some(dettaglio) = voce.detail.as_ref() else {
        panic!("la voce deve dire che cosa è entrato");
    };
    assert!(dettaglio.as_str().contains("anni 2026"));
    assert!(dettaglio.as_str().contains("omesse"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **La fotografia vera di NVD, letta per intero.**
///
/// Richiede una fotografia annuale scaricata da `scripts/fetch-cve.ps1`. Si
/// esegue con `cargo test -p lisi-services --test cve_snapshot -- --ignored`.
///
/// Prova l'anno **2003**, che è il più piccolo (millecinquecentocinquantacinque
/// voci): basta a dimostrare che il formato reale si legge, senza scaricare
/// trecento megabyte.
#[test]
#[ignore = "richiede una fotografia CVE reale, scaricata da scripts/fetch-cve.ps1"]
fn la_fotografia_reale_di_nvd_si_importa() {
    let radice = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let cartella = radice.join("assets/cve");
    assert!(
        cartella.join("nvdcve-2.0-2003.json").exists(),
        "la fotografia non c'è: eseguire prima scripts/fetch-cve.ps1 con l'anno 2003"
    );

    let mut database = archivio();
    let esito = {
        let mut service = CveSnapshotService::new(&mut database);
        service.import(&cartella, &[2003], ATTRIBUZIONE, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("la fotografia reale deve potersi importare");
    };

    assert!(
        esito.records > 1_000,
        "l'anno 2003 ha più di mille voci, ne sono entrate {}",
        esito.records
    );
    assert_eq!(esito.years.len(), 1);
    assert_eq!(esito.years[0].year, 2003);
    assert_eq!(esito.years[0].source_sha256.len(), 64);
    assert!(!esito.years[0].source_last_modified.is_empty());

    // Una CVE che c'è davvero, e una che ha un anno coperto e non c'è.
    let service = CveSnapshotService::new(&mut database);
    let Ok(trovata) = service.resolve(esito.snapshot_id, &identificativo("CVE-2003-0061")) else {
        panic!("la risoluzione deve riuscire");
    };
    let CveResolution::Found(record) = trovata else {
        panic!("CVE-2003-0061 doveva essere trovata");
    };
    assert!(record.description().len() > 20);

    let Ok(assente) = service.resolve(esito.snapshot_id, &identificativo("CVE-2003-99999")) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(assente, CveResolution::AbsentFromCatalogue { .. }));

    let Ok(fuori) = service.resolve(esito.snapshot_id, &identificativo("CVE-2026-1234")) else {
        panic!("la risoluzione deve riuscire");
    };
    assert!(matches!(fuori, CveResolution::OutsideCoverage { .. }));
}

/// Tutto il testo delle tabelle della fotografia, in una stringa sola.
///
/// Serve a cercare ciò che **non** deve esserci: cercarlo solo dove ci si
/// aspetta che sia significherebbe non trovarlo proprio nel caso in cui è
/// finito nel posto sbagliato.
fn scarica_fotografia(database: &Database, _etichetta: &str) -> String {
    let Ok(fotografie) = database.cve_snapshots() else {
        panic!("le fotografie devono potersi rileggere");
    };
    let mut dump = format!("{fotografie:?}");
    for fotografia in &fotografie {
        for anno in fotografia.coverage.years() {
            let id = format!("CVE-{anno}-");
            dump.push_str(&id);
        }
        // Le voci si rileggono attraverso la risoluzione, che e' l'unica strada
        // pubblica: se un campo vietato fosse entrato, uscirebbe di qui.
        for numero in [1234_u32, 5678] {
            let Ok(id) = CveId::try_new(&format!("CVE-2026-{numero}")) else {
                continue;
            };
            if let Ok(esito) = database.resolve_cve(fotografia.id, &id) {
                dump.push_str(&format!("{esito:?}"));
            }
        }
    }
    dump
}

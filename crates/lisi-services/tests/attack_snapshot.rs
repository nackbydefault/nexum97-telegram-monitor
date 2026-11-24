//! L'importazione della fotografia ATT&CK, dal file all'archivio.
//!
//! I test per modulo provano che il pacchetto si sappia leggere. Questo prova
//! le due cose che nessuno di quelli può provare: che l'**impronta** venga
//! davvero riverificata al momento dell'importazione, e che il **pacchetto
//! vero** — cinquantaquattro megabyte scaricati da MITRE — si legga per intero
//! senza che nulla di ciò che non deve entrare entri.
//!
//! # Perché la prova sul pacchetto vero è `ignored`
//!
//! Perché richiede un file che il repository **non conserva**: le impronte
//! stanno in `attack.lock.json`, i dati no (ADR-0058). La prova si esegue dopo
//! `scripts/fetch-attack.ps1`, con
//! `cargo test -p lisi-services --test attack_snapshot -- --ignored`.
//! Saltarla in silenzio quando il file non c'è la renderebbe una prova che non
//! può fallire, cioè il genere peggiore: **dichiara di essere ignorata**.

use std::path::{Path, PathBuf};

use lisi_core::model::attack::MITRE_ATTRIBUTION;
use lisi_core::text::Actor;
use lisi_core::{Sha256Digest, Timestamp};
use lisi_services::ServiceError;
use lisi_services::attack_snapshot::AttackSnapshotService;
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

/// Un pacchetto minimo, della forma che ATT&CK produce, con dentro un attore.
const PACCHETTO: &str = r#"{
  "type": "bundle",
  "id": "bundle--0",
  "objects": [
    {"type": "x-mitre-collection", "name": "Enterprise ATT&CK",
     "x_mitre_version": "19.2", "x_mitre_attack_spec_version": "3.3.0"},
    {"type": "x-mitre-tactic", "name": "Execution", "description": "descrizione",
     "x_mitre_shortname": "execution",
     "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002",
                              "url": "https://attack.mitre.org/tactics/TA0002"}]},
    {"type": "attack-pattern", "name": "Command and Scripting Interpreter",
     "description": "descrizione", "revoked": false, "x_mitre_deprecated": false,
     "x_mitre_version": "2.5", "x_mitre_domains": ["enterprise-attack"],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1059",
                              "url": "https://attack.mitre.org/techniques/T1059"}]},
    {"type": "intrusion-set", "name": "Gruppo Inventato",
     "description": "un gruppo che questo prodotto non deve nominare",
     "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}]},
    {"type": "relationship", "relationship_type": "uses"}
  ]
}"#;

fn temporary_directory(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("nexum-attack-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let Ok(()) = std::fs::create_dir_all(&directory) else {
        panic!("la cartella di prova deve potersi creare");
    };
    directory
}

/// Scrive pacchetto e licenza in una cartella di prova.
fn prepara(directory: &Path, pacchetto: &str, licenza: &str) -> (PathBuf, PathBuf, Sha256Digest) {
    let bundle = directory.join("attack.json");
    let license = directory.join("LICENSE.txt");
    let (Ok(()), Ok(())) = (
        std::fs::write(&bundle, pacchetto),
        std::fs::write(&license, licenza),
    ) else {
        panic!("i file di prova devono potersi scrivere");
    };
    let digest = Sha256Digest::of_bytes(pacchetto.as_bytes());
    (bundle, license, digest)
}

fn licenza_valida() -> String {
    format!("License\n-------\nqualcosa\n\n\"{MITRE_ATTRIBUTION}\"\n")
}

fn archivio() -> Database {
    let Ok(database) = open_in_memory_database() else {
        panic!("il database in memoria deve potersi aprire");
    };
    database
}

#[test]
fn una_fotografia_si_importa_e_lascia_fuori_gli_attori() {
    let directory = temporary_directory("importazione");
    let (bundle, license, digest) = prepara(&directory, PACCHETTO, &licenza_valida());
    let mut database = archivio();

    let esito = {
        let mut service = AttackSnapshotService::new(&mut database);
        service.import(&bundle, &license, &digest, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("l'importazione del pacchetto di prova deve riuscire");
    };

    assert_eq!(esito.attack_version, "19.2");
    assert_eq!(esito.domain, "enterprise-attack");
    assert_eq!(esito.techniques, 1);
    assert_eq!(esito.tactics, 1);
    assert_eq!(esito.actors_ignored, 1, "il gruppo doveva essere contato");

    let Ok(tecniche) = database.attack_techniques(esito.snapshot_id) else {
        panic!("le tecniche devono potersi rileggere");
    };
    assert_eq!(tecniche.len(), 1);
    assert_eq!(tecniche[0].id().as_str(), "T1059");

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Il nome del gruppo non finisce da nessuna parte nell'archivio.**
///
/// È la prova che il modulo non può dare da sé: la struttura in memoria dice
/// che il codice intende non scriverlo; qui si guarda il database.
#[test]
fn il_nome_di_un_attore_non_finisce_nell_archivio() {
    let directory = temporary_directory("attori");
    let (bundle, license, digest) = prepara(&directory, PACCHETTO, &licenza_valida());
    let mut database = archivio();

    {
        let mut service = AttackSnapshotService::new(&mut database);
        let Ok(_) = service.import(&bundle, &license, &digest, &operator(), now()) else {
            panic!("l'importazione deve riuscire");
        };
    }

    // Si interrogano TUTTE le tabelle della fotografia, non quelle che ci si
    // aspetta contengano qualcosa: un nome finito nel posto sbagliato non
    // sarebbe nel posto in cui lo si cerca.
    let dump = scarica_fotografia(&database);
    for vietato in [
        "Gruppo Inventato",
        "G0001",
        "intrusion-set",
        "non deve nominare",
    ] {
        assert!(
            !dump.contains(vietato),
            "l'archivio non deve contenere «{vietato}»"
        );
    }

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Un pacchetto con un'altra impronta non si importa.**
#[test]
fn un_pacchetto_con_un_altra_impronta_si_rifiuta() {
    let directory = temporary_directory("impronta");
    let (bundle, license, _) = prepara(&directory, PACCHETTO, &licenza_valida());
    let mut database = archivio();
    let altra = Sha256Digest::of_text("qualcos'altro");

    let esito = {
        let mut service = AttackSnapshotService::new(&mut database);
        service.import(&bundle, &license, &altra, &operator(), now())
    };
    assert!(matches!(
        esito,
        Err(ServiceError::AttackImportRefused { .. })
    ));

    let Ok(fotografie) = database.attack_snapshots() else {
        panic!("le fotografie devono potersi rileggere");
    };
    assert!(
        fotografie.is_empty(),
        "un pacchetto rifiutato non deve lasciare nulla in archivio"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Se la licenza non porta più la designazione di copyright, non si importa.**
///
/// La condizione della licenza è riprodurla: se MITRE l'ha cambiata, deve
/// vederlo una persona, non essere aggirata copiando quello che c'è.
#[test]
fn una_licenza_senza_designazione_di_copyright_rifiuta_l_importazione() {
    let directory = temporary_directory("licenza");
    let (bundle, license, digest) = prepara(
        &directory,
        PACCHETTO,
        "License\n-------\nMITRE ha riscritto la propria licenza",
    );
    let mut database = archivio();

    let esito = {
        let mut service = AttackSnapshotService::new(&mut database);
        service.import(&bundle, &license, &digest, &operator(), now())
    };
    assert!(matches!(
        esito,
        Err(ServiceError::AttackImportRefused { .. })
    ));

    let _ = std::fs::remove_dir_all(&directory);
}

/// L'importazione lascia una voce di audit con l'impronta.
#[test]
fn l_importazione_lascia_una_voce_di_audit() {
    let directory = temporary_directory("audit");
    let (bundle, license, digest) = prepara(&directory, PACCHETTO, &licenza_valida());
    let mut database = archivio();

    {
        let mut service = AttackSnapshotService::new(&mut database);
        let Ok(_) = service.import(&bundle, &license, &digest, &operator(), now()) else {
            panic!("l'importazione deve riuscire");
        };
    }

    let Ok(voci) = database.audit_entries() else {
        panic!("l'audit deve essere leggibile");
    };
    let Some(voce) = voci
        .iter()
        .find(|voce| voce.action.as_str() == "fotografia_attack_importata")
    else {
        panic!("l'importazione deve lasciare una voce di audit");
    };
    let Some(dettaglio) = voce.detail.as_ref() else {
        panic!("la voce deve dire che cosa è entrato");
    };
    assert!(dettaglio.as_str().contains(digest.as_str()));
    assert!(dettaglio.as_str().contains("lasciati fuori"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// **Il pacchetto vero di MITRE, letto per intero.**
///
/// Richiede `assets/attack/enterprise-attack-19.2.json`, che il repository non
/// conserva: si esegue dopo `scripts/fetch-attack.ps1`, con
/// `cargo test -p lisi-services --test attack_snapshot -- --ignored`.
///
/// I numeri attesi sono quelli **letti** dal pacchetto fissato in
/// `attack.lock.json`, non ricordati: 858 tecniche, 15 tattiche, e 1075 oggetti
/// che nominano attori — 191 gruppi, 56 campagne, 733 malware, 95 strumenti —
/// che **non entrano**.
#[test]
#[ignore = "richiede il pacchetto ATT&CK reale, scaricato da scripts/fetch-attack.ps1"]
fn il_pacchetto_reale_di_mitre_si_importa_per_intero() {
    let radice = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let bundle = radice.join("assets/attack/enterprise-attack-19.2.json");
    let license = radice.join("assets/attack/licenses/MITRE-ATTACK-LICENSE.txt");

    assert!(
        bundle.exists(),
        "il pacchetto non c'è: eseguire prima scripts/fetch-attack.ps1"
    );

    let Ok(file) = std::fs::File::open(&bundle) else {
        panic!("il pacchetto deve potersi aprire");
    };
    let Ok(digest) = Sha256Digest::of_reader(std::io::BufReader::new(file)) else {
        panic!("l'impronta del pacchetto deve potersi calcolare");
    };
    assert_eq!(
        digest.as_str(),
        "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
        "il pacchetto non è quello fissato in attack.lock.json"
    );

    let mut database = archivio();
    let esito = {
        let mut service = AttackSnapshotService::new(&mut database);
        service.import(&bundle, &license, &digest, &operator(), now())
    };
    let Ok(esito) = esito else {
        panic!("il pacchetto reale deve potersi importare");
    };

    assert_eq!(esito.attack_version, "19.2");
    assert_eq!(esito.domain, "enterprise-attack");
    assert_eq!(esito.techniques, 858, "le tecniche del pacchetto fissato");
    assert_eq!(esito.tactics, 15, "le tattiche del pacchetto fissato");
    assert_eq!(
        esito.actors_ignored, 1075,
        "gli oggetti che nominano attori, e che non entrano"
    );

    let dump = scarica_fotografia(&database);

    // NESSUN OGGETTO ATTORE E' ENTRATO.
    //
    // Si cercano gli IDENTIFICATIVI STIX, non le parole: «malware» compare
    // legittimamente nella prosa di MITRE - «change the on-disk representation
    // of malware» - ed e' un sostantivo comune dentro la descrizione di un
    // comportamento, non un oggetto. Una guardia sulla parola sarebbe rossa
    // per la ragione sbagliata, e qualcuno la allenterebbe.
    for vietato in [
        "intrusion-set--",
        "malware--",
        "campaign--",
        "tool--",
        "course-of-action--",
    ] {
        assert!(
            !dump.contains(vietato),
            "l'archivio non deve contenere un oggetto «{vietato}»"
        );
    }

    // E NESSUNA DESCRIZIONE RIMANDA A UN ATTORE.
    //
    // Le descrizioni sono prosa di MITRE, e contengono collegamenti in
    // Markdown alle proprie pagine. Nel pacchetto 19.2 **nessuna** rimanda a
    // un gruppo o a una campagna: e' un fatto verificato, non una speranza, ed
    // e' la ragione per cui vale la pena sorvegliarlo. Se una versione futura
    // di ATT&CK introducesse un rimando a un gruppo dentro la descrizione di
    // una tecnica, questa prova diventerebbe rossa e qualcuno guarderebbe.
    //
    // I rimandi a `/software/` invece CI SONO, ed e' dichiarato in ADR-0058:
    // sono testo di MITRE che descrive come una tecnica viene eseguita, non
    // un'entita' che questo prodotto possa interrogare o collegare a qualcuno.
    for attore in ["attack.mitre.org/groups/", "attack.mitre.org/campaigns/"] {
        assert!(
            !dump.contains(attore),
            "nessuna descrizione deve rimandare a «{attore}»"
        );
    }

    // Ogni identificativo conservato e' una tecnica, non un gruppo o un software.
    let Ok(tecniche) = database.attack_techniques(esito.snapshot_id) else {
        panic!("le tecniche devono potersi rileggere");
    };
    for tecnica in &tecniche {
        let id = tecnica.id().as_str();
        assert!(
            id.starts_with('T'),
            "«{id}» non è l'identificativo di una tecnica"
        );
    }
    assert_eq!(tecniche.len(), 858);
}

/// Tutto il testo delle tabelle della fotografia, in una stringa sola.
///
/// Serve a cercare ciò che **non** deve esserci: cercarlo solo dove ci si
/// aspetta che sia significherebbe non trovarlo proprio nel caso in cui è
/// finito nel posto sbagliato.
fn scarica_fotografia(database: &Database) -> String {
    let Ok(fotografie) = database.attack_snapshots() else {
        panic!("le fotografie devono potersi rileggere");
    };
    let mut dump = format!("{fotografie:?}");
    for fotografia in &fotografie {
        let (Ok(tecniche), Ok(tattiche)) = (
            database.attack_techniques(fotografia.id),
            database.attack_tactics(fotografia.id),
        ) else {
            panic!("tecniche e tattiche devono potersi rileggere");
        };
        dump.push_str(&format!("{tecniche:?}{tattiche:?}"));
    }
    dump
}

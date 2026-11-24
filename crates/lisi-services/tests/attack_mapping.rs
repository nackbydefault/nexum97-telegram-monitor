//! La catena intera: un contenuto, un termine riscontrato, una tecnica associata.
//!
//! I test per modulo provano che gli atti si registrino. Questo prova la cosa
//! che nessuno di quelli può provare: che la **coppia con cui un riscontro è
//! scritto** e la **coppia con cui un'associazione è dichiarata** combacino
//! davvero, senza che nessuno debba indovinare.
//!
//! È la ragione per cui ADR-0059 ha scelto quella chiave e non un
//! `dictionary_term_id`: qui si vede se la scelta regge.

use lisi_core::model::AcquisitionOrigin;
use lisi_core::model::attack::{
    AttackSnapshot, AttackTactic, AttackTacticId, AttackTechnique, AttackTechniqueId,
    NewAttackTechnique,
};
use lisi_core::model::attack_association::{
    AssociatedTerm, AttackAssociationWithdrawal, NewAttackAssociation,
};
use lisi_core::model::dictionary::{
    ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
};
use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
use lisi_core::text::{
    Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier, TermCategory,
    TermText,
};
use lisi_core::{AttackSnapshotId, ContentId, Sha256Digest, Timestamp};
use lisi_services::analysis::{AnalysisService, NewContentDraft};
use lisi_services::attack_mapping::AttackMappingService;
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

fn termine() -> AssociatedTerm {
    let Ok(termine) = AssociatedTerm::new("molotov", "oggetto") else {
        panic!("il termine di prova deve essere valido");
    };
    termine
}

fn tecnica_id(raw: &str) -> AttackTechniqueId {
    let Ok(id) = AttackTechniqueId::try_new(raw) else {
        panic!("l'identificativo di prova deve essere valido");
    };
    id
}

/// Una fotografia con una tattica e una tecnica.
fn fotografia(database: &mut Database) -> AttackSnapshotId {
    let Ok(tactic_id) = AttackTacticId::try_new("TA0002") else {
        panic!("l'identificativo di prova deve essere valido");
    };
    let Ok(tactic) = AttackTactic::new(tactic_id, "execution", "Execution", "descrizione") else {
        panic!("la tattica di prova deve essere valida");
    };
    let Ok(technique) = AttackTechnique::new(NewAttackTechnique {
        id: tecnica_id("T1234"),
        name: "Nome della tecnica",
        description: "descrizione della tecnica",
        tactics: vec![String::from("execution")],
        deprecated: false,
        revoked: false,
        object_version: "1.0",
        url: "https://attack.mitre.org/techniques/T1234",
    }) else {
        panic!("la tecnica di prova deve essere valida");
    };
    let Ok(snapshot) = AttackSnapshot::new(
        "enterprise-attack",
        "19.2",
        "3.3.0",
        "License\n-------\n…",
        vec![tactic],
        vec![technique],
    ) else {
        panic!("la fotografia di prova deve essere valida");
    };

    let Ok(id) = database.insert_attack_snapshot(
        &snapshot,
        &Sha256Digest::of_text("pacchetto"),
        &operator(),
        now(),
    ) else {
        panic!("la fotografia deve potersi registrare");
    };
    id
}

/// Archivio con un contenuto che riscontra «molotov» e uno che non riscontra
/// nulla.
fn archivio() -> (Database, ContentId, ContentId) {
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
    let mut identificativi = Vec::new();
    for (indice, testo) in ["hanno parlato di una molotov", "buongiorno a tutti"]
        .iter()
        .enumerate()
    {
        let Ok(indice) = i64::try_from(indice) else {
            panic!("l'indice deve stare in un intero");
        };
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new(&format!("m{indice}")),
            ContentBody::try_new(testo),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let Ok(record) = analysis.analyse_and_record(
            &NewContentDraft {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
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
        let Some(content_id) = record.content_id else {
            panic!("il contenuto di prova deve essere nuovo e registrato");
        };
        identificativi.push(content_id);
    }

    let [con_riscontro, senza_riscontro] = identificativi[..] else {
        panic!("servono esattamente due contenuti");
    };
    (analysis.into_database(), con_riscontro, senza_riscontro)
}

fn atto() -> NewAttackAssociation {
    NewAttackAssociation {
        term: termine(),
        technique: tecnica_id("T1234"),
        reason: String::from("il termine ricorre nei materiali che descrivono quella tecnica"),
        declared_by: operator(),
        declared_at: now(),
    }
}

/// **La coppia con cui un riscontro è scritto e quella con cui un'associazione è
/// dichiarata combaciano.**
///
/// È la scelta di ADR-0059 messa alla prova: se non combaciassero, la domanda
/// «quali tecniche riguardano questo contenuto» resterebbe senza risposta, e
/// nessun test per modulo lo direbbe.
#[test]
fn un_contenuto_che_riscontra_il_termine_trova_la_tecnica() {
    let (mut database, con_riscontro, senza_riscontro) = archivio();
    let snapshot_id = fotografia(&mut database);

    {
        let mut service = AttackMappingService::new(&mut database);
        let Ok(_) = service.declare(snapshot_id, atto()) else {
            panic!("la dichiarazione deve riuscire");
        };
    }

    let service = AttackMappingService::new(&mut database);
    let Ok(trovate) = service.for_content(con_riscontro) else {
        panic!("la lettura deve riuscire");
    };
    assert_eq!(trovate.len(), 1);
    assert_eq!(trovate[0].technique().as_str(), "T1234");
    assert_eq!(trovate[0].attack_version(), "19.2");

    let Ok(nessuna) = service.for_content(senza_riscontro) else {
        panic!("la lettura deve riuscire");
    };
    assert!(
        nessuna.is_empty(),
        "un contenuto che non riscontra il termine non deve portare tecniche"
    );
}

/// **La frase che il contenuto porta non attribuisce nulla a nessuno.**
#[test]
fn la_frase_del_contenuto_non_attribuisce() {
    let (mut database, con_riscontro, _) = archivio();
    let snapshot_id = fotografia(&mut database);
    {
        let mut service = AttackMappingService::new(&mut database);
        let Ok(_) = service.declare(snapshot_id, atto()) else {
            panic!("la dichiarazione deve riuscire");
        };
    }

    let service = AttackMappingService::new(&mut database);
    let Ok(trovate) = service.for_content(con_riscontro) else {
        panic!("la lettura deve riuscire");
    };
    let frase = trovate[0].as_sentence();

    assert!(frase.contains("è associato alla tecnica T1234"));
    assert!(
        frase
            .to_lowercase()
            .contains("non dice che qualcuno l'abbia impiegata")
    );
    for vietato in [
        "ha usato",
        "ha impiegato",
        "ha eseguito",
        "attaccante",
        "responsabile",
        "adversary",
    ] {
        assert!(
            !frase.to_lowercase().contains(vietato),
            "la frase non deve contenere «{vietato}»: {frase}"
        );
    }
}

/// **Il motivo di chi ha dichiarato viaggia con la tecnica.**
///
/// Chi legge un riferimento dentro un rapporto deve poter sapere su quale base
/// esiste, e la base è una persona con un nome e una data.
#[test]
fn il_motivo_e_chi_ha_dichiarato_viaggiano_con_la_tecnica() {
    let (mut database, con_riscontro, _) = archivio();
    let snapshot_id = fotografia(&mut database);
    {
        let mut service = AttackMappingService::new(&mut database);
        let Ok(_) = service.declare(snapshot_id, atto()) else {
            panic!("la dichiarazione deve riuscire");
        };
    }

    let service = AttackMappingService::new(&mut database);
    let Ok(trovate) = service.for_content(con_riscontro) else {
        panic!("la lettura deve riuscire");
    };
    assert!(trovate[0].reason().contains("ricorre nei materiali"));
    assert_eq!(trovate[0].declared_by().as_str(), "operatore.prova");
    assert_eq!(trovate[0].declared_at(), now());
}

/// **Un'associazione senza motivo non si dichiara**, e non lascia nulla.
#[test]
fn un_associazione_senza_motivo_non_lascia_nulla() {
    let (mut database, _, _) = archivio();
    let snapshot_id = fotografia(&mut database);

    let esito = {
        let mut service = AttackMappingService::new(&mut database);
        service.declare(
            snapshot_id,
            NewAttackAssociation {
                reason: String::from("   "),
                ..atto()
            },
        )
    };
    assert!(esito.is_err());

    let service = AttackMappingService::new(&mut database);
    let Ok(trovate) = service.for_term(&termine()) else {
        panic!("la lettura deve riuscire");
    };
    assert!(trovate.is_empty());
}

/// **Ritirare toglie la tecnica dal contenuto, e lascia l'atto nell'audit.**
#[test]
fn ritirare_toglie_la_tecnica_dal_contenuto() {
    let (mut database, con_riscontro, _) = archivio();
    let snapshot_id = fotografia(&mut database);

    let id = {
        let mut service = AttackMappingService::new(&mut database);
        let Ok(id) = service.declare(snapshot_id, atto()) else {
            panic!("la dichiarazione deve riuscire");
        };
        id
    };

    {
        let mut service = AttackMappingService::new(&mut database);
        let Ok(()) = service.withdraw(
            id,
            AttackAssociationWithdrawal {
                reason: String::from("l'associazione era sbagliata"),
                withdrawn_by: operator(),
                withdrawn_at: now().plus_seconds(60),
            },
        ) else {
            panic!("il ritiro deve riuscire");
        };
    }

    let service = AttackMappingService::new(&mut database);
    let Ok(trovate) = service.for_content(con_riscontro) else {
        panic!("la lettura deve riuscire");
    };
    assert!(trovate.is_empty());

    let Ok(voci) = database.audit_entries() else {
        panic!("l'audit deve essere leggibile");
    };
    let azioni: Vec<&str> = voci.iter().map(|voce| voce.action.as_str()).collect();
    assert!(azioni.contains(&"associazione_attack_dichiarata"));
    assert!(azioni.contains(&"associazione_attack_ritirata"));

    let Some(ritiro) = voci
        .iter()
        .find(|voce| voce.action.as_str() == "associazione_attack_ritirata")
    else {
        panic!("il ritiro deve lasciare una voce");
    };
    let Some(dettaglio) = ritiro.detail.as_ref() else {
        panic!("il ritiro deve dire perché");
    };
    assert!(dettaglio.as_str().contains("era sbagliata"));
}

/// **Un termine con un'altra categoria è un altro termine.**
///
/// La stessa parola in due categorie diverse è due termini diversi: un'associazione
/// dichiarata sull'una non raggiunge l'altra, ed è corretto anche se a vista
/// sembrano lo stesso.
#[test]
fn la_stessa_parola_in_un_altra_categoria_non_e_lo_stesso_termine() {
    let (mut database, con_riscontro, _) = archivio();
    let snapshot_id = fotografia(&mut database);

    let Ok(altra) = AssociatedTerm::new("molotov", "azione") else {
        panic!("il termine di prova deve essere valido");
    };
    {
        let mut service = AttackMappingService::new(&mut database);
        let Ok(_) = service.declare(
            snapshot_id,
            NewAttackAssociation {
                term: altra,
                ..atto()
            },
        ) else {
            panic!("la dichiarazione deve riuscire");
        };
    }

    let service = AttackMappingService::new(&mut database);
    let Ok(trovate) = service.for_content(con_riscontro) else {
        panic!("la lettura deve riuscire");
    };
    assert!(
        trovate.is_empty(),
        "l'associazione dichiarata su un'altra categoria non deve raggiungere questo contenuto"
    );
}

/// **L'associazione non tocca il livello di analisi del contenuto.**
///
/// Un riferimento tassonomico non è un segnale: se lo fosse, il prodotto
/// direbbe «questo contenuto è più grave perché qualcuno ha collegato una sua
/// parola a una tecnica di attacco».
#[test]
fn un_associazione_non_alza_il_livello_del_contenuto() {
    let (mut database, con_riscontro, _) = archivio();
    let snapshot_id = fotografia(&mut database);

    let Ok(prima) = database.content(con_riscontro) else {
        panic!("il contenuto deve potersi rileggere");
    };

    {
        let mut service = AttackMappingService::new(&mut database);
        let Ok(_) = service.declare(snapshot_id, atto()) else {
            panic!("la dichiarazione deve riuscire");
        };
    }

    let Ok(dopo) = database.content(con_riscontro) else {
        panic!("il contenuto deve potersi rileggere");
    };
    assert_eq!(
        prima.analysis_level, dopo.analysis_level,
        "dichiarare un'associazione non deve cambiare il livello di analisi"
    );
}

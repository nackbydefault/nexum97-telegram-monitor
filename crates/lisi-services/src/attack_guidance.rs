//! Mitigazioni e rilevazioni di ATT&CK, dallo stesso pacchetto della
//! fotografia, e la scheda della tecnica (ATTACK-03, ADR-0185).
//!
//! # Perché un modulo a parte
//!
//! La fotografia ATT&CK prende tattiche e tecniche e lascia fuori gli attori
//! (ADR-0058). Qui si rilegge lo stesso pacchetto, già verificato con la sua
//! impronta, e se ne prendono soltanto contromisure, strategie di
//! rilevamento e i legami `mitigates` e `detects` verso una tecnica. Un
//! legame che parte da un attore o arriva altrove si scarta (decisione 5).

use std::collections::HashMap;

use lisi_core::AttackSnapshotId;
use lisi_core::model::attack::AttackTechniqueId;
use lisi_core::model::attack_guidance::{AttackGuidance, GuidanceKind};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// La frase che apre mitigazioni e rilevazioni nella scheda (decisione 6).
pub const WHAT_IT_IS: &str =
    "Ciò che ATT&CK suggerisce per difendersi da questa tecnica, e come riconoscerla.";

#[derive(serde::Deserialize)]
struct RawBundle {
    #[serde(default)]
    objects: Vec<RawObject>,
}

#[derive(serde::Deserialize)]
struct RawObject {
    #[serde(rename = "type")]
    object_type: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    external_references: Vec<RawReference>,
    #[serde(default)]
    revoked: bool,
    #[serde(default, rename = "x_mitre_deprecated")]
    deprecated: bool,
    #[serde(default)]
    relationship_type: Option<String>,
    #[serde(default)]
    source_ref: Option<String>,
    #[serde(default)]
    target_ref: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawReference {
    #[serde(default)]
    source_name: String,
    #[serde(default)]
    external_id: Option<String>,
}

impl RawObject {
    fn attack_id(&self) -> Option<&str> {
        self.external_references
            .iter()
            .find(|reference| reference.source_name == "mitre-attack")
            .and_then(|reference| reference.external_id.as_deref())
    }
}

/// Le mitigazioni e le rilevazioni del pacchetto, con le tecniche legate;
/// e quante voci non si sono potute leggere.
///
/// # Errori
///
/// [`ServiceError::AttackImportRefused`] se il pacchetto non si legge.
pub fn extract(bytes: &[u8]) -> ServiceResult<(Vec<AttackGuidance>, usize)> {
    let bundle: RawBundle =
        serde_json::from_slice(bytes).map_err(|_| ServiceError::AttackImportRefused {
            reason: "il pacchetto non è un file di dati leggibile",
        })?;

    // Le tecniche per identificativo STIX, e le voci candidate.
    let mut tecniche: HashMap<&str, AttackTechniqueId> = HashMap::new();
    let mut candidate: HashMap<&str, (GuidanceKind, &RawObject)> = HashMap::new();
    for oggetto in &bundle.objects {
        if oggetto.revoked || oggetto.deprecated {
            continue;
        }
        match oggetto.object_type.as_str() {
            "attack-pattern" => {
                if let Some(id) = oggetto
                    .attack_id()
                    .and_then(|id| AttackTechniqueId::try_new(id).ok())
                {
                    tecniche.insert(oggetto.id.as_str(), id);
                }
            }
            "course-of-action" => {
                candidate.insert(oggetto.id.as_str(), (GuidanceKind::Mitigation, oggetto));
            }
            "x-mitre-detection-strategy" => {
                candidate.insert(oggetto.id.as_str(), (GuidanceKind::Detection, oggetto));
            }
            _ => {}
        }
    }

    // I legami: soltanto da una candidata a una tecnica, del verbo giusto.
    let mut legami: HashMap<&str, Vec<AttackTechniqueId>> = HashMap::new();
    for oggetto in &bundle.objects {
        if oggetto.object_type != "relationship" || oggetto.revoked || oggetto.deprecated {
            continue;
        }
        let (Some(verbo), Some(da), Some(a)) = (
            oggetto.relationship_type.as_deref(),
            oggetto.source_ref.as_deref(),
            oggetto.target_ref.as_deref(),
        ) else {
            continue;
        };
        let (Some((genere, _)), Some(tecnica)) = (candidate.get(da), tecniche.get(a)) else {
            continue;
        };
        let atteso = match genere {
            GuidanceKind::Mitigation => "mitigates",
            GuidanceKind::Detection => "detects",
        };
        if verbo != atteso {
            continue;
        }
        let elenco = legami.entry(da).or_default();
        if !elenco.contains(tecnica) {
            elenco.push(tecnica.clone());
        }
    }

    let mut voci = Vec::new();
    let mut illeggibili = 0;
    let mut ordinate: Vec<_> = candidate.into_iter().collect();
    ordinate.sort_by(|a, b| a.0.cmp(b.0));
    for (stix, (genere, oggetto)) in ordinate {
        let tecniche_legate = legami.remove(stix).unwrap_or_default();
        if tecniche_legate.is_empty() {
            // Una voce che non si lega a nessuna tecnica della fotografia non
            // ha una scheda in cui stare.
            continue;
        }
        match AttackGuidance::new(
            genere,
            oggetto.attack_id().unwrap_or_default(),
            oggetto.name.as_deref().unwrap_or_default(),
            oggetto.description.as_deref().unwrap_or_default(),
            tecniche_legate,
        ) {
            Some(voce) => voci.push(voce),
            None => illeggibili += 1,
        }
    }
    Ok((voci, illeggibili))
}

/// Legge e scrive le mitigazioni e le rilevazioni di una fotografia appena
/// scritta. La chiama soltanto il servizio della fotografia.
///
/// # Errori
///
/// Come [`extract`], o un errore se la scrittura non riesce.
pub fn import(
    database: &mut Database,
    snapshot_id: AttackSnapshotId,
    bytes: &[u8],
) -> ServiceResult<(usize, usize)> {
    let (voci, illeggibili) = extract(bytes)?;
    let scritte = database.insert_attack_guidance(snapshot_id, &voci)?;
    Ok((scritte, illeggibili))
}

/// La scheda di una tecnica nella fotografia ATT&CK più recente: nome,
/// tattiche, e ciò che ATT&CK suggerisce (decisione 6).
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn technique_card(database: &Database, technique: &AttackTechniqueId) -> ServiceResult<String> {
    let Some(fotografia) = database
        .attack_snapshots()?
        .into_iter()
        .max_by_key(|fotografia| fotografia.imported_at)
    else {
        return Ok(String::from("Nessuna fotografia ATT&CK importata."));
    };
    let Some(tecnica) = database
        .attack_techniques(fotografia.id)?
        .into_iter()
        .find(|tecnica| tecnica.id() == technique)
    else {
        return Ok(format!(
            "La fotografia ATT&CK {} non conosce {}.",
            fotografia.attack_version,
            technique.as_str()
        ));
    };
    let mut righe = vec![format!(
        "{} — {}. Fotografia ATT&CK {}.",
        technique.as_str(),
        tecnica.name(),
        fotografia.attack_version
    )];
    if !database.attack_snapshot_has_guidance(fotografia.id)? {
        righe.push(String::from(
            "Questa fotografia non porta mitigazioni e rilevazioni: è stata importata prima che \
             il programma le leggesse.",
        ));
        return Ok(righe.join("\n"));
    }
    let voci = database.attack_guidance_for(fotografia.id, technique)?;
    righe.push(String::from(WHAT_IT_IS));
    for (genere, titolo) in [
        (GuidanceKind::Mitigation, "Mitigazioni"),
        (GuidanceKind::Detection, "Rilevazioni"),
    ] {
        let elenco: Vec<String> = voci
            .iter()
            .filter(|voce| voce.kind() == genere)
            .map(|voce| format!("{} {}", voce.id(), voce.name()))
            .collect();
        righe.push(if elenco.is_empty() {
            format!("{titolo}: ATT&CK non ne indica.")
        } else {
            format!("{titolo}: {}.", elenco.join("; "))
        });
    }
    Ok(righe.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::extract;
    use lisi_core::model::attack_guidance::GuidanceKind;

    /// **Soltanto contromisure e rilevazioni legate a una tecnica, e nessun
    /// attore** (ADR-0185, decisioni 4 e 5): un legame da un attore, un verbo
    /// sbagliato, una voce ritirata o senza tecniche si scartano.
    #[test]
    fn soltanto_cio_che_si_lega_a_una_tecnica_e_nessun_attore() {
        let pacchetto = r#"{"objects": [
            {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Interprete",
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]},
            {"type": "course-of-action", "id": "course-of-action--1", "name": "Execution Prevention",
             "description": "Bloccare l'esecuzione.",
             "external_references": [{"source_name": "mitre-attack", "external_id": "M1038"}]},
            {"type": "course-of-action", "id": "course-of-action--2", "name": "Ritirata", "revoked": true,
             "external_references": [{"source_name": "mitre-attack", "external_id": "M1000"}]},
            {"type": "course-of-action", "id": "course-of-action--3", "name": "Sola",
             "external_references": [{"source_name": "mitre-attack", "external_id": "M1001"}]},
            {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--1",
             "name": "Interpreti avviati in modo insolito",
             "external_references": [{"source_name": "mitre-attack", "external_id": "DET0001"}]},
            {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Gruppo Inventato"},
            {"type": "relationship", "relationship_type": "mitigates",
             "source_ref": "course-of-action--1", "target_ref": "attack-pattern--1"},
            {"type": "relationship", "relationship_type": "mitigates",
             "source_ref": "course-of-action--2", "target_ref": "attack-pattern--1"},
            {"type": "relationship", "relationship_type": "detects",
             "source_ref": "x-mitre-detection-strategy--1", "target_ref": "attack-pattern--1"},
            {"type": "relationship", "relationship_type": "uses",
             "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"},
            {"type": "relationship", "relationship_type": "detects",
             "source_ref": "course-of-action--3", "target_ref": "attack-pattern--1"}
        ]}"#;
        let Ok((voci, illeggibili)) = extract(pacchetto.as_bytes()) else {
            panic!("il pacchetto si legge");
        };
        assert_eq!(illeggibili, 0);
        let id: Vec<_> = voci
            .iter()
            .map(|voce| (voce.kind(), voce.id().to_owned()))
            .collect();
        assert_eq!(
            id,
            [
                (GuidanceKind::Mitigation, String::from("M1038")),
                (GuidanceKind::Detection, String::from("DET0001")),
            ]
        );
        assert!(voci.iter().all(|voce| voce.techniques().len() == 1));
        assert!(!voci.iter().any(|voce| voce.name().contains("Gruppo")));
    }
}

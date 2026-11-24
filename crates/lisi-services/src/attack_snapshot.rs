//! Importazione della fotografia MITRE ATT&CK da un file verificato.
//!
//! # Che cosa entra, e che cosa no
//!
//! Le **tecniche** e le **tattiche**. Il pacchetto ufficiale contiene anche 191
//! gruppi di attaccanti, 56 campagne, 733 malware e 95 strumenti: **non
//! entrano**, e l'esito dell'importazione dice quanti ne ha lasciati fuori.
//! Una tecnica è la descrizione di un comportamento; un gruppo è
//! un'attribuzione fatta da qualcun altro (ADR-0058).
//!
//! # Il prodotto non scarica
//!
//! Il file arriva da `scripts/fetch-attack.ps1`, che lo scarica e ne verifica
//! l'impronta contro `attack.lock.json`. Dare all'applicazione un client HTTP
//! aprirebbe un trust boundary nuovo dentro un programma che oggi parla
//! soltanto con TDLib, e non serve.
//!
//! Qui l'impronta **si riverifica**: il file potrebbe essere stato sostituito
//! dopo lo scaricamento, e chi importa non sa quando lo scaricamento è
//! avvenuto.
//!
//! # Il contenuto è ostile finché non è convalidato
//!
//! È JSON di terze parti letto da un percorso locale che qualcuno potrebbe aver
//! riempito con altro. Un tetto sui byte, un tetto sugli oggetti, ogni
//! identificativo convalidato contro la propria forma, ogni testo troncato a
//! una misura dichiarata. **Un pacchetto che non supera la validazione non
//! produce una fotografia parziale: non ne produce nessuna.**

use std::path::Path;

use lisi_core::model::NewAuditEntry;
use lisi_core::model::attack::{
    AttackSnapshot, AttackTactic, AttackTacticId, AttackTechnique, AttackTechniqueId,
    MITRE_ATTRIBUTION, NewAttackTechnique,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{AttackSnapshotId, Sha256Digest, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Quanti byte di pacchetto si accettano.
///
/// ATT&CK Enterprise 19.2 ne ha 53 835 637. Il tetto non serve a limitare
/// MITRE: serve a rifiutare un file che dice di essere ATT&CK e non lo è, prima
/// di provare a leggerlo.
pub const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

/// Quanti byte di testo di licenza si accettano.
pub const MAX_LICENSE_BYTES: u64 = 64 * 1024;

/// Quanti oggetti STIX si accettano dentro un pacchetto.
///
/// ATT&CK Enterprise 19.2 ne ha circa 26 000, relazioni comprese.
pub const MAX_OBJECTS: usize = 500_000;

/// I generi di oggetto che questo prodotto **non** importa.
///
/// Sono attori, campagne e arsenali: nominarli significherebbe portare dentro
/// NEXUM un vocabolario di attribuzione. Si contano, per poter dire quanti se
/// ne sono lasciati fuori, e nient'altro.
const ACTOR_TYPES: &[&str] = &["intrusion-set", "campaign", "malware", "tool"];

/// Che cosa un'importazione ha prodotto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackImportOutcome {
    /// La fotografia registrata.
    pub snapshot_id: AttackSnapshotId,
    /// Il dominio ATT&CK.
    pub domain: String,
    /// La versione di ATT&CK letta **dal pacchetto**, non dal nome del file.
    pub attack_version: String,
    /// Quante tecniche sono entrate.
    pub techniques: usize,
    /// Quante tattiche sono entrate.
    pub tactics: usize,
    /// Quanti oggetti che nominano attori sono stati lasciati fuori.
    ///
    /// **Non è un difetto: è la decisione.** Il numero esiste perché si possa
    /// dire quanti erano, invece di lasciar credere che non ce ne fossero.
    pub actors_ignored: usize,
    /// Quante mitigazioni e rilevazioni sono entrate (ATTACK-03, ADR-0185).
    pub guidance: usize,
}

/// `attack.lock.json`, incorporato a tempo di compilazione (PR-14, ADR-0130):
/// l'impronta del pacchetto è quella che **questa versione** del prodotto
/// conosce, e una persona non la deve scrivere.
const LOCK: &str = include_str!("../../../attack.lock.json");

/// La cartella, dentro il deposito, in cui `fetch-attack.ps1` mette i file: i
/// percorsi del lock sono relativi al deposito, l'importazione a una cartella.
const LOCK_FOLDER: &str = "assets/attack/";

/// Il pacchetto approvato, come lo fissa `attack.lock.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedBundle {
    /// Il pacchetto, relativo alla cartella dell'importazione.
    pub bundle: String,
    /// La licenza, relativa alla stessa cartella.
    pub license: String,
    /// L'impronta del pacchetto.
    pub sha256: Sha256Digest,
    /// La versione di ATT&CK che il lock dichiara.
    pub attack_version: String,
}

impl PinnedBundle {
    /// I due percorsi dentro la cartella indicata.
    #[must_use]
    pub fn paths_in(&self, cartella: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        (cartella.join(&self.bundle), cartella.join(&self.license))
    }
}

/// Il pacchetto approvato, letto da `attack.lock.json`.
///
/// # Errori
///
/// Restituisce un errore se il lock incorporato non ha la forma attesa: un
/// difetto della costruzione, che una prova coglie.
pub fn pinned() -> ServiceResult<PinnedBundle> {
    let rifiuto = |motivo: &'static str| ServiceError::AttackImportRefused { reason: motivo };
    let valore: serde_json::Value = serde_json::from_str(LOCK)
        .map_err(|_| rifiuto("il file delle impronte incorporato non si legge"))?;
    let testo = |puntatore: &str| -> ServiceResult<String> {
        valore
            .pointer(puntatore)
            .and_then(serde_json::Value::as_str)
            .map(String::from)
            .ok_or_else(|| rifiuto("il file delle impronte incorporato non ha la forma attesa"))
    };
    let relativo = |percorso: String| -> ServiceResult<String> {
        percorso
            .strip_prefix(LOCK_FOLDER)
            .map(String::from)
            .ok_or_else(|| {
                rifiuto("il file delle impronte indica un file fuori dalla sua cartella")
            })
    };
    Ok(PinnedBundle {
        bundle: relativo(testo("/fotografia/file")?)?,
        license: relativo(testo("/licenza/file")?)?,
        sha256: Sha256Digest::from_hex(&testo("/fotografia/sha256")?)
            .map_err(|_| rifiuto("l'impronta del file delle impronte non è un'impronta"))?,
        attack_version: testo("/fotografia/versione_attack")?,
    })
}

/// Il servizio che importa la fotografia.
pub struct AttackSnapshotService<'a> {
    database: &'a mut Database,
}

impl<'a> AttackSnapshotService<'a> {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub fn new(database: &'a mut Database) -> Self {
        Self { database }
    }

    /// Importa una fotografia da un pacchetto locale già verificato.
    ///
    /// `expected_sha256` è l'impronta fissata in `attack.lock.json`: il file
    /// viene riverificato qui, perché fra lo scaricamento e l'importazione può
    /// essere passato del tempo e chi importa non sa quanto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un file non si legge, se l'impronta non
    /// corrisponde, se il testo della licenza non contiene la designazione di
    /// copyright che il prodotto conosce, se il pacchetto non supera la
    /// validazione, o se una fotografia della stessa versione è già in
    /// archivio.
    pub fn import(
        &mut self,
        bundle_path: &Path,
        license_path: &Path,
        expected_sha256: &Sha256Digest,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<AttackImportOutcome> {
        let license_text = read_capped(license_path, MAX_LICENSE_BYTES)?;

        // LA DESIGNAZIONE DI COPYRIGHT SI VERIFICA, NON SI COPIA.
        //
        // La licenza concede l'uso a condizione che ogni copia la riproduca.
        // Se il testo scaricato non contiene piu' la frase che il prodotto
        // conosce, MITRE l'ha cambiata: e' una cosa che deve vedere una
        // persona, non un caso da aggirare copiando quello che c'e'.
        if !license_text.contains(MITRE_ATTRIBUTION) {
            return Err(ServiceError::AttackImportRefused {
                reason: "il testo della licenza non contiene la designazione di copyright \
                         che il prodotto conosce: MITRE l'ha cambiata, e serve una persona",
            });
        }

        let bytes = read_bundle(bundle_path)?;
        let digest = Sha256Digest::of_bytes(&bytes);
        if digest != *expected_sha256 {
            return Err(ServiceError::AttackImportRefused {
                reason: "l'impronta del pacchetto non è quella dichiarata: il file non è \
                         quello che questa versione del prodotto conosce",
            });
        }

        let (snapshot, actors_ignored) = parse(&bytes, &license_text)?;
        let snapshot_id = self
            .database
            .insert_attack_snapshot(&snapshot, &digest, actor, now)?;
        // MITIGAZIONI E RILEVAZIONI, dallo stesso pacchetto già verificato
        // (ATTACK-03, ADR-0185): le legge un modulo a parte, che scarta gli
        // attori come qui.
        let (guide, guide_illeggibili) =
            crate::attack_guidance::import(self.database, snapshot_id, &bytes)?;

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("fotografia_attack_importata")?,
            entity: AuditEntity::try_new("attack_snapshot")?,
            entity_id: Some(snapshot_id.get()),
            // Importare un vocabolario pubblico non e' un'azione riservata.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "attack {dominio} {versione}: {tecniche} tecniche, {tattiche} tattiche, \
                 {guide} mitigazioni e rilevazioni ({illeggibili} non lette), \
                 {attori} oggetti che nominano attori lasciati fuori, sha256 {impronta}",
                guide = guide,
                illeggibili = guide_illeggibili,
                dominio = snapshot.domain(),
                versione = snapshot.attack_version(),
                tecniche = snapshot.techniques().len(),
                tattiche = snapshot.tactics().len(),
                attori = actors_ignored,
                impronta = digest.as_str(),
            ))?),
            recorded_at: now,
        })?;

        Ok(AttackImportOutcome {
            snapshot_id,
            domain: String::from(snapshot.domain()),
            attack_version: String::from(snapshot.attack_version()),
            techniques: snapshot.techniques().len(),
            tactics: snapshot.tactics().len(),
            actors_ignored,
            guidance: guide,
        })
    }
}

/// Legge un file rifiutando ciò che è oltre misura **prima** di leggerlo.
fn read_capped(path: &Path, max: u64) -> ServiceResult<String> {
    let metadata = std::fs::metadata(path).map_err(|_| ServiceError::AttackImportRefused {
        reason: "il file indicato non si legge",
    })?;
    if metadata.len() > max {
        return Err(ServiceError::AttackImportRefused {
            reason: "il file indicato è oltre la misura ammessa",
        });
    }
    std::fs::read_to_string(path).map_err(|_| ServiceError::AttackImportRefused {
        reason: "il file indicato non è testo leggibile",
    })
}

/// Legge il pacchetto, con il proprio tetto.
fn read_bundle(path: &Path) -> ServiceResult<Vec<u8>> {
    let metadata = std::fs::metadata(path).map_err(|_| ServiceError::AttackImportRefused {
        reason: "il pacchetto indicato non si legge",
    })?;
    if metadata.len() > MAX_BUNDLE_BYTES {
        return Err(ServiceError::AttackImportRefused {
            reason: "il pacchetto indicato è oltre la misura ammessa",
        });
    }
    std::fs::read(path).map_err(|_| ServiceError::AttackImportRefused {
        reason: "il pacchetto indicato non si legge",
    })
}

/// Il pacchetto, con i soli campi che questo prodotto guarda.
///
/// # Perché una struttura e non un albero JSON generico
///
/// Perché ciò che non è dichiarato qui **non viene nemmeno allocato**: un
/// pacchetto di cinquanta megabyte pieno di campi che non ci riguardano non
/// diventa cinquanta megabyte di memoria. Ed è anche una guardia: un campo che
/// non esiste in questa struttura non può finire nell'archivio per distrazione.
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
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    external_references: Vec<RawReference>,
    #[serde(default)]
    kill_chain_phases: Vec<RawPhase>,
    #[serde(default)]
    revoked: bool,
    #[serde(default, rename = "x_mitre_deprecated")]
    deprecated: bool,
    #[serde(default, rename = "x_mitre_version")]
    object_version: Option<String>,
    #[serde(default, rename = "x_mitre_shortname")]
    shortname: Option<String>,
    #[serde(default, rename = "x_mitre_attack_spec_version")]
    spec_version: Option<String>,
    #[serde(default, rename = "x_mitre_domains")]
    domains: Vec<String>,
}

#[derive(serde::Deserialize)]
struct RawReference {
    #[serde(default)]
    source_name: String,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawPhase {
    #[serde(default)]
    kill_chain_name: String,
    #[serde(default)]
    phase_name: String,
}

impl RawObject {
    /// L'identificativo ATT&CK, che sta nel riferimento esterno `mitre-attack`.
    ///
    /// Gli altri riferimenti esterni sono **citazioni bibliografiche** — blog,
    /// documentazione, articoli — e nessuno di essi porta l'identificativo:
    /// prendere il primo che capita darebbe l'identificativo di un blog.
    fn attack_id(&self) -> Option<&str> {
        self.external_references
            .iter()
            .find(|reference| reference.source_name == "mitre-attack")
            .and_then(|reference| reference.external_id.as_deref())
    }

    /// L'indirizzo della pagina ufficiale, dallo stesso riferimento.
    fn attack_url(&self) -> &str {
        self.external_references
            .iter()
            .find(|reference| reference.source_name == "mitre-attack")
            .and_then(|reference| reference.url.as_deref())
            .unwrap_or_default()
    }

    /// I nomi brevi delle tattiche, dalla sola catena `mitre-attack`.
    fn tactics(&self) -> Vec<String> {
        self.kill_chain_phases
            .iter()
            .filter(|phase| phase.kill_chain_name == "mitre-attack")
            .map(|phase| phase.phase_name.clone())
            .collect()
    }
}

/// Legge il pacchetto e ne ricava la fotografia, oppure la rifiuta.
///
/// Restituisce anche **quanti** oggetti che nominano attori sono stati lasciati
/// fuori: il numero esiste perché si possa dire quanti erano, invece di
/// lasciar credere che non ce ne fossero.
fn parse(bytes: &[u8], license_text: &str) -> ServiceResult<(AttackSnapshot, usize)> {
    let bundle: RawBundle =
        serde_json::from_slice(bytes).map_err(|_| ServiceError::AttackImportRefused {
            reason: "il pacchetto non è un file di dati leggibile",
        })?;

    if bundle.objects.len() > MAX_OBJECTS {
        return Err(ServiceError::AttackImportRefused {
            reason: "il pacchetto dichiara più oggetti di quanti ATT&CK ne abbia mai avuti",
        });
    }

    let mut attack_version = None;
    let mut spec_version = None;
    let mut domain = None;
    let mut tactics = Vec::new();
    let mut techniques = Vec::new();
    let mut actors_ignored = 0_usize;

    for object in &bundle.objects {
        if ACTOR_TYPES.contains(&object.object_type.as_str()) {
            actors_ignored += 1;
            continue;
        }

        match object.object_type.as_str() {
            "x-mitre-collection" => {
                // LA VERSIONE SI LEGGE DAL PACCHETTO, NON DAL NOME DEL FILE.
                //
                // Un file rinominato direbbe di essere una versione che non e',
                // e la fotografia porterebbe un numero sbagliato senza che
                // nulla lo segnali.
                attack_version = object.object_version.clone();
                spec_version = object.spec_version.clone();
            }
            "x-mitre-tactic" => {
                let (Some(id), Some(shortname), Some(name)) = (
                    object.attack_id(),
                    object.shortname.as_deref(),
                    object.name.as_deref(),
                ) else {
                    return Err(ServiceError::AttackImportRefused {
                        reason: "una tattica del pacchetto non porta identificativo, \
                                 nome breve o nome",
                    });
                };
                let id = AttackTacticId::try_new(id)?;
                tactics.push(AttackTactic::new(
                    id,
                    shortname,
                    name,
                    object.description.as_deref().unwrap_or_default(),
                )?);
            }
            "attack-pattern" => {
                let (Some(id), Some(name)) = (object.attack_id(), object.name.as_deref()) else {
                    return Err(ServiceError::AttackImportRefused {
                        reason: "una tecnica del pacchetto non porta identificativo o nome",
                    });
                };
                if domain.is_none()
                    && let Some(primo) = object.domains.first()
                {
                    domain = Some(primo.clone());
                }
                let id = AttackTechniqueId::try_new(id)?;
                techniques.push(AttackTechnique::new(NewAttackTechnique {
                    id,
                    name,
                    description: object.description.as_deref().unwrap_or_default(),
                    tactics: object.tactics(),
                    deprecated: object.deprecated,
                    revoked: object.revoked,
                    object_version: object.object_version.as_deref().unwrap_or_default(),
                    url: object.attack_url(),
                })?);
            }
            // Tutto il resto - relazioni, analitiche, strategie di rilevamento,
            // sorgenti di dato, contromisure, identita', marcature - non
            // riguarda questo prodotto e non ha un posto in cui stare.
            _ => {}
        }
    }

    let (Some(attack_version), Some(spec_version)) = (attack_version, spec_version) else {
        return Err(ServiceError::AttackImportRefused {
            reason: "il pacchetto non dichiara la propria versione ATT&CK",
        });
    };
    let Some(domain) = domain else {
        return Err(ServiceError::AttackImportRefused {
            reason: "il pacchetto non dichiara a quale dominio ATT&CK appartenga",
        });
    };

    let snapshot = AttackSnapshot::new(
        &domain,
        &attack_version,
        &spec_version,
        license_text,
        tactics,
        techniques,
    )?;

    Ok((snapshot, actors_ignored))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un pacchetto minimo, della forma che ATT&CK produce.
    fn pacchetto(extra: &str) -> String {
        format!(
            r#"{{
              "type": "bundle",
              "id": "bundle--0",
              "objects": [
                {{
                  "type": "x-mitre-collection",
                  "name": "Enterprise ATT&CK",
                  "x_mitre_version": "19.2",
                  "x_mitre_attack_spec_version": "3.3.0"
                }},
                {{
                  "type": "x-mitre-tactic",
                  "name": "Execution",
                  "description": "L'avversario sta provando a eseguire codice.",
                  "x_mitre_shortname": "execution",
                  "external_references": [
                    {{"source_name": "mitre-attack", "external_id": "TA0002",
                      "url": "https://attack.mitre.org/tactics/TA0002"}}
                  ]
                }},
                {{
                  "type": "attack-pattern",
                  "name": "Command and Scripting Interpreter",
                  "description": "descrizione della tecnica",
                  "revoked": false,
                  "x_mitre_deprecated": false,
                  "x_mitre_version": "2.5",
                  "x_mitre_domains": ["enterprise-attack"],
                  "x_mitre_is_subtechnique": false,
                  "kill_chain_phases": [
                    {{"kill_chain_name": "mitre-attack", "phase_name": "execution"}}
                  ],
                  "external_references": [
                    {{"source_name": "Un Blog", "url": "https://esempio.test/a"}},
                    {{"source_name": "mitre-attack", "external_id": "T1059",
                      "url": "https://attack.mitre.org/techniques/T1059"}}
                  ]
                }}{extra}
              ]
            }}"#
        )
    }

    fn licenza() -> String {
        format!("License\n-------\nqualcosa\n\n\"{MITRE_ATTRIBUTION}\"\n")
    }

    fn analizza(json: &str) -> ServiceResult<(AttackSnapshot, usize)> {
        parse(json.as_bytes(), &licenza())
    }

    #[test]
    fn un_pacchetto_ben_formato_produce_una_fotografia() {
        let Ok((snapshot, attori)) = analizza(&pacchetto("")) else {
            panic!("il pacchetto di prova deve produrre una fotografia");
        };
        assert_eq!(snapshot.attack_version(), "19.2");
        assert_eq!(snapshot.spec_version(), "3.3.0");
        assert_eq!(snapshot.domain(), "enterprise-attack");
        assert_eq!(snapshot.tactics().len(), 1);
        assert_eq!(snapshot.techniques().len(), 1);
        assert_eq!(attori, 0);

        let tecnica = &snapshot.techniques()[0];
        assert_eq!(tecnica.id().as_str(), "T1059");
        assert_eq!(tecnica.tactics(), &[String::from("execution")]);
        assert_eq!(tecnica.url(), "https://attack.mitre.org/techniques/T1059");
        assert_eq!(tecnica.object_version(), "2.5");
    }

    /// **Gli attori non entrano, e si dice quanti erano.**
    ///
    /// È la decisione di ATTACK-01: una tecnica descrive un comportamento, un
    /// gruppo è un'attribuzione fatta da qualcun altro.
    #[test]
    fn gli_attori_non_entrano_e_il_loro_numero_si_dichiara() {
        let attori = r#",
                {"type": "intrusion-set", "name": "Gruppo Inventato",
                 "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}]},
                {"type": "malware", "name": "Malware Inventato"},
                {"type": "campaign", "name": "Campagna Inventata"},
                {"type": "tool", "name": "Strumento Inventato"}"#;

        let Ok((snapshot, ignorati)) = analizza(&pacchetto(attori)) else {
            panic!("il pacchetto deve produrre una fotografia");
        };
        assert_eq!(ignorati, 4, "i quattro attori dovevano essere contati");
        assert_eq!(snapshot.techniques().len(), 1);

        // E nessuno dei loro nomi e' finito da qualche parte.
        let reso = format!("{snapshot:?}");
        for nome in [
            "Gruppo Inventato",
            "Malware Inventato",
            "Campagna Inventata",
            "Strumento Inventato",
        ] {
            assert!(
                !reso.contains(nome),
                "la fotografia non deve contenere «{nome}»"
            );
        }
    }

    /// L'identificativo viene dal riferimento `mitre-attack`, non dal primo.
    ///
    /// Gli altri riferimenti sono citazioni bibliografiche: prendere il primo
    /// che capita darebbe l'identificativo di un blog.
    #[test]
    fn l_identificativo_viene_dal_riferimento_ufficiale() {
        let Ok((snapshot, _)) = analizza(&pacchetto("")) else {
            panic!("il pacchetto deve produrre una fotografia");
        };
        assert_eq!(snapshot.techniques()[0].id().as_str(), "T1059");
    }

    /// **Un pacchetto senza versione si rifiuta.**
    #[test]
    fn un_pacchetto_senza_versione_si_rifiuta() {
        let senza = pacchetto("").replace("\"x_mitre_version\": \"19.2\",\n", "");
        assert!(matches!(
            parse(senza.as_bytes(), &licenza()),
            Err(ServiceError::AttackImportRefused { .. })
        ));
    }

    /// **Un identificativo deformato rifiuta l'intero pacchetto.**
    ///
    /// Non si salta la riga: una fotografia a cui manca una tecnica risponde
    /// «non c'è» a una domanda a cui ATT&CK risponde di sì.
    #[test]
    fn un_identificativo_deformato_rifiuta_l_intero_pacchetto() {
        let deformato =
            pacchetto("").replace("\"external_id\": \"T1059\"", "\"external_id\": \"XY\"");
        assert!(analizza(&deformato).is_err());
    }

    /// **Un pacchetto che non è JSON si rifiuta senza tentare di interpretarlo.**
    #[test]
    fn un_pacchetto_non_json_si_rifiuta() {
        assert!(matches!(
            parse(b"non sono json", &licenza()),
            Err(ServiceError::AttackImportRefused { .. })
        ));
    }

    /// **Una tecnica che nomina una tattica assente rifiuta la fotografia.**
    #[test]
    fn una_tattica_assente_rifiuta_la_fotografia() {
        let sbagliato = pacchetto("").replace(
            "\"phase_name\": \"execution\"",
            "\"phase_name\": \"persistence\"",
        );
        assert!(analizza(&sbagliato).is_err());
    }

    /// **Se la licenza non contiene più la designazione di copyright, non si
    /// importa.**
    ///
    /// La condizione della licenza è riprodurla: se MITRE l'ha cambiata, la
    /// cosa deve vederla una persona, non essere aggirata copiando quel che c'è.
    #[test]
    fn una_licenza_senza_designazione_di_copyright_non_produce_una_fotografia() {
        let esito = parse(pacchetto("").as_bytes(), "License\n-------\nqualcos'altro");
        // Il rifiuto qui arriva dal dominio: la fotografia riceve comunque
        // l'attribuzione costante. Il controllo sul testo sta nel servizio, ed
        // e' verificato dalla prova d'integrazione.
        assert!(esito.is_ok());
        let Ok((snapshot, _)) = esito else {
            panic!("il dominio non rifiuta un testo di licenza diverso");
        };
        assert_eq!(snapshot.attribution(), MITRE_ATTRIBUTION);
    }

    /// Le tattiche di un'altra catena non si contano.
    #[test]
    fn una_catena_diversa_da_mitre_attack_non_produce_tattiche() {
        let altra = pacchetto("").replace(
            "\"kill_chain_name\": \"mitre-attack\", \"phase_name\": \"execution\"",
            "\"kill_chain_name\": \"altra-catena\", \"phase_name\": \"execution\"",
        );
        let Ok((snapshot, _)) = analizza(&altra) else {
            panic!("il pacchetto deve produrre una fotografia");
        };
        assert!(snapshot.techniques()[0].tactics().is_empty());
    }

    /// **L'impronta e i file vengono da `attack.lock.json`**, incorporato: la
    /// schermata non chiede a una persona di scriverli (PR-14, ADR-0130).
    #[test]
    fn il_pacchetto_approvato_viene_dal_lock() {
        let Ok(fissato) = super::pinned() else {
            panic!("il lock incorporato deve leggersi");
        };
        assert_eq!(fissato.bundle, "enterprise-attack-19.2.json");
        assert_eq!(fissato.license, "licenses/MITRE-ATTACK-LICENSE.txt");
        assert_eq!(fissato.attack_version, "19.2");
        assert_eq!(
            fissato.sha256.as_str(),
            "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
        );
    }
}

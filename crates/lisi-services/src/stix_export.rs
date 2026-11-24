//! Esportazione STIX 2.1 di un monitoraggio, dove la semantica regge.
//!
//! Produce due file: il **pacchetto** JSON e un **manifest** che ne riporta il
//! nome, la dimensione e l'impronta SHA-256 — lo stesso manifest dello Storico,
//! così che il verificatore di integrità già esistente sappia leggerlo senza
//! modifiche.
//!
//! # Che cosa esce, e che cosa no
//!
//! La decisione sta in `docs/adr/ADR-0057-STIX-DOVE-LA-SEMANTICA-REGGE.md` e la
//! applica [`lisi_core::model::stix`]. Qui non si decide nulla di semantico: si
//! legge l'archivio, si chiede al dominio che cosa ciascun valore possa
//! diventare, e si scrive ciò che ne esce. Un valore che il dominio rifiuta
//! **non entra nel pacchetto**, e il suo motivo finisce nel manifest.
//!
//! # Perché la provenienza sta nel manifest e non nel pacchetto
//!
//! Perché sono due destinatari diversi. Il pacchetto può uscire dall'ufficio, e
//! dirvi dentro quale monitoraggio ha nominato quel dominio significherebbe
//! dire a un'altra organizzazione che cosa questo ufficio guarda. Il manifest
//! resta accanto al file, sulla postazione, e lì la provenienza serve.
//!
//! # Nessun automatismo
//!
//! Nulla in questo modulo è chiamato da un temporizzatore, da un osservatore o
//! da un percorso di acquisizione. L'esportazione è un gesto, e perché il gesto
//! possa essere informato c'è [`StixExportService::preview`], che dice che cosa
//! uscirebbe **senza scrivere niente**.
//!
//! # Nessuna trasmissione
//!
//! Questo modulo scrive un file locale e si ferma. Non c'è caricamento e non
//! c'è rete: la scelta del destinatario appartiene all'ufficio (ADR-0057).
//! L'invio a un server TAXII sta in [`crate::taxii`] (ADR-0179), che da qui
//! prende soltanto la busta: gli stessi oggetti del pacchetto, composti dalla
//! stessa funzione.

use std::path::{Path, PathBuf};

use lisi_core::model::indicator::CyberIndicator;
use lisi_core::model::stix::{
    StixBundle, StixObject, StixOmission, StixType, StixValue, caveat_text, object_for,
};
use lisi_core::model::{NewAuditEntry, Session};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{ATTRIBUTION, PRODUCT_NAME, SessionId, Sha256Digest, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::indicator::SessionIndicator;

use crate::error::{ServiceError, ServiceResult};
use crate::export::{MANIFEST_SUFFIX, display, file_name_of, file_stem, render_manifest};
use crate::protected_output::{
    CurrentUser, Delivery, Existing, REFUSED_AUDIT_ACTION, record_refusal,
};

/// Ciò che si dice quando l'esportazione non si scrive per i permessi.
const STIX_NOT_WRITTEN: &str = "L'esportazione STIX NON è stata scritta";

/// Suffisso del pacchetto prodotto.
///
/// Doppia estensione voluta: `.json` perché è JSON e si apre con qualunque
/// strumento, `.stix` davanti perché un JSON in una cartella di documenti non
/// dice da sé che cosa sia.
pub const STIX_SUFFIX: &str = ".stix.json";

/// Un valore che entrerà nel pacchetto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StixPlannedObject {
    /// Il genere e il valore, come stanno in archivio.
    pub indicator: CyberIndicator,
    /// Quanti contenuti del monitoraggio lo nominano.
    pub mentioning_contents: u64,
    /// Il tipo STIX che ne uscirà.
    pub object_type: StixType,
    /// L'identificativo STIX che ne uscirà.
    pub stix_id: String,
}

/// Un valore che **non** entrerà nel pacchetto, e perché.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StixPlannedOmission {
    /// Il genere e il valore, come stanno in archivio.
    pub indicator: CyberIndicator,
    /// Quanti contenuti del monitoraggio lo nominano.
    pub mentioning_contents: u64,
    /// Il motivo dell'omissione.
    pub reason: StixOmission,
}

/// Che cosa uscirebbe, e che cosa resterebbe fuori.
///
/// # Perché il piano esiste separato dall'esito
///
/// Perché l'operatore deve poter sapere che cosa verrà esportato **prima** di
/// produrre il pacchetto. Il piano si calcola senza scrivere nulla, e
/// l'esportazione usa lo stesso piano: la schermata della milestone successiva
/// non può mostrare una cosa e produrne un'altra, e una prova lo verifica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StixExportPlan {
    /// Il monitoraggio.
    pub session_id: SessionId,
    /// I valori rappresentabili.
    pub exported: Vec<StixPlannedObject>,
    /// I valori non rappresentabili, con il loro motivo.
    pub omitted: Vec<StixPlannedOmission>,
}

impl StixExportPlan {
    /// Se non c'è nulla da scrivere.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exported.is_empty()
    }
}

/// Che cosa è stato prodotto.
#[derive(Debug, Clone)]
pub struct StixExportOutcome {
    /// Il piano effettivamente applicato.
    pub plan: StixExportPlan,
    /// Il pacchetto scritto.
    pub bundle: PathBuf,
    /// Il manifest scritto accanto.
    pub manifest: PathBuf,
    /// L'impronta del pacchetto.
    pub digest: Sha256Digest,
    /// L'utente Windows che solo può aprire pacchetto e manifest (SEC-02).
    pub owner: CurrentUser,
}

/// Il servizio di esportazione STIX.
pub struct StixExportService<'a> {
    database: &'a Database,
}

impl<'a> StixExportService<'a> {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    /// Che cosa uscirebbe da questo monitoraggio, senza scrivere nulla.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn preview(&self, session_id: SessionId) -> ServiceResult<StixExportPlan> {
        let indicatori = self.database.distinct_session_indicators(session_id)?;
        Ok(plan_from(session_id, &indicatori))
    }

    /// Produce il pacchetto e il suo manifest.
    ///
    /// # Perché la destinazione arriva come argomento
    ///
    /// La stessa ragione dello Storico: non c'è un percorso digitabile, quindi
    /// non c'è un percorso da cui uscire. La cartella la sceglie il chiamante
    /// fra quelle dell'applicazione, e i test scrivono nella propria.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile, se nessun elemento
    /// del monitoraggio è rappresentabile, o se i file non si possono scrivere.
    pub fn export(
        &self,
        session_id: SessionId,
        directory: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<StixExportOutcome> {
        let session = self.database.session(session_id)?;
        let plan = self.preview(session_id)?;

        // UN PACCHETTO VUOTO NON E' UNA RISPOSTA.
        //
        // Sarebbe formalmente valido e direbbe «non abbiamo trovato niente»,
        // che e' un'altra cosa da «non c'e' niente che si possa dire senza
        // affermare piu' di quanto si sappia».
        if plan.is_empty() {
            return Err(ServiceError::StixNothingToExport);
        }

        std::fs::create_dir_all(directory).map_err(|error| ServiceError::ExportNotWritten {
            reason: error.to_string(),
        })?;

        let stem = file_stem(&session, now);
        let bundle_path = directory.join(format!("{stem}{STIX_SUFFIX}"));
        let manifest_path = directory.join(format!("{stem}{STIX_SUFFIX}{MANIFEST_SUFFIX}"));

        // Un file gia' presente non viene sostituito: un pacchetto consegnato e
        // poi cambiato in silenzio renderebbe vuota la promessa del manifest.
        for path in [&bundle_path, &manifest_path] {
            if path.exists() {
                return Err(ServiceError::ExportNotWritten {
                    reason: format!("esiste già un documento con il nome {}", display(path)),
                });
            }
        }

        let bytes = render_bundle(&plan, now).into_bytes();
        let digest = Sha256Digest::of_bytes(&bytes);

        let manifest = crate::run_mode::marked_text(format!(
            "{}\n{}",
            render_manifest(&bundle_path, bytes.len(), &digest, actor, now),
            render_provenance(&session, &plan)
        ));

        // DEL SOLO UTENTE, O NIENTE (SEC-02, ADR-0157).
        let consegnati = Delivery::begin(directory, &stem, STIX_NOT_WRITTEN)
            .and_then(|mut consegna| {
                consegna.write(&file_name_of(&bundle_path), &bytes)?;
                consegna.write(&file_name_of(&manifest_path), manifest.as_bytes())?;
                consegna.deliver(Existing::Refuse)
            })
            .inspect_err(|errore| {
                record_refusal(
                    self.database,
                    actor,
                    now,
                    REFUSED_AUDIT_ACTION,
                    "stix",
                    errore,
                );
            })?;

        self.record(session_id, &plan, &digest, actor, now)?;

        Ok(StixExportOutcome {
            plan,
            bundle: bundle_path,
            manifest: manifest_path,
            digest,
            owner: consegnati.owner,
        })
    }

    /// Registra l'atto nell'audit.
    ///
    /// # Perché nell'audit e non nella tabella degli export
    ///
    /// Perché `exports` ammette tre formati per un vincolo dello schema che
    /// esiste dalla migrazione 0001, e riscriverlo per aggiungerne un quarto
    /// toccherebbe una struttura che contiene i rapporti già prodotti
    /// dall'ufficio — la stessa ragione per cui i pacchetti di report non ci
    /// sono entrati (migrazione 0014).
    ///
    /// L'audit è **append-only per trigger**, e conservare lì l'impronta è più
    /// forte che conservarla in una tabella modificabile: fra un anno si potrà
    /// dire se un file consegnato fu prodotto da questa postazione.
    fn record(
        &self,
        session_id: SessionId,
        plan: &StixExportPlan,
        digest: &Sha256Digest,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = format!(
            "stix 2.1: {esportati} oggetti esportati, {omessi} valori omessi, sha256 {impronta}",
            esportati = plan.exported.len(),
            omessi = plan.omitted.len(),
            impronta = digest.as_str(),
        );

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("stix_esportato")?,
            entity: AuditEntity::try_new("session")?,
            entity_id: Some(session_id.get()),
            // Non e' un'azione riservata: attribuirle una modalita' operativa
            // direbbe che lo e'.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&detail)?),
            recorded_at: now,
        })?;

        Ok(())
    }
}

/// Costruisce il piano a partire dagli indicatori letti.
///
/// Sta fuori dal servizio perché non tocca l'archivio: così si esercita con
/// elenchi costruiti a mano, senza aprire un database per verificare una
/// decisione semantica.
fn plan_from(session_id: SessionId, indicatori: &[SessionIndicator]) -> StixExportPlan {
    let mut exported = Vec::new();
    let mut omitted = Vec::new();

    for riga in indicatori {
        match object_for(&riga.indicator) {
            Ok(object) => exported.push(StixPlannedObject {
                indicator: riga.indicator.clone(),
                mentioning_contents: riga.mentioning_contents,
                object_type: object.object_type(),
                stix_id: object.id().as_string(),
            }),
            Err(reason) => omitted.push(StixPlannedOmission {
                indicator: riga.indicator.clone(),
                mentioning_contents: riga.mentioning_contents,
                reason,
            }),
        }
    }

    StixExportPlan {
        session_id,
        exported,
        omitted,
    }
}

/// Compone il pacchetto e lo scrive come JSON.
///
/// # Perché si ricostruiscono gli oggetti invece di conservarli nel piano
///
/// Perché il piano è ciò che si **mostra**, e un piano che portasse dentro gli
/// oggetti già costruiti sarebbe una struttura di presentazione che trasporta
/// il documento. Ricostruirli qui costa una passata e garantisce che ciò che si
/// scrive derivi dagli stessi valori che si sono mostrati: se le due strade
/// divergessero, la prova che confronta piano ed esito diventerebbe rossa.
fn render_bundle(plan: &StixExportPlan, now: Timestamp) -> String {
    let bundle = bundle_json(plan, now);

    // IL PACCHETTO SI SCRIVE LEGGIBILE.
    //
    // Un bundle su una riga sola e' JSON valido e nessuno lo rilegge: e' un
    // atto che qualcuno aprira' in un editor, e la prima cosa che deve poter
    // fare e' capire che cosa contiene. L'indentazione di serde_json e' fissa,
    // quindi non toglie nulla al determinismo.
    let mut testo = match serde_json::to_string_pretty(&bundle) {
        Ok(testo) => testo,
        // Un albero fatto di sole stringhe, elenchi e oggetti non ha modo di
        // fallire la serializzazione: se accadesse, la forma compatta e'
        // preferibile a un pacchetto non scritto.
        Err(_) => bundle.to_string(),
    };
    testo.push('\n');
    testo
}

/// Il pacchetto come albero JSON: la sola composizione, per il file e per
/// TAXII.
fn bundle_json(plan: &StixExportPlan, now: Timestamp) -> serde_json::Value {
    let objects: Vec<StixObject> = plan
        .exported
        .iter()
        .filter_map(|planned| object_for(&planned.indicator).ok())
        .collect();

    // In Esercitazione l'avvertenza del pacchetto si apre con la frase di SIC-17
    // (PR-13, ADR-0129): il JSON resta valido, e la parola sta dentro.
    let caveat = crate::run_mode::marked_text(caveat_text(PRODUCT_NAME, env!("CARGO_PKG_VERSION")));
    to_json(&StixBundle::new(objects, &caveat, now).to_value())
}

/// La busta TAXII 2.1 (`envelope`) con gli stessi oggetti del pacchetto
/// (ADR-0179, decisione 2).
///
/// # Perché dal pacchetto e non da una composizione propria
///
/// Perché ciò che esce verso un server deve essere ciò che uscirebbe in un
/// file, e nient'altro: gli stessi oggetti, l'avvertenza compresa, presi
/// dall'elenco `objects` dello stesso albero. Del pacchetto non si manda il
/// guscio (`type`, `id`), che in TAXII 2.1 non esiste. Si scrive compatta:
/// questa non la rilegge una persona, e l'impronta che finisce nel registro è
/// quella di questi byte.
///
/// Restituisce i byte e quanti oggetti contengono, avvertenza compresa.
pub(crate) fn taxii_envelope(plan: &StixExportPlan, now: Timestamp) -> (Vec<u8>, usize) {
    let objects = bundle_json(plan, now)
        .get("objects")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
    let quanti = objects.as_array().map_or(0, Vec::len);
    let mut busta = serde_json::Map::new();
    busta.insert(String::from("objects"), objects);
    (
        serde_json::Value::Object(busta).to_string().into_bytes(),
        quanti,
    )
}

/// Traduce il valore ristretto del dominio in JSON.
///
/// # Perché `serde_json` e non una scrittura nostra
///
/// Perché scrivere JSON a mano è codice nuovo su un percorso che produce atti,
/// e `serde_json` è già nel workspace. La forma canonica RFC 8785 resta invece
/// nel dominio, perché nessun crate del workspace la fornisce e serve soltanto
/// a calcolare gli identificativi.
///
/// L'ordine delle chiavi è quello della mappa di `serde_json`, che è ordinata:
/// due esportazioni della stessa selezione danno gli stessi byte.
fn to_json(value: &StixValue) -> serde_json::Value {
    match value {
        StixValue::Text(text) => serde_json::Value::String(text.clone()),
        StixValue::List(items) => serde_json::Value::Array(items.iter().map(to_json).collect()),
        StixValue::Object(fields) => {
            let mut mappa = serde_json::Map::new();
            for (key, field) in fields {
                mappa.insert(key.clone(), to_json(field));
            }
            serde_json::Value::Object(mappa)
        }
    }
}

/// La parte di manifest che dice da dove viene il pacchetto e che cosa non c'è.
///
/// **Non nomina le fonti.** Nomina il monitoraggio, che è un riferimento
/// interno: chi ha il manifest ha anche l'archivio, e chi ha soltanto il
/// pacchetto non ha nemmeno questo.
fn render_provenance(session: &Session, plan: &StixExportPlan) -> String {
    let mut testo = String::new();
    testo.push_str("Provenienza interna — NON fa parte del pacchetto STIX\n");
    testo.push_str(
        "Questa sezione resta sulla postazione. Il pacchetto non nomina il\n\
         monitoraggio né le fonti: dirlo a un'altra organizzazione significherebbe\n\
         dire che cosa questo ufficio guarda.\n\n",
    );
    testo.push_str(&format!("Monitoraggio: {}\n", session.label.as_str()));
    testo.push_str(&format!(
        "Valori esportati: {}\nValori omessi: {}\n\n",
        plan.exported.len(),
        plan.omitted.len()
    ));

    testo.push_str("Esportati (genere, valore, contenuti che lo nominano, identificativo STIX):\n");
    for planned in &plan.exported {
        testo.push_str(&format!(
            "  {kind}\t{value}\t{quanti}\t{id}\n",
            kind = planned.indicator.kind.as_str(),
            value = planned.indicator.value,
            quanti = planned.mentioning_contents,
            id = planned.stix_id,
        ));
    }

    if plan.omitted.is_empty() {
        testo.push_str("\nOmessi: nessuno.\n");
    } else {
        testo.push_str("\nOmessi (genere, valore, motivo):\n");
        for omission in &plan.omitted {
            testo.push_str(&format!(
                "  {kind}\t{value}\t{motivo}\n",
                kind = omission.indicator.kind.as_str(),
                value = omission.indicator.value,
                motivo = omission.reason.as_sentence(),
            ));
        }
    }

    testo.push_str(&format!("\n{ATTRIBUTION}\n"));
    testo
}

#[cfg(test)]
mod tests {
    use lisi_core::model::indicator::IndicatorKind;
    use lisi_core::model::session::{SessionDuration, SessionState};
    use lisi_core::text::DisplayName;

    use super::*;

    fn riga(kind: IndicatorKind, value: &str, quanti: u64) -> SessionIndicator {
        SessionIndicator {
            indicator: CyberIndicator {
                kind,
                value: String::from(value),
            },
            mentioning_contents: quanti,
        }
    }

    fn piano_di(indicatori: &[SessionIndicator]) -> StixExportPlan {
        plan_from(SessionId::new(1), indicatori)
    }

    fn json_di(indicatori: &[SessionIndicator]) -> String {
        render_bundle(
            &piano_di(indicatori),
            Timestamp::from_millis(1_757_000_000_000),
        )
    }

    /// **Il pacchetto non contiene mai un tipo che asserisce.**
    ///
    /// La guardia del dominio impedisce di costruirli. Questa guarda il JSON
    /// prodotto, cioè il punto in cui un tipo nuovo arriverebbe davvero a un
    /// altro sistema.
    #[test]
    fn il_pacchetto_prodotto_non_nomina_alcun_tipo_vietato() {
        let json = json_di(&[
            riga(IndicatorKind::Domain, "esempio.test", 3),
            riga(IndicatorKind::Ipv4, "198.51.100.3", 1),
            riga(IndicatorKind::Cve, "CVE-2026-1234", 2),
            riga(
                IndicatorKind::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                1,
            ),
        ]);

        for vietato in [
            "indicator",
            "observed-data",
            "sighting",
            "relationship",
            "identity",
            "threat-actor",
            "malware",
            "attack-pattern",
            "campaign",
            "intrusion-set",
            "grouping",
            "opinion",
            "infrastructure",
            "created_by_ref",
            "confidence",
            "pattern",
            "valid_from",
        ] {
            assert!(
                !json.contains(&format!("\"{vietato}\"")),
                "il pacchetto non deve nominare «{vietato}»:\n{json}"
            );
        }
    }

    /// **La busta TAXII porta gli stessi oggetti del pacchetto, e nient'altro**
    /// (ADR-0179, decisione 2).
    ///
    /// Né il guscio del pacchetto (`type`, `id`), né un oggetto in più: ciò che
    /// esce verso un server è ciò che uscirebbe in un file.
    #[test]
    fn la_busta_taxii_porta_gli_stessi_oggetti_del_pacchetto() {
        let indicatori = [
            riga(IndicatorKind::Domain, "esempio.test", 2),
            riga(IndicatorKind::Cve, "CVE-2026-1234", 1),
        ];
        let adesso = Timestamp::from_millis(1_757_000_000_000);
        let piano = piano_di(&indicatori);
        let (Ok(pacchetto), (busta, quanti)) = (
            serde_json::from_str::<serde_json::Value>(&render_bundle(&piano, adesso)),
            taxii_envelope(&piano, adesso),
        ) else {
            panic!("il pacchetto deve essere JSON valido");
        };
        let Ok(busta) = serde_json::from_slice::<serde_json::Value>(&busta) else {
            panic!("la busta deve essere JSON valido");
        };

        let Some(chiavi) = busta
            .as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
        else {
            panic!("la busta deve essere un oggetto");
        };
        assert_eq!(
            chiavi,
            vec![String::from("objects")],
            "la busta ha una chiave sola"
        );
        assert_eq!(busta["objects"], pacchetto["objects"]);
        // Due osservabili e l'avvertenza.
        assert_eq!(quanti, 3);
    }

    /// Il pacchetto è JSON valido, con un `bundle` e i tipi attesi.
    #[test]
    fn il_pacchetto_e_json_valido_con_i_tipi_attesi() {
        let json = json_di(&[
            riga(IndicatorKind::Domain, "esempio.test", 1),
            riga(IndicatorKind::Cve, "CVE-2026-1234", 1),
        ]);
        let Ok(valore) = serde_json::from_str::<serde_json::Value>(&json) else {
            panic!("il pacchetto deve essere JSON valido:\n{json}");
        };

        assert_eq!(valore["type"], "bundle");
        assert!(
            valore["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("bundle--"))
        );

        let Some(oggetti) = valore["objects"].as_array() else {
            panic!("il pacchetto deve portare un elenco di oggetti");
        };
        let ammessi = [
            "domain-name",
            "ipv4-addr",
            "ipv6-addr",
            "url",
            "file",
            "vulnerability",
            "note",
        ];
        for oggetto in oggetti {
            let Some(tipo) = oggetto["type"].as_str() else {
                panic!("ogni oggetto deve dichiarare il proprio tipo");
            };
            assert!(ammessi.contains(&tipo), "tipo non ammesso: {tipo}");
            assert_eq!(oggetto["spec_version"], "2.1");
            let Some(id) = oggetto["id"].as_str() else {
                panic!("ogni oggetto deve portare un identificativo");
            };
            assert!(
                id.starts_with(&format!("{tipo}--")),
                "l'identificativo {id} non corrisponde al tipo {tipo}"
            );
        }
    }

    /// **Il contenitore non porta `spec_version`**: STIX 2.1 lo ha tolto, e
    /// aggiungerlo lo renderebbe una proprietà personalizzata.
    #[test]
    fn il_contenitore_non_porta_spec_version() {
        let json = json_di(&[riga(IndicatorKind::Domain, "esempio.test", 1)]);
        let Ok(valore) = serde_json::from_str::<serde_json::Value>(&json) else {
            panic!("il pacchetto deve essere JSON valido");
        };
        assert!(valore.get("spec_version").is_none());
    }

    /// Gli oggetti di dominio portano gli istanti nella forma che STIX chiede.
    #[test]
    fn la_nota_porta_gli_istanti_al_millesimo() {
        let json = json_di(&[riga(IndicatorKind::Domain, "esempio.test", 1)]);
        let Ok(valore) = serde_json::from_str::<serde_json::Value>(&json) else {
            panic!("il pacchetto deve essere JSON valido");
        };
        let Some(oggetti) = valore["objects"].as_array() else {
            panic!("servono gli oggetti");
        };
        let Some(nota) = oggetti.iter().find(|oggetto| oggetto["type"] == "note") else {
            panic!("il pacchetto deve portare la propria avvertenza");
        };
        assert_eq!(nota["created"], "2025-09-04T15:33:20.000Z");
        assert_eq!(nota["modified"], "2025-09-04T15:33:20.000Z");
    }

    /// **Due esportazioni della stessa selezione danno gli stessi byte.**
    #[test]
    fn due_esportazioni_uguali_danno_gli_stessi_byte() {
        let indicatori = [
            riga(IndicatorKind::Domain, "esempio.test", 1),
            riga(IndicatorKind::Cve, "CVE-2026-1234", 1),
        ];
        assert_eq!(json_di(&indicatori), json_di(&indicatori));
    }

    /// **Un valore non rappresentabile esce dal piano con il proprio motivo.**
    #[test]
    fn un_valore_non_rappresentabile_e_omesso_con_il_motivo() {
        let piano = piano_di(&[
            riga(IndicatorKind::Domain, "esempio.test", 1),
            riga(IndicatorKind::Ipv4, "999.1.1.1", 1),
            riga(IndicatorKind::Url, "https://t.me/mario_rossi", 4),
        ]);

        assert_eq!(piano.exported.len(), 1);
        assert_eq!(piano.omitted.len(), 2);
        assert!(
            piano
                .omitted
                .iter()
                .any(|o| o.reason == StixOmission::MalformedValue)
        );
        assert!(
            piano
                .omitted
                .iter()
                .any(|o| o.reason == StixOmission::TelegramIdentifier)
        );
    }

    /// **Un identificativo Telegram non compare nel pacchetto.**
    #[test]
    fn un_identificativo_telegram_non_compare_nel_pacchetto() {
        let json = json_di(&[
            riga(IndicatorKind::Domain, "esempio.test", 1),
            riga(IndicatorKind::Url, "https://t.me/mario_rossi", 4),
            riga(IndicatorKind::Domain, "t.me", 4),
        ]);
        assert!(
            !json.contains("t.me"),
            "il pacchetto non deve nominare t.me"
        );
        assert!(!json.contains("mario_rossi"));
    }

    /// **Ciò che si mostra è ciò che si scrive.**
    ///
    /// Se il piano e il pacchetto divergessero, la schermata della milestone
    /// successiva mostrerebbe una cosa e ne produrrebbe un'altra.
    #[test]
    fn il_piano_e_il_pacchetto_dicono_la_stessa_cosa() {
        let indicatori = [
            riga(IndicatorKind::Domain, "esempio.test", 1),
            riga(IndicatorKind::Ipv4, "198.51.100.3", 1),
            riga(IndicatorKind::Cve, "CVE-2026-1234", 1),
            riga(IndicatorKind::Ipv4, "999.1.1.1", 1),
        ];
        let piano = piano_di(&indicatori);
        let json = render_bundle(&piano, Timestamp::from_millis(0));
        let Ok(valore) = serde_json::from_str::<serde_json::Value>(&json) else {
            panic!("il pacchetto deve essere JSON valido");
        };
        let Some(oggetti) = valore["objects"].as_array() else {
            panic!("servono gli oggetti");
        };

        let identificativi: Vec<String> = oggetti
            .iter()
            .filter(|oggetto| oggetto["type"] != "note")
            .filter_map(|oggetto| oggetto["id"].as_str().map(String::from))
            .collect();
        let previsti: Vec<String> = piano
            .exported
            .iter()
            .map(|planned| planned.stix_id.clone())
            .collect();

        assert_eq!(identificativi, previsti);
        for omesso in &piano.omitted {
            assert!(
                !json.contains(omesso.indicator.value.as_str()),
                "«{}» era omesso e non deve comparire",
                omesso.indicator.value
            );
        }
    }

    /// La provenienza dichiara di non far parte del pacchetto.
    #[test]
    fn la_provenienza_dichiara_di_stare_fuori_dal_pacchetto() {
        let piano = piano_di(&[
            riga(IndicatorKind::Domain, "esempio.test", 3),
            riga(IndicatorKind::Ipv4, "999.1.1.1", 1),
        ]);
        let (Ok(label), Ok(actor)) = (
            DisplayName::try_new("Monitoraggio di prova"),
            Actor::try_new("operatore"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let session = Session {
            id: SessionId::new(1),
            label,
            started_by: actor,
            duration: SessionDuration::Manual,
            state: SessionState::Stopped,
            created_at: Timestamp::from_millis(0),
            started_at: None,
            ended_at: None,
        };
        let testo = render_provenance(&session, &piano);

        assert!(testo.contains("NON fa parte del pacchetto STIX"));
        assert!(testo.contains("esempio.test"));
        assert!(testo.contains("999.1.1.1"));
        assert!(testo.contains("forma che il suo genere richiede"));
        assert!(testo.contains(ATTRIBUTION));
    }
}

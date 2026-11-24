//! Il punteggio CVSS delle CVE, letto dalla stessa fotografia NVD (CVSS-01,
//! ADR-0184).
//!
//! # Perché un modulo a parte
//!
//! Il servizio della fotografia non conosce punteggi, e una guardia lo
//! sorveglia: è ciò che tiene il punteggio fuori dal record della CVE, e da lì
//! fuori dai documenti e dalle viste dei contenuti. Qui si rilegge lo stesso
//! file di un anno, già verificato con la sua impronta, e se ne prende
//! soltanto il punteggio (ADR-0184, decisioni 1 e 2).
//!
//! # Che cosa si prende
//!
//! Per ogni CVE, il punteggio **primario** della versione più recente
//! presente (4.0, poi 3.1, 3.0, 2.0). Un punteggio che non si legge si omette
//! e si conta (decisione 6). Nessun punteggio si calcola qui.

use std::path::Path;

use lisi_core::CveSnapshotId;
use lisi_core::model::cve::CveId;
use lisi_core::model::cvss::{CvssScore, CvssVersion, WHAT_IT_GRADES};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Quanti punteggi si scrivono per transazione.
const SCORES_PER_BATCH: usize = 2_000;

/// Che cosa la lettura dei punteggi di un anno ha prodotto.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct YearScores {
    /// I punteggi scritti.
    pub written: u64,
    /// Le CVE con un punteggio che non si è potuto leggere.
    pub omitted: u64,
}

#[derive(serde::Deserialize)]
struct RawFeed {
    #[serde(default)]
    vulnerabilities: Vec<RawVulnerability>,
}

#[derive(serde::Deserialize)]
struct RawVulnerability {
    cve: RawCve,
}

#[derive(serde::Deserialize)]
struct RawCve {
    #[serde(default)]
    id: String,
    #[serde(default)]
    metrics: RawMetrics,
}

#[derive(serde::Deserialize, Default)]
struct RawMetrics {
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<RawMetric>,
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<RawMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<RawMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<RawMetric>,
}

#[derive(serde::Deserialize)]
struct RawMetric {
    #[serde(default)]
    source: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(rename = "cvssData")]
    data: RawData,
    /// In CVSS 2.0 la severità sta fuori da `cvssData`.
    #[serde(default, rename = "baseSeverity")]
    outer_severity: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawData {
    #[serde(default, rename = "vectorString")]
    vector: String,
    #[serde(rename = "baseScore")]
    base: f64,
    #[serde(default, rename = "baseSeverity")]
    severity: Option<String>,
}

/// Il punteggio da conservare per una CVE: il primario della versione più
/// recente presente. `Err(())` se c'è ma non si legge; `Ok(None)` se non c'è.
fn scegli(metriche: &RawMetrics) -> Result<Option<CvssScore>, ()> {
    for (versione, elenco) in [
        (CvssVersion::V40, &metriche.v40),
        (CvssVersion::V31, &metriche.v31),
        (CvssVersion::V30, &metriche.v30),
        (CvssVersion::V2, &metriche.v2),
    ] {
        let Some(primario) = elenco.iter().find(|metrica| metrica.kind == "Primary") else {
            continue;
        };
        let severita = primario
            .data
            .severity
            .as_deref()
            .or(primario.outer_severity.as_deref())
            .unwrap_or_default();
        let decimi = CvssScore::tenths_of(primario.data.base).map_err(|_| ())?;
        return CvssScore::try_new(
            versione,
            &primario.data.vector,
            decimi,
            severita,
            &primario.source,
        )
        .map(Some)
        .map_err(|_| ());
    }
    Ok(None)
}

/// Legge i punteggi di un anno già verificato e li scrive per la fotografia.
///
/// La chiama soltanto il servizio della fotografia, dopo aver scritto le voci
/// dello stesso anno.
///
/// # Errori
///
/// [`ServiceError::CveImportRefused`] se il file non si legge; un errore se la
/// scrittura non riesce.
pub fn import_year(
    database: &mut Database,
    snapshot_id: CveSnapshotId,
    year_file: &Path,
) -> ServiceResult<YearScores> {
    let file = std::fs::File::open(year_file).map_err(|_| ServiceError::CveImportRefused {
        reason: "la fotografia di un anno non si apre",
    })?;
    let feed: RawFeed = serde_json::from_reader(std::io::BufReader::new(file)).map_err(|_| {
        ServiceError::CveImportRefused {
            reason: "la fotografia di un anno non è un file di dati leggibile",
        }
    })?;

    let mut esito = YearScores::default();
    let mut punteggi = Vec::new();
    for voce in feed.vulnerabilities {
        let Ok(id) = CveId::try_new(&voce.cve.id) else {
            // L'identificativo storto lo conta già la fotografia.
            continue;
        };
        match scegli(&voce.cve.metrics) {
            Ok(Some(punteggio)) => punteggi.push((id, punteggio)),
            Ok(None) => {}
            Err(()) => esito.omitted += 1,
        }
    }
    for blocco in punteggi.chunks(SCORES_PER_BATCH) {
        esito.written += database.insert_cve_scores(snapshot_id, blocco)? as u64;
    }
    Ok(esito)
}

/// La frase del punteggio per la scheda della CVE (ADR-0184, decisioni 3 e
/// 5). È l'unico modo in cui l'interfaccia lo riceve.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn sentence(
    database: &Database,
    snapshot_id: CveSnapshotId,
    id: &CveId,
) -> ServiceResult<String> {
    if !database.cve_snapshot_has_scores(snapshot_id)? {
        return Ok(String::from(
            "Questa fotografia non porta i punteggi CVSS: è stata importata prima che il \
             programma li leggesse.",
        ));
    }
    Ok(match database.cve_score(snapshot_id, id)? {
        Some(punteggio) => punteggio.as_sentence(),
        None => format!("NVD non dichiara un punteggio CVSS per questa CVE. {WHAT_IT_GRADES}"),
    })
}

#[cfg(test)]
mod tests {
    use super::{RawMetrics, scegli};
    use lisi_core::model::cvss::CvssVersion;

    fn metriche(json: &str) -> RawMetrics {
        let Ok(metriche) = serde_json::from_str::<RawMetrics>(json) else {
            panic!("le metriche di prova si leggono");
        };
        metriche
    }

    /// **Il primario della versione più recente** (ADR-0184, decisione 2):
    /// il secondario non conta, la 3.1 batte la 2.0, la severità della 2.0
    /// sta fuori da `cvssData`.
    #[test]
    fn si_prende_il_primario_della_versione_piu_recente() {
        let Ok(Some(punteggio)) = scegli(&metriche(
            r#"{
                "cvssMetricV31": [
                    {"source": "altro@esempio.test", "type": "Secondary",
                     "cvssData": {"vectorString": "CVSS:3.1/AV:L", "baseScore": 2.0, "baseSeverity": "LOW"}},
                    {"source": "nvd@nist.gov", "type": "Primary",
                     "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                ],
                "cvssMetricV2": [
                    {"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
                     "cvssData": {"vectorString": "AV:N/AC:L", "baseScore": 7.5}}
                ]
            }"#,
        )) else {
            panic!("c'è un punteggio primario");
        };
        assert_eq!(punteggio.version(), CvssVersion::V31);
        assert_eq!(punteggio.base_tenths(), 98);
        assert_eq!(punteggio.source(), "nvd@nist.gov");

        let Ok(Some(vecchio)) = scegli(&metriche(
            r#"{"cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
                 "cvssData": {"vectorString": "AV:N/AC:L", "baseScore": 7.5}}]}"#,
        )) else {
            panic!("la 2.0 si legge");
        };
        assert_eq!(vecchio.severity(), "HIGH");
    }

    /// **Nessun punteggio, o uno che non si legge** (ADR-0184, decisione 6).
    #[test]
    fn senza_punteggio_o_con_uno_storto() {
        assert_eq!(scegli(&metriche("{}")), Ok(None));
        assert_eq!(
            scegli(&metriche(
                r#"{"cvssMetricV31": [{"source": "x", "type": "Secondary",
                    "cvssData": {"vectorString": "AV:N", "baseScore": 5.0, "baseSeverity": "MEDIUM"}}]}"#
            )),
            Ok(None),
            "soltanto un secondario"
        );
        assert_eq!(
            scegli(&metriche(
                r#"{"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                    "cvssData": {"vectorString": "AV:N", "baseScore": 11.0, "baseSeverity": "CRITICAL"}}]}"#
            )),
            Err(())
        );
    }

    /// I file di produzione di tutte le crate, con il percorso relativo.
    fn sorgenti() -> Vec<(String, String)> {
        let radice = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut trovati = Vec::new();
        let mut da_vedere = vec![radice.clone()];
        while let Some(cartella) = da_vedere.pop() {
            let Ok(voci) = std::fs::read_dir(&cartella) else {
                continue;
            };
            for voce in voci.flatten() {
                let percorso = voce.path();
                if percorso.is_dir() {
                    if !percorso.ends_with("target") && !percorso.ends_with("tests") {
                        da_vedere.push(percorso);
                    }
                } else if percorso.extension().is_some_and(|e| e == "rs") {
                    let Ok(testo) = std::fs::read_to_string(&percorso) else {
                        continue;
                    };
                    let produzione = testo
                        .split_once("\n#[cfg(test)]")
                        .map_or(testo.as_str(), |(prima, _)| prima)
                        .to_owned();
                    let relativo = percorso
                        .strip_prefix(&radice)
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default();
                    trovati.push((relativo, produzione));
                }
            }
        }
        trovati
    }

    /// **Il punteggio non compare fuori dalla scheda della CVE** (ADR-0184,
    /// decisione 4): fuori dai moduli che lo leggono, lo conservano e lo
    /// mostrano nella scheda, il codice di produzione non lo nomina. Una
    /// relazione, un registro, un avviso o la vista di un contenuto che lo
    /// nominassero farebbero diventare rossa questa prova.
    #[test]
    fn il_punteggio_non_compare_fuori_dalla_scheda() {
        const AMMESSI: [&str; 9] = [
            "lisi-core/src/model/cvss.rs",
            "lisi-core/src/model/mod.rs",
            "lisi-services/src/cve_scores.rs",
            "lisi-services/src/cve_snapshot.rs",
            "lisi-services/src/lib.rs",
            "lisi-storage/src/repository/cve_scores.rs",
            "lisi-storage/src/repository/mod.rs",
            "lisi-storage/src/migrations.rs",
            "lisi-app/src/references.rs",
        ];
        let mut visti = 0;
        for (file, produzione) in sorgenti() {
            let minuscolo = produzione.to_lowercase();
            if minuscolo.contains("cvss") || minuscolo.contains("cve_score") {
                assert!(
                    AMMESSI.contains(&file.as_str()),
                    "{file} nomina il punteggio CVSS: si mostra soltanto nella scheda della CVE"
                );
                visti += 1;
            }
        }
        assert!(
            visti >= 5,
            "la prova non trova più i moduli del punteggio: {visti}"
        );
    }
}

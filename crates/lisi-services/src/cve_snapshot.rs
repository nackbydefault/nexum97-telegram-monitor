//! Importazione delle fotografie annuali CVE/NVD, e risoluzione offline.
//!
//! # Il prodotto non scarica, e non decomprime
//!
//! I file arrivano da `scripts/fetch-cve.ps1`, che li scarica, verifica
//! l'impronta contro quella che **NVD stessa** dichiara nel proprio `.meta`, e
//! li estrae. Qui si legge JSON semplice: il prodotto non acquisisce né un
//! client HTTP né una libreria di decompressione per leggere un file che
//! qualcun altro ha già preso (ADR-0060).
//!
//! **L'impronta si riverifica.** Fra l'acquisizione e l'importazione può essere
//! passato del tempo, e chi importa non sa quanto.
//!
//! # Che cosa NON entra
//!
//! Il punteggio CVSS, le configurazioni CPE, le debolezze CWE e l'elenco dei
//! riferimenti. Il prodotto deve **risolvere un identificativo**, non possedere
//! l'inventario del software del mondo — e un numero che sembra oggettivo,
//! stampato accanto a un messaggio scritto da una persona, viene letto come un
//! giudizio su quel messaggio.
//!
//! # Una voce che non entra lo dice
//!
//! Una fotografia a cui manca una voce, **senza dirlo**, risponde «assente dal
//! catalogo» a una domanda a cui NVD risponde di sì — e in questo prodotto
//! quella risposta significa «identificativo inventato». Ogni omissione porta il
//! proprio motivo.

use std::path::{Path, PathBuf};

use lisi_core::model::NewAuditEntry;
use lisi_core::model::cve::{
    CveId, CveOmission, CveOmissionReason, CveRecord, CveResolution, CveStatus, MAX_RECORDS,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{CveSnapshotId, Sha256Digest, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::cve::{AcquiredYear, StoredCveSnapshot};

use crate::error::{ServiceError, ServiceResult};

/// Quanti byte può avere una fotografia annuale.
///
/// L'anno 2026 ne ha circa 340 milioni decompressi. Il tetto non serve a
/// limitare NVD: serve a rifiutare un file che dice di essere una fotografia
/// CVE e non lo è, **prima** di provare a leggerlo.
pub const MAX_YEAR_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Quanti byte può avere un file `.meta`.
pub const MAX_META_BYTES: u64 = 4 * 1024;

/// Quante voci si scrivono per transazione.
///
/// Una fotografia di tre anni ha più di centomila voci: tenerle tutte in
/// memoria prima di scriverle costerebbe centinaia di megabyte senza guadagnare
/// nulla.
pub const RECORDS_PER_BATCH: usize = 2_000;

/// Lo schema della fonte, come si scrive in archivio.
pub const SOURCE_SCHEMA: &str = "NVD_CVE 2.0";

/// L'attribuzione che registra una fotografia importata dalla schermata
/// «Riferimenti informatici» (PR-14, ADR-0130): la designazione di MITRE per i
/// record CVE e il non-avallo di NVD, come chiede `cve.lock.json`. Non ripete la
/// formula delle API di NVD, che il prodotto non usa. La formula esatta si
/// riverifica sui termini d'uso correnti (HVQ-63).
pub const CVE_ATTRIBUTION: &str = "CVE® © The MITRE Corporation, secondo i CVE Terms of Use. \
     Dalle fotografie statiche di NVD (NIST): NVD non avalla questo prodotto.";

/// Che cosa un'importazione ha prodotto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveImportOutcome {
    /// La fotografia registrata.
    pub snapshot_id: CveSnapshotId,
    /// Gli anni acquisiti, con l'identità di ciò che è stato preso.
    pub years: Vec<AcquiredYear>,
    /// Quante voci sono entrate.
    pub records: u64,
    /// Le voci lasciate fuori, con il loro motivo.
    ///
    /// **Non è un difetto nascosto: è l'esito.** Una fotografia a cui manca una
    /// voce senza dirlo risponde «assente dal catalogo» a una domanda a cui NVD
    /// risponde di sì.
    pub omitted: Vec<CveOmission>,
    /// Quante voci hanno anche il loro punteggio, letto a parte
    /// (`crate::cve_scores`, ADR-0184).
    pub scored: u64,
    /// Quante voci hanno un punteggio che non si è potuto leggere.
    pub scored_omitted: u64,
}

/// Il servizio della fotografia CVE.
pub struct CveSnapshotService<'a> {
    database: &'a mut Database,
}

impl<'a> CveSnapshotService<'a> {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub fn new(database: &'a mut Database) -> Self {
        Self { database }
    }

    /// Le fotografie in archivio, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn snapshots(&self) -> ServiceResult<Vec<StoredCveSnapshot>> {
        Ok(self.database.cve_snapshots()?)
    }

    /// Importa una fotografia dagli anni presenti nella cartella indicata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un file manca o non si legge, se l'impronta non
    /// corrisponde a quella dichiarata da NVD, se un anno non supera la
    /// validazione, o se la scrittura non riesce.
    pub fn import(
        &mut self,
        directory: &Path,
        years: &[i32],
        attribution: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<CveImportOutcome> {
        if years.is_empty() {
            return Err(ServiceError::CveImportRefused {
                reason: "una fotografia che non copre alcun anno non è una fotografia",
            });
        }

        // PRIMA SI VERIFICA TUTTO, POI SI SCRIVE.
        //
        // Un anno che non corrisponde a meta' importazione lascerebbe una
        // fotografia parziale che si dichiara intera - e la sua copertura
        // direbbe una cosa falsa proprio dove serve a distinguere «non lo so»
        // da «non esiste».
        let mut acquisiti = Vec::new();
        for anno in years {
            acquisiti.push(verify_year(directory, *anno)?);
        }

        let snapshot_id =
            self.database
                .open_cve_snapshot(SOURCE_SCHEMA, attribution, &acquisiti, actor, now)?;

        let mut scritte = 0_u64;
        let mut omitted = Vec::new();
        let mut scored = 0_u64;
        let mut scored_omitted = 0_u64;
        for anno in years {
            let (records, omissioni) = read_year(directory, *anno)?;
            omitted.extend(omissioni);
            for blocco in records.chunks(RECORDS_PER_BATCH) {
                scritte += self.database.insert_cve_records(snapshot_id, blocco)? as u64;
            }
            // Il punteggio lo legge un modulo a parte, dallo stesso file già
            // verificato: questo servizio non sa che cosa ci sia (ADR-0184,
            // decisione 1).
            let anno_letto = crate::cve_scores::import_year(
                self.database,
                snapshot_id,
                &year_path(directory, *anno),
            )?;
            scored += anno_letto.written;
            scored_omitted += anno_letto.omitted;
        }

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("fotografia_cve_importata")?,
            entity: AuditEntity::try_new("cve_snapshot")?,
            entity_id: Some(snapshot_id.get()),
            // Importare un catalogo pubblico non e' un'azione riservata.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "cve {schema}: anni {anni}, {voci} voci, {omesse} omesse",
                schema = SOURCE_SCHEMA,
                anni = years
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<String>>()
                    .join(", "),
                voci = scritte,
                omesse = omitted.len(),
            ))?),
            recorded_at: now,
        })?;

        Ok(CveImportOutcome {
            snapshot_id,
            years: acquisiti,
            records: scritte,
            omitted,
            scored,
            scored_omitted,
        })
    }

    /// Risolve un identificativo dentro una fotografia.
    ///
    /// L'esito ha **tre forme**, e due di esse sono due assenze diverse: vedere
    /// [`CveResolution`].
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn resolve(&self, snapshot_id: CveSnapshotId, id: &CveId) -> ServiceResult<CveResolution> {
        Ok(self.database.resolve_cve(snapshot_id, id)?)
    }
}

/// Il percorso della fotografia di un anno.
fn year_path(directory: &Path, year: i32) -> PathBuf {
    directory.join(format!("nvdcve-2.0-{year}.json"))
}

/// Il percorso del `.meta` di un anno.
fn meta_path(directory: &Path, year: i32) -> PathBuf {
    directory.join(format!("nvdcve-2.0-{year}.meta"))
}

/// Verifica un anno contro l'impronta che NVD dichiara, e ne restituisce
/// l'identità.
fn verify_year(directory: &Path, year: i32) -> ServiceResult<AcquiredYear> {
    let meta = read_meta(&meta_path(directory, year))?;

    let json = year_path(directory, year);
    let metadata = std::fs::metadata(&json).map_err(|_| ServiceError::CveImportRefused {
        reason: "la fotografia di un anno dichiarato non si legge",
    })?;
    if metadata.len() > MAX_YEAR_BYTES {
        return Err(ServiceError::CveImportRefused {
            reason: "la fotografia di un anno è oltre la misura ammessa",
        });
    }

    let file = std::fs::File::open(&json).map_err(|_| ServiceError::CveImportRefused {
        reason: "la fotografia di un anno non si apre",
    })?;
    let digest = Sha256Digest::of_reader(std::io::BufReader::new(file)).map_err(|_| {
        ServiceError::CveImportRefused {
            reason: "la fotografia di un anno non si legge per intero",
        }
    })?;

    if digest.as_str() != meta.sha256 {
        return Err(ServiceError::CveImportRefused {
            reason: "l'impronta di un anno non è quella che NVD dichiara nel proprio .meta",
        });
    }

    Ok(AcquiredYear {
        year,
        source_sha256: meta.sha256,
        source_last_modified: meta.last_modified,
    })
}

/// Ciò che un `.meta` dichiara.
struct DeclaredMeta {
    sha256: String,
    last_modified: String,
}

/// Legge un `.meta`, che è testo di terze parti con un formato semplice.
///
/// # Perché si rifiuta un `.meta` senza impronta
///
/// Perché è ciò contro cui si verifica. Un `.meta` senza impronta non è un
/// `.meta`, ed è meglio fermarsi che procedere senza verifica.
fn read_meta(path: &Path) -> ServiceResult<DeclaredMeta> {
    let metadata = std::fs::metadata(path).map_err(|_| ServiceError::CveImportRefused {
        reason: "il file .meta di un anno dichiarato non si legge",
    })?;
    if metadata.len() > MAX_META_BYTES {
        return Err(ServiceError::CveImportRefused {
            reason: "il file .meta è oltre la misura ammessa: non è un .meta",
        });
    }

    let testo = std::fs::read_to_string(path).map_err(|_| ServiceError::CveImportRefused {
        reason: "il file .meta non è testo leggibile",
    })?;

    let mut sha256 = None;
    let mut last_modified = None;
    for riga in testo.lines() {
        if let Some(valore) = riga.strip_prefix("sha256:") {
            sha256 = Some(valore.trim().to_ascii_lowercase());
        } else if let Some(valore) = riga.strip_prefix("lastModifiedDate:") {
            last_modified = Some(String::from(valore.trim()));
        }
    }

    let Some(sha256) = sha256 else {
        return Err(ServiceError::CveImportRefused {
            reason: "il file .meta non dichiara alcuna impronta",
        });
    };
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ServiceError::CveImportRefused {
            reason: "l'impronta dichiarata dal file .meta non ha la forma di un'impronta",
        });
    }

    Ok(DeclaredMeta {
        sha256,
        last_modified: last_modified.unwrap_or_default(),
    })
}

/// La fotografia di un anno, con i soli campi che questo prodotto guarda.
///
/// # Perché una struttura e non un albero JSON generico
///
/// Perché ciò che non è dichiarato qui **non viene nemmeno allocato**: un file
/// di trecento megabyte pieno di configurazioni CPE, punteggi e riferimenti non
/// diventa trecento megabyte di memoria. Ed è anche una guardia: un campo che
/// non esiste in questa struttura non può finire nell'archivio per distrazione,
/// e il punteggio CVSS **non esiste qui**.
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
    published: String,
    #[serde(default, rename = "lastModified")]
    last_modified: String,
    #[serde(default, rename = "vulnStatus")]
    status: String,
    #[serde(default)]
    descriptions: Vec<RawDescription>,
}

#[derive(serde::Deserialize)]
struct RawDescription {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

/// Legge la fotografia di un anno, separando ciò che entra da ciò che si omette.
fn read_year(directory: &Path, year: i32) -> ServiceResult<(Vec<CveRecord>, Vec<CveOmission>)> {
    let json = year_path(directory, year);
    let file = std::fs::File::open(&json).map_err(|_| ServiceError::CveImportRefused {
        reason: "la fotografia di un anno non si apre",
    })?;

    let feed: RawFeed = serde_json::from_reader(std::io::BufReader::new(file)).map_err(|_| {
        ServiceError::CveImportRefused {
            reason: "la fotografia di un anno non è un file di dati leggibile",
        }
    })?;

    if feed.vulnerabilities.len() > MAX_RECORDS {
        return Err(ServiceError::CveImportRefused {
            reason: "la fotografia dichiara più voci di quante il catalogo ne abbia mai avute",
        });
    }

    let mut records = Vec::with_capacity(feed.vulnerabilities.len());
    let mut omitted = Vec::new();

    for voce in feed.vulnerabilities {
        let dichiarato = voce.cve.id.clone();

        let Ok(id) = CveId::try_new(&voce.cve.id) else {
            omitted.push(CveOmission {
                declared_id: dichiarato,
                reason: CveOmissionReason::MalformedIdentifier,
            });
            continue;
        };

        // SOLO LA DESCRIZIONE INGLESE.
        //
        // Le traduzioni sono feed separati, di altri enti - INCIBE per lo
        // spagnolo - e prenderne una chiamandola NVD attribuirebbe a NVD un
        // testo che non e' suo.
        let Some(descrizione) = voce
            .cve
            .descriptions
            .iter()
            .find(|descrizione| descrizione.lang == "en")
        else {
            omitted.push(CveOmission {
                declared_id: dichiarato,
                reason: CveOmissionReason::NoEnglishDescription,
            });
            continue;
        };

        let Ok(status) = CveStatus::try_new(&voce.cve.status) else {
            omitted.push(CveOmission {
                declared_id: dichiarato,
                reason: CveOmissionReason::IncompleteRecord,
            });
            continue;
        };

        match CveRecord::new(
            id,
            &descrizione.value,
            &voce.cve.published,
            &voce.cve.last_modified,
            status,
        ) {
            Ok(record) => records.push(record),
            Err(lisi_core::DomainError::TooLong { .. }) => omitted.push(CveOmission {
                declared_id: dichiarato,
                reason: CveOmissionReason::DescriptionTooLong,
            }),
            Err(_) => omitted.push(CveOmission {
                declared_id: dichiarato,
                reason: CveOmissionReason::IncompleteRecord,
            }),
        }
    }

    Ok((records, omitted))
}

#[cfg(test)]
mod tests {

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("cve_snapshot.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| {
                let trimmed = riga.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    /// **Il servizio non conosce i punteggi.**
    ///
    /// Un campo che non esiste nella struttura di lettura non può finire
    /// nell'archivio per distrazione.
    #[test]
    fn il_servizio_non_conosce_punteggi() {
        for vietato in [
            "cvss",
            "Cvss",
            "CVSS",
            "metrics",
            "baseScore",
            "base_score",
            "baseSeverity",
            "severity",
        ] {
            assert!(
                !codice_di_produzione().contains(vietato),
                "il servizio della fotografia CVE non deve nominare «{vietato}»"
            );
        }
    }

    /// **Il servizio non decomprime.**
    ///
    /// # Perché qui non si sorveglia anche la rete
    ///
    /// Perché lo fa già, e meglio, una guardia del prodotto:
    /// `il_prodotto_non_ascolta` percorre **ogni** crate e vieta i tipi di rete
    /// dello standard. Ripeterli qui non aggiungerebbe nulla — e, la prima
    /// volta che è stato provato, ha fatto diventare rossa proprio quella
    /// guardia, perché un elenco di parole vietate è codice che contiene le
    /// parole vietate.
    ///
    /// Ciò che resta a questa prova è la decompressione, che nessun'altra
    /// guardia copre: i file arrivano già estratti da
    /// `scripts/fetch-cve.ps1`, e il prodotto non acquisisce una libreria per
    /// aprire un archivio che qualcun altro ha già aperto.
    #[test]
    fn il_servizio_non_decomprime() {
        for vietato in ["ZipArchive", "GzDecoder", "flate2", "zip::"] {
            assert!(
                !codice_di_produzione().contains(vietato),
                "il servizio della fotografia CVE non deve nominare «{vietato}»"
            );
        }
    }
}

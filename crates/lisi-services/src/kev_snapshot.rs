//! Importazione del catalogo CISA KEV, e risoluzione offline.
//!
//! # Il prodotto non scarica
//!
//! Il file arriva da `scripts/fetch-kev.ps1`. Qui si legge JSON semplice: il
//! prodotto non acquisisce un client HTTP per prendere un file che qualcun
//! altro ha già preso (ADR-0061).
//!
//! # Che cosa si verifica davvero, e che cosa no
//!
//! **Non** un'impronta dichiarata dalla fonte: **CISA non ne pubblica alcuna**.
//! Si verificano due cose, e vanno chiamate con il loro nome.
//!
//! 1. **La coerenza interna del file.** Il catalogo dichiara `count`, e un file
//!    il cui conteggio non corrisponde alle voci presenti è stato troncato,
//!    tagliato o modificato. È l'unica integrità che la fonte offre **di sé**.
//! 2. **L'impronta di ciò che è stato acquisito**, calcolata dallo script e
//!    riverificata qui. Dice una cosa sola: che il file non è cambiato da quando
//!    è stato preso. **Non dice che sia quello che CISA ha pubblicato.**
//!
//! # Che cosa NON entra
//!
//! `requiredAction`, `dueDate` e `forensicTriage`: un **ordine rivolto alle
//! agenzie federali civili statunitensi**, che questo ufficio non deve leggere
//! come rivolto a sé. E `cwes` e `notes`, per proporzione.
//!
//! # Una voce che non entra lo dice
//!
//! Perché una fotografia a cui manca una voce, **senza dirlo**, risponde «non
//! elencata» a una domanda a cui CISA risponde di sì — ed è l'unica risposta che
//! questa fotografia non deve mai sbagliare.

use std::path::{Path, PathBuf};

use lisi_core::model::NewAuditEntry;
use lisi_core::model::cve::CveId;
use lisi_core::model::kev::{
    KevCatalogIdentity, KevEntry, KevOmission, KevOmissionReason, KevResolution, MAX_ENTRIES,
    RansomwareUse,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{KevSnapshotId, Sha256Digest, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::kev::{NewKevSnapshot, StoredKevSnapshot};

use crate::error::{ServiceError, ServiceResult};

/// Quanti byte può avere il catalogo.
///
/// Il catalogo reale ne pesava **1 714 060** il 2026-09-10: otto mebibyte sono
/// già quasi cinque volte il necessario. Il tetto non serve a limitare CISA:
/// serve a rifiutare un file che dice di essere un catalogo KEV e non lo è.
///
/// # Perché è questo numero a limitare la memoria, e non [`MAX_ENTRIES`]
///
/// Perché il tetto sulle voci si può controllare **solo dopo** che il documento
/// è stato interpretato, e a quel punto la memoria è già stata occupata. Un file
/// pieno di voci minime produrrebbe milioni di record da qualche decina di byte
/// l'uno: il tetto sulle voci lo **constaterebbe** invece di impedirlo.
///
/// Il catalogo si legge in un buffer limitato da questo numero, e sono quei
/// byte — **gli stessi** su cui si calcola l'impronta — a essere interpretati.
pub const MAX_CATALOGUE_BYTES: u64 = 8 * 1024 * 1024;

/// Quanti byte può avere il file di impronta.
pub const MAX_DIGEST_FILE_BYTES: u64 = 4 * 1024;

/// Il nome del file del catalogo, come lo scrive lo script di acquisizione.
pub const CATALOGUE_FILE: &str = "known_exploited_vulnerabilities.json";

/// Il nome del file che porta l'impronta **calcolata da noi**.
///
/// Si chiama `acquired` e non `source` perché non viene dalla fonte, e il nome è
/// il posto in cui quella differenza non si perde.
pub const ACQUIRED_DIGEST_FILE: &str = "known_exploited_vulnerabilities.acquired.sha256";

/// La fonte, registrata dentro la fotografia.
///
/// La licenza è CC0 e non richiederebbe alcuna attribuzione: qui l'attribuzione
/// serve alla **verità della frase**, perché il prodotto cita CISA invece di
/// affermare al suo posto.
pub const ATTRIBUTION: &str = "CISA — Known Exploited Vulnerabilities Catalog (CC0 1.0 Universal)";

/// Che cosa un'importazione ha prodotto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevImportOutcome {
    /// La fotografia registrata.
    pub snapshot_id: KevSnapshotId,
    /// L'identità del catalogo: versione e istante di rilascio.
    pub catalog: KevCatalogIdentity,
    /// Quante voci sono entrate.
    pub entries: u64,
    /// Quante voci il catalogo dichiarava di avere.
    pub declared_count: u64,
    /// Le voci lasciate fuori, con il loro motivo.
    ///
    /// **Non è un difetto nascosto: è l'esito.**
    pub omitted: Vec<KevOmission>,
}

/// Il servizio della fotografia KEV.
pub struct KevSnapshotService<'a> {
    database: &'a mut Database,
}

impl<'a> KevSnapshotService<'a> {
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
    pub fn snapshots(&self) -> ServiceResult<Vec<StoredKevSnapshot>> {
        Ok(self.database.kev_snapshots()?)
    }

    /// Importa il catalogo dalla cartella indicata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il file manca o non si legge, se l'impronta non
    /// è quella registrata all'acquisizione, se il conteggio dichiarato non
    /// corrisponde alle voci presenti, o se la scrittura non riesce.
    pub fn import(
        &mut self,
        directory: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<KevImportOutcome> {
        // SI LEGGE UNA VOLTA SOLA, E SI SCRIVE IN UNA VOLTA SOLA.
        //
        // Gli stessi byte su cui si calcola l'impronta sono quelli che vengono
        // interpretati: aprire il file due volte lascerebbe fra la verifica e
        // la lettura una finestra in cui qualcuno puo' sostituirlo, e
        // l'impronta varrebbe su un contenuto diverso da quello importato.
        //
        // La scrittura e' una transazione sola perche' una fotografia parziale
        // e' IMMUTABILE E INCANCELLABILE: risponderebbe «non elencata» a una
        // domanda a cui CISA risponde di si', per sempre.
        let bytes = read_catalogue_bytes(directory)?;
        verify_acquired_digest(directory, &bytes)?;
        let acquired_sha256 = Sha256Digest::of_bytes(&bytes).as_str().to_string();
        let (catalog, declared_count, entries, omitted) = read_catalogue(&bytes)?;

        let scritte = entries.len() as u64;
        let snapshot_id = self.database.record_kev_snapshot(&NewKevSnapshot {
            catalog: &catalog,
            declared_count,
            omitted_count: omitted.len() as u64,
            acquired_sha256: &acquired_sha256,
            attribution: ATTRIBUTION,
            entries: &entries,
            imported_by: actor,
            imported_at: now,
        })?;

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("fotografia_kev_importata")?,
            entity: AuditEntity::try_new("kev_snapshot")?,
            entity_id: Some(snapshot_id.get()),
            // Importare un catalogo pubblico non e' un'azione riservata.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "kev {versione} del {rilascio}: {voci} voci, {omesse} omesse",
                versione = catalog.version(),
                rilascio = catalog.released_at(),
                voci = scritte,
                omesse = omitted.len(),
            ))?),
            recorded_at: now,
        })?;

        Ok(KevImportOutcome {
            snapshot_id,
            catalog,
            entries: scritte,
            declared_count,
            omitted,
        })
    }

    /// Risolve un identificativo dentro una fotografia del catalogo.
    ///
    /// L'esito ha **due forme asimmetriche**: la prima afferma per bocca di
    /// CISA, la seconda **non sa**. Vedere [`KevResolution`].
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn resolve(&self, snapshot_id: KevSnapshotId, id: &CveId) -> ServiceResult<KevResolution> {
        Ok(self.database.resolve_kev(snapshot_id, id)?)
    }
}

/// Il percorso del catalogo.
fn catalogue_path(directory: &Path) -> PathBuf {
    directory.join(CATALOGUE_FILE)
}

/// Il percorso del file che porta l'impronta calcolata all'acquisizione.
fn digest_path(directory: &Path) -> PathBuf {
    directory.join(ACQUIRED_DIGEST_FILE)
}

/// Legge il catalogo **una volta sola**, in un buffer limitato.
///
/// # Perché il tetto sta qui e non dopo
///
/// Perché il tetto sulle **voci** si può controllare solo dopo aver interpretato
/// il documento, e a quel punto la memoria è già occupata: un file pieno di voci
/// minime produrrebbe milioni di record: quel tetto constaterebbe invece di
/// impedire. Qui si leggono al più [`MAX_CATALOGUE_BYTES`] byte, e un file più
/// grande viene rifiutato **senza** essere interpretato.
///
/// Il controllo non si fida della misura dichiarata dal filesystem: legge un
/// byte in più del tetto e rifiuta se arriva.
fn read_catalogue_bytes(directory: &Path) -> ServiceResult<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(catalogue_path(directory)).map_err(|_| {
        ServiceError::KevImportRefused {
            reason: "il catalogo KEV non si apre",
        }
    })?;

    let mut bytes = Vec::new();
    std::io::BufReader::new(file)
        .take(MAX_CATALOGUE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ServiceError::KevImportRefused {
            reason: "il catalogo KEV non si legge per intero",
        })?;

    if bytes.len() as u64 > MAX_CATALOGUE_BYTES {
        return Err(ServiceError::KevImportRefused {
            reason: "il catalogo KEV è oltre la misura ammessa",
        });
    }

    Ok(bytes)
}

/// Riverifica i byte letti contro l'impronta registrata all'acquisizione.
///
/// # Che cosa questa verifica dimostra, e che cosa no
///
/// Dimostra che il file **non è cambiato da quando è stato preso**. Non dimostra
/// che sia quello che CISA ha pubblicato: CISA non pubblica alcuna impronta, e
/// questa l'ha calcolata lo script di acquisizione.
///
/// **E non dimostra nulla contro chi può scrivere in quella cartella.** Il file
/// di impronta sta accanto al catalogo, con gli stessi permessi: chi può
/// sostituire l'uno può riscrivere l'altro. Protegge dal cambiamento
/// accidentale, non dalla sostituzione deliberata.
///
/// # Perché riceve i byte invece di rileggere il file
///
/// Perché ciò che si verifica devono essere **gli stessi byte** che verranno
/// interpretati. Rileggere lascerebbe fra la verifica e la lettura una finestra
/// in cui il file può cambiare, e l'impronta varrebbe su un contenuto diverso da
/// quello importato.
fn verify_acquired_digest(directory: &Path, bytes: &[u8]) -> ServiceResult<()> {
    let registrata = read_declared_digest(&digest_path(directory))?;

    if Sha256Digest::of_bytes(bytes).as_str() != registrata {
        return Err(ServiceError::KevImportRefused {
            reason: "il catalogo KEV è cambiato da quando è stato acquisito",
        });
    }

    Ok(())
}

/// Legge l'impronta dal file che l'accompagna.
///
/// Il formato è a righe `chiave:valore`, lo stesso del `.meta` di NVD, perché il
/// lettore era già scritto in quello stile.
fn read_declared_digest(path: &Path) -> ServiceResult<String> {
    let metadata = std::fs::metadata(path).map_err(|_| ServiceError::KevImportRefused {
        reason: "manca il file di impronta con cui il catalogo era stato acquisito",
    })?;
    if metadata.len() > MAX_DIGEST_FILE_BYTES {
        return Err(ServiceError::KevImportRefused {
            reason: "il file di impronta è oltre la misura ammessa: non è un file di impronta",
        });
    }

    let testo = std::fs::read_to_string(path).map_err(|_| ServiceError::KevImportRefused {
        reason: "il file di impronta non è testo leggibile",
    })?;

    // VINCE LA PRIMA, COME NELLO SCRIPT.
    //
    // Lo script si ferma alla prima riga `sha256:`. Se qui vincesse l'ultima,
    // un file con due impronte supererebbe una verifica e fallirebbe l'altra:
    // due verita' sulla stessa catena, ed e' il genere di divergenza che si
    // scopre in campagna invece che qui.
    let mut sha256 = None;
    for riga in testo.lines() {
        if let Some(valore) = riga.strip_prefix("sha256:") {
            sha256 = Some(valore.trim().to_ascii_lowercase());
            break;
        }
    }

    let Some(sha256) = sha256 else {
        return Err(ServiceError::KevImportRefused {
            reason: "il file di impronta non dichiara alcuna impronta",
        });
    };
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ServiceError::KevImportRefused {
            reason: "l'impronta registrata non ha la forma di un'impronta",
        });
    }

    Ok(sha256)
}

/// Il catalogo, con i soli campi che questo prodotto guarda.
///
/// # Perché una struttura e non un albero JSON generico
///
/// Perché ciò che non è dichiarato qui **non viene nemmeno allocato**, ed è
/// anche una guardia: un campo che non esiste in questa struttura non può finire
/// nell'archivio per distrazione. `requiredAction`, `dueDate` e
/// `forensicTriage` **non esistono qui**.
///
/// # Perché i campi sconosciuti non fanno fallire nulla
///
/// Perché la voce reale del 2026-09-10 porta `forensicTriage`, che lo schema
/// pubblicato — aggiornato il 2024-06-25 — **non dichiara**. La fonte cambia più
/// in fretta del proprio schema, e una guardia che punisse questo punirebbe la
/// cosa sbagliata.
#[derive(serde::Deserialize)]
struct RawCatalogue {
    #[serde(default, rename = "catalogVersion")]
    catalog_version: String,
    #[serde(default, rename = "dateReleased")]
    date_released: String,
    #[serde(default)]
    count: u64,
    #[serde(default)]
    vulnerabilities: Vec<RawEntry>,
}

#[derive(serde::Deserialize)]
struct RawEntry {
    #[serde(default, rename = "cveID")]
    cve_id: String,
    #[serde(default, rename = "vendorProject")]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default, rename = "vulnerabilityName")]
    vulnerability_name: String,
    #[serde(default, rename = "dateAdded")]
    date_added: String,
    #[serde(default, rename = "shortDescription")]
    short_description: String,
    #[serde(default, rename = "knownRansomwareCampaignUse")]
    ransomware_use: String,
}

/// Interpreta il catalogo dai byte **già verificati**, separando ciò che entra
/// da ciò che si omette.
fn read_catalogue(
    bytes: &[u8],
) -> ServiceResult<(KevCatalogIdentity, u64, Vec<KevEntry>, Vec<KevOmission>)> {
    let catalogo: RawCatalogue =
        serde_json::from_slice(bytes).map_err(|_| ServiceError::KevImportRefused {
            reason: "il catalogo KEV non è un file di dati leggibile",
        })?;

    if catalogo.vulnerabilities.len() > MAX_ENTRIES {
        return Err(ServiceError::KevImportRefused {
            reason: "il catalogo dichiara più voci di quante il catalogo KEV ne abbia mai avute",
        });
    }

    // LA COERENZA INTERNA E' L'UNICA INTEGRITA' CHE LA FONTE OFFRE DI SE'.
    //
    // Un file il cui conteggio non corrisponde alle voci presenti e' stato
    // troncato, tagliato o modificato. Non e' un'impronta, e non ne fa le veci:
    // e' cio' che c'e'.
    let presenti = catalogo.vulnerabilities.len() as u64;
    if catalogo.count != presenti {
        return Err(ServiceError::KevImportRefused {
            reason: "il catalogo dichiara un numero di voci diverso da quelle che contiene",
        });
    }

    // UNA FOTOGRAFIA CHE NON SA DIRE DI QUANDO E' NON HA IL CONFINE CHE LE
    // SERVE: il suo esito negativo diventerebbe inesprimibile.
    let Ok(identita) = KevCatalogIdentity::new(&catalogo.catalog_version, &catalogo.date_released)
    else {
        return Err(ServiceError::KevImportRefused {
            reason: "il catalogo non dichiara la propria versione o il proprio rilascio",
        });
    };

    let mut entries = Vec::with_capacity(catalogo.vulnerabilities.len());
    let mut omitted = Vec::new();
    let mut gia_viste: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for voce in catalogo.vulnerabilities {
        let dichiarato = etichetta(&voce.cve_id);

        let Ok(id) = CveId::try_new(&voce.cve_id) else {
            omitted.push(KevOmission {
                declared_id: dichiarato,
                reason: KevOmissionReason::MalformedIdentifier,
            });
            continue;
        };

        // UN IDENTIFICATIVO RIPETUTO E' L'UNICA STRADA PER CUI UNA VOCE
        // POTREBBE SPARIRE IN SILENZIO.
        //
        // La fotografia ha una chiave primaria su (fotografia, identificativo):
        // la seconda riga non puo' entrare. Lasciarla cadere nell'archivio la
        // farebbe sparire senza motivo, ed e' precisamente la regola che questo
        // modulo dichiara.
        if !gia_viste.insert(String::from(id.as_str())) {
            omitted.push(KevOmission {
                declared_id: dichiarato,
                reason: KevOmissionReason::DuplicateIdentifier,
            });
            continue;
        }

        let Ok(uso) = RansomwareUse::try_new(&voce.ransomware_use) else {
            omitted.push(KevOmission {
                declared_id: dichiarato,
                reason: KevOmissionReason::IncompleteEntry,
            });
            continue;
        };

        match KevEntry::new(
            id,
            &voce.vendor_project,
            &voce.product,
            &voce.vulnerability_name,
            &voce.date_added,
            &voce.short_description,
            uso,
        ) {
            Ok(entry) => entries.push(entry),
            Err(lisi_core::DomainError::TooLong { .. }) => omitted.push(KevOmission {
                declared_id: dichiarato,
                reason: KevOmissionReason::FieldTooLong,
            }),
            Err(_) => omitted.push(KevOmission {
                declared_id: dichiarato,
                reason: KevOmissionReason::IncompleteEntry,
            }),
        }
    }

    Ok((identita, catalogo.count, entries, omitted))
}

/// L'identificativo dichiarato, ridotto a un'etichetta d'audit.
///
/// # Perché qui si tronca, mentre altrove no
///
/// Perché **non è un dato che il prodotto conserva**: è il modo di dire quale
/// voce non è entrata. Un identificativo deformato arriva da un file di terze
/// parti e può essere lungo quanto il file; una descrizione di CISA, invece, si
/// conserva intera o non entra, perché quella il prodotto la attribuisce.
fn etichetta(dichiarato: &str) -> String {
    const MAX: usize = 120;
    if dichiarato.chars().count() <= MAX {
        return String::from(dichiarato);
    }
    let ridotto: String = dichiarato.chars().take(MAX).collect();
    format!("{ridotto}… (troncato)")
}

#[cfg(test)]
mod tests {

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("kev_snapshot.rs");
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

    /// **Il servizio non legge l'ordine che KEV rivolge a qualcun altro.**
    ///
    /// Un campo che non esiste nella struttura di lettura non può finire
    /// nell'archivio per distrazione.
    #[test]
    fn il_servizio_non_legge_scadenze_ne_azioni_imposte() {
        for vietato in [
            "requiredAction",
            "required_action",
            "dueDate",
            "due_date",
            "forensicTriage",
            "forensic_triage",
            "cwes",
            "notes",
        ] {
            assert!(
                !codice_di_produzione().contains(vietato),
                "il servizio della fotografia KEV non deve nominare «{vietato}»"
            );
        }
    }

    /// **L'impronta non si racconta come se venisse dalla fonte.**
    ///
    /// CISA non ne pubblica alcuna. Chiamarla «dichiarata dalla fonte», o
    /// battezzare una variabile `source_sha256`, inventerebbe una provenienza
    /// che non esiste — ed è il difetto più facile da introdurre qui, perché il
    /// modulo gemello di NVD quella provenienza ce l'ha davvero.
    #[test]
    fn l_impronta_non_si_spaccia_per_una_provenienza() {
        let codice = codice_di_produzione();
        for vietato in [
            "source_sha256",
            "dichiarata dalla fonte",
            "dichiara CISA",
            "impronta di CISA",
        ] {
            assert!(
                !codice.contains(vietato),
                "il servizio della fotografia KEV non deve dire «{vietato}»: \
                 l'impronta l'abbiamo calcolata noi, e chiamarla altrimenti \
                 inventerebbe una provenienza"
            );
        }
        assert!(
            codice.contains("ACQUIRED_DIGEST_FILE"),
            "il nome del file di impronta deve dire che è acquisita, non dichiarata"
        );
    }

    /// **Il servizio non decomprime e non conosce archivi.**
    ///
    /// Il catalogo KEV è un JSON semplice: non c'è nulla da estrarre, e il
    /// prodotto non acquisisce una libreria per aprire un archivio.
    #[test]
    fn il_servizio_non_decomprime() {
        for vietato in ["ZipArchive", "GzDecoder", "flate2", "zip::"] {
            assert!(
                !codice_di_produzione().contains(vietato),
                "il servizio della fotografia KEV non deve nominare «{vietato}»"
            );
        }
    }
}

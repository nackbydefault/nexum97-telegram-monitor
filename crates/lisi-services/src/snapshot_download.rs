//! Le fotografie CVE, KEV e ATT&CK scaricate su comando dalle fonti fissate
//! (SNAP-NET-01, ADR-0186).
//!
//! # Si scarica nella forma degli script, e si importa come oggi
//!
//! Le destinazioni sono quelle dei file di blocco compilati nel programma
//! (`attack.lock.json`, `kev.lock.json`, `cve.lock.json`): non si scrivono in
//! un campo e non si configurano (decisione 1). I file scendono in una
//! cartella del solo utente, nella stessa forma che producono gli script
//! `scripts/fetch-*.ps1`, e li importano i servizi di sempre, che verificano
//! ciò che verificavano (decisione 3). La cartella si toglie dopo.
//!
//! # La decompressione sta qui
//!
//! NVD pubblica ogni anno anche come `.json.gz`. Il gzip si decomprime qui, su
//! file, entro la misura che il `.meta` dichiara e mai oltre il tetto di un
//! anno; l'impronta la riconfronta l'importazione con quella del `.meta`. Il
//! servizio della fotografia CVE continua a non decomprimere (decisione 4).
//! Gli archivi `zip` non si leggono (ADR-0180).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use lisi_core::Sha256Digest;
use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_platform::https::{self, BodyLimit, Downloaded, Fetched};
use lisi_storage::Database;

use crate::attack_snapshot::{AttackImportOutcome, AttackSnapshotService};
use crate::cve_snapshot::{CVE_ATTRIBUTION, CveImportOutcome, CveSnapshotService};
use crate::error::{ServiceError, ServiceResult};
use crate::kev_snapshot::{
    ACQUIRED_DIGEST_FILE, CATALOGUE_FILE, KevImportOutcome, KevSnapshotService,
};
use crate::protected_output::ProtectedFolder;

/// I file di blocco, compilati nel programma: le sole destinazioni.
const ATTACK_LOCK: &str = include_str!("../../../attack.lock.json");
const KEV_LOCK: &str = include_str!("../../../kev.lock.json");
const CVE_LOCK: &str = include_str!("../../../cve.lock.json");

/// Il tetto di un anno NVD decompresso.
const MAX_YEAR_BYTES: u64 = 1024 * 1024 * 1024;

/// Una lettura della rete in memoria: in produzione [`https::fetch_within`].
pub(crate) type Reader = fn(&str, BodyLimit) -> Fetched;

/// Uno scaricamento su disco: in produzione [`https::fetch_to_file`].
pub(crate) type FileReader = fn(&str, &Path, u64) -> Downloaded;

/// Le tre fonti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSource {
    /// MITRE ATT&CK, il pacchetto fissato.
    Attack,
    /// Il catalogo KEV di CISA.
    Kev,
    /// Gli anni NVD di `cve.lock.json`.
    Cve,
}

impl SnapshotSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Attack => "attack",
            Self::Kev => "kev",
            Self::Cve => "cve",
        }
    }
}

/// Il servizio che scarica e importa.
pub struct SnapshotDownloadService<'a> {
    database: &'a mut Database,
    read: Reader,
    read_file: FileReader,
    /// Dove scendono i file: la cartella dei dati, o quella di una prova.
    root: Option<PathBuf>,
}

impl<'a> SnapshotDownloadService<'a> {
    /// Costruisce il servizio sull'archivio, con la rete di Windows.
    #[must_use]
    pub fn new(database: &'a mut Database) -> Self {
        Self {
            database,
            read: https::fetch_within,
            read_file: https::fetch_to_file,
            root: None,
        }
    }

    /// Costruisce il servizio con letture che dicono l'esito che serve.
    #[cfg(test)]
    pub(crate) fn with(
        database: &'a mut Database,
        read: Reader,
        read_file: FileReader,
        root: PathBuf,
    ) -> Self {
        Self {
            database,
            read,
            read_file,
            root: Some(root),
        }
    }

    /// Scarica e importa il pacchetto ATT&CK fissato, con il testo della sua
    /// licenza (decisione 5).
    ///
    /// # Errori
    ///
    /// [`ServiceError::SnapshotDownloadRefused`] se qualcosa non arriva o non
    /// corrisponde; gli errori dell'importazione.
    pub fn download_attack(
        &mut self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<AttackImportOutcome> {
        let lock = Lock::of(ATTACK_LOCK)?;
        let pacchetto = lock.file("/fotografia")?;
        let licenza = lock.file("/licenza")?;
        let pinned = crate::attack_snapshot::pinned()?;
        let cartella = self.staging(SnapshotSource::Attack, now)?;
        let (percorso_pacchetto, percorso_licenza) = pinned.paths_in(&cartella);
        let esito = self
            .scarica_su_file(
                SnapshotSource::Attack,
                &pacchetto,
                &percorso_pacchetto,
                actor,
                now,
            )
            .and_then(|()| {
                self.scarica_su_file(
                    SnapshotSource::Attack,
                    &licenza,
                    &percorso_licenza,
                    actor,
                    now,
                )
            })
            .and_then(|()| {
                AttackSnapshotService::new(self.database).import(
                    &percorso_pacchetto,
                    &percorso_licenza,
                    &pinned.sha256,
                    actor,
                    now,
                )
            });
        clean(&cartella);
        esito
    }

    /// Scarica e importa il catalogo KEV di CISA.
    ///
    /// # Errori
    ///
    /// Come [`Self::download_attack`].
    pub fn download_kev(
        &mut self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<KevImportOutcome> {
        let lock = Lock::of(KEV_LOCK)?;
        let indirizzo = lock.text("/fonte/catalogo_url")?;
        let byte = self.in_memory(
            SnapshotSource::Kev,
            &indirizzo,
            BodyLimit::Catalogue,
            actor,
            now,
        )?;
        let cartella = self.staging(SnapshotSource::Kev, now)?;
        let esito = self.kev_into(&cartella, &byte, actor, now);
        clean(&cartella);
        esito
    }

    fn kev_into(
        &mut self,
        cartella: &Path,
        byte: &[u8],
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<KevImportOutcome> {
        {
            write(&cartella.join(CATALOGUE_FILE), byte)?;
            // L'impronta la calcola NEXUM, e il file lo dice: CISA non ne
            // pubblica una (ADR-0061, ADR-0186, rischio residuo).
            const CHI: &str = "# Impronta calcolata da NEXUM/97 allo scaricamento, non da CISA.";
            const CAMPO: &str = "sha256:";
            let impronta = format!("{CHI}\n{CAMPO}{}\n", Sha256Digest::of_bytes(byte).as_str());
            write(&cartella.join(ACQUIRED_DIGEST_FILE), impronta.as_bytes())?;
            KevSnapshotService::new(self.database).import(cartella, actor, now)
        }
    }

    /// Scarica e importa gli anni NVD di `cve.lock.json`.
    ///
    /// # Errori
    ///
    /// Come [`Self::download_attack`].
    pub fn download_cve(
        &mut self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<CveImportOutcome> {
        let lock = Lock::of(CVE_LOCK)?;
        let base = lock.text("/fonte/base_url")?;
        let anni = lock.years("/copertura/anni")?;
        let cartella = self.staging(SnapshotSource::Cve, now)?;
        let esito = self.cve_into(&cartella, &base, &anni, actor, now);
        clean(&cartella);
        esito
    }

    fn cve_into(
        &mut self,
        cartella: &Path,
        base: &str,
        anni: &[i32],
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<CveImportOutcome> {
        {
            for anno in anni {
                let meta_url = format!("{base}/nvdcve-2.0-{anno}.meta");
                let meta =
                    self.in_memory(SnapshotSource::Cve, &meta_url, BodyLimit::Small, actor, now)?;
                let dichiarato = DeclaredYear::of(&meta)?;
                write(&cartella.join(format!("nvdcve-2.0-{anno}.meta")), &meta)?;
                let compresso = cartella.join(format!("nvdcve-2.0-{anno}.json.gz"));
                let gz = LockedFile {
                    url: format!("{base}/nvdcve-2.0-{anno}.json.gz"),
                    bytes: dichiarato.gz_bytes,
                    sha256: None,
                };
                self.scarica_su_file(SnapshotSource::Cve, &gz, &compresso, actor, now)?;
                decompress_capped(
                    &compresso,
                    &cartella.join(format!("nvdcve-2.0-{anno}.json")),
                    dichiarato.bytes,
                )?;
                let _ = std::fs::remove_file(&compresso);
            }
            CveSnapshotService::new(self.database).import(
                cartella,
                anni,
                CVE_ATTRIBUTION,
                actor,
                now,
            )
        }
    }

    /// La cartella del solo utente in cui scendono i file.
    fn staging(&self, fonte: SnapshotSource, now: Timestamp) -> ServiceResult<PathBuf> {
        let radice = match &self.root {
            Some(radice) => radice.clone(),
            None => crate::data_directory::application_directory()?.join("fotografie-scaricate"),
        };
        std::fs::create_dir_all(&radice)
            .map_err(|_| rifiuto("la cartella dei file scaricati non si crea"))?;
        let cartella = radice.join(format!("{}-{}", fonte.as_str(), now.as_millis()));
        let protetta = ProtectedFolder::create(&cartella, "i file scaricati", |_| {
            rifiuto("la cartella dei file scaricati non si crea")
        })?;
        // Ristretta al solo utente (SEC-01): da qui la cartella si usa per
        // percorso, e si toglie con `clean`.
        let percorso = protetta.path().to_path_buf();
        protetta.release();
        Ok(percorso)
    }

    /// Una lettura in memoria, con la sua riga d'audit.
    fn in_memory(
        &mut self,
        fonte: SnapshotSource,
        indirizzo: &str,
        limite: BodyLimit,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<Vec<u8>> {
        let esito = (self.read)(indirizzo, limite);
        let dettaglio = match &esito {
            Fetched::Body(byte) => format!("{}: scaricati {} byte", fonte.as_str(), byte.len()),
            Fetched::Refused(motivo) => format!("{}: non scaricato: {motivo}", fonte.as_str()),
        };
        self.audit(&dettaglio, actor, now)?;
        match esito {
            Fetched::Body(byte) => Ok(byte),
            Fetched::Refused(motivo) => Err(ServiceError::SnapshotDownloadRefused {
                reason: motivo.to_string(),
            }),
        }
    }

    /// Uno scaricamento su disco della misura dichiarata, con la sua riga
    /// d'audit; l'impronta, se il blocco la fissa, si confronta qui.
    fn scarica_su_file(
        &mut self,
        fonte: SnapshotSource,
        voce: &LockedFile,
        percorso: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if let Some(cartella) = percorso.parent() {
            std::fs::create_dir_all(cartella)
                .map_err(|_| rifiuto("la cartella dei file scaricati non si crea"))?;
        }
        let esito = (self.read_file)(&voce.url, percorso, voce.bytes);
        let dettaglio = match &esito {
            Downloaded::Saved { bytes } => format!("{}: scaricati {bytes} byte", fonte.as_str()),
            Downloaded::Refused(motivo) => format!("{}: non scaricato: {motivo}", fonte.as_str()),
        };
        self.audit(&dettaglio, actor, now)?;
        if let Downloaded::Refused(motivo) = esito {
            return Err(ServiceError::SnapshotDownloadRefused {
                reason: motivo.to_string(),
            });
        }
        if let Some(atteso) = &voce.sha256 {
            let file = std::fs::File::open(percorso)
                .map_err(|_| rifiuto("il file scaricato non si apre"))?;
            let trovato = Sha256Digest::of_reader(std::io::BufReader::new(file))
                .map_err(|_| rifiuto("il file scaricato non si legge"))?;
            if trovato.as_str() != atteso {
                let _ = std::fs::remove_file(percorso);
                return Err(rifiuto(
                    "il file scaricato non ha l'impronta fissata nel programma, e non si tiene",
                ));
            }
        }
        Ok(())
    }

    fn audit(&mut self, dettaglio: &str, actor: &Actor, now: Timestamp) -> ServiceResult<()> {
        // L'indirizzo non entra: si legge nel file di blocco.
        let dettaglio: String = dettaglio.chars().take(240).collect();
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("fotografia_scaricata")?,
            entity: AuditEntity::try_new("fotografia")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

fn rifiuto(motivo: &str) -> ServiceError {
    ServiceError::SnapshotDownloadRefused {
        reason: motivo.to_owned(),
    }
}

fn write(percorso: &Path, byte: &[u8]) -> ServiceResult<()> {
    std::fs::write(percorso, byte).map_err(|_| rifiuto("un file scaricato non si scrive"))
}

/// Toglie i file scaricati e la loro cartella.
fn clean(cartella: &Path) {
    if let Err(errore) = std::fs::remove_dir_all(cartella) {
        tracing::warn!(%errore, "cartella dei file scaricati non tolta");
    }
}

/// Un file fissato in un blocco: dove, quanto, e l'impronta se c'è.
struct LockedFile {
    url: String,
    bytes: u64,
    sha256: Option<String>,
}

/// Un file di blocco letto.
struct Lock(serde_json::Value);

impl Lock {
    fn of(testo: &str) -> ServiceResult<Self> {
        serde_json::from_str(testo)
            .map(Self)
            .map_err(|_| rifiuto("un file di blocco incorporato non si legge"))
    }

    fn text(&self, puntatore: &str) -> ServiceResult<String> {
        self.0
            .pointer(puntatore)
            .and_then(serde_json::Value::as_str)
            .map(String::from)
            .ok_or_else(|| rifiuto("un file di blocco incorporato non ha la forma attesa"))
    }

    fn file(&self, voce: &str) -> ServiceResult<LockedFile> {
        let byte = self
            .0
            .pointer(&format!("{voce}/byte"))
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| rifiuto("un file di blocco incorporato non ha la forma attesa"))?;
        Ok(LockedFile {
            url: self.text(&format!("{voce}/origine"))?,
            bytes: byte,
            sha256: Some(self.text(&format!("{voce}/sha256"))?),
        })
    }

    fn years(&self, puntatore: &str) -> ServiceResult<Vec<i32>> {
        self.0
            .pointer(puntatore)
            .and_then(serde_json::Value::as_array)
            .map(|anni| {
                anni.iter()
                    .filter_map(serde_json::Value::as_i64)
                    .filter_map(|anno| i32::try_from(anno).ok())
                    .collect::<Vec<_>>()
            })
            .filter(|anni| !anni.is_empty())
            .ok_or_else(|| rifiuto("un file di blocco incorporato non ha la forma attesa"))
    }
}

/// Ciò che il `.meta` di un anno dichiara sulle misure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeclaredYear {
    /// I byte del file decompresso.
    bytes: u64,
    /// I byte del `.json.gz`.
    gz_bytes: u64,
}

impl DeclaredYear {
    fn of(meta: &[u8]) -> ServiceResult<Self> {
        let testo =
            std::str::from_utf8(meta).map_err(|_| rifiuto("il .meta di NVD non è testo"))?;
        let campo = |nome: &str| {
            testo
                .lines()
                .find_map(|riga| riga.strip_prefix(nome))
                .and_then(|valore| valore.trim().parse::<u64>().ok())
        };
        let (Some(bytes), Some(gz_bytes)) = (campo("size:"), campo("gzSize:")) else {
            return Err(rifiuto("il .meta di NVD non dichiara le misure del file"));
        };
        if bytes == 0 || bytes > MAX_YEAR_BYTES || gz_bytes == 0 || gz_bytes > bytes {
            return Err(rifiuto("il .meta di NVD dichiara misure fuori dal tetto"));
        }
        Ok(Self { bytes, gz_bytes })
    }
}

/// Decomprime un `.gz` su file, fermandosi oltre i byte dichiarati: un file
/// che ne produce di più, o di meno, non si tiene.
fn decompress_capped(da: &Path, a: &Path, dichiarati: u64) -> ServiceResult<()> {
    let ingresso = std::fs::File::open(da).map_err(|_| rifiuto("il file compresso non si apre"))?;
    let mut lettore =
        flate2::read::GzDecoder::new(std::io::BufReader::new(ingresso)).take(dichiarati + 1);
    let mut uscita =
        std::fs::File::create(a).map_err(|_| rifiuto("il file decompresso non si crea"))?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut scritti = 0_u64;
    loop {
        let letti = lettore
            .read(&mut buffer)
            .map_err(|_| rifiuto("il file compresso non si legge"))?;
        if letti == 0 {
            break;
        }
        scritti += letti as u64;
        if scritti > dichiarati {
            drop(uscita);
            let _ = std::fs::remove_file(a);
            return Err(rifiuto(
                "il file decompresso supera la misura dichiarata, e non si tiene",
            ));
        }
        uscita
            .write_all(&buffer[..letti])
            .map_err(|_| rifiuto("il file decompresso non si scrive"))?;
    }
    if scritti != dichiarati {
        drop(uscita);
        let _ = std::fs::remove_file(a);
        return Err(rifiuto(
            "il file decompresso non ha la misura dichiarata, e non si tiene",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{ATTACK_LOCK, CVE_LOCK, DeclaredYear, KEV_LOCK, Lock, decompress_capped};

    fn gz(contenuto: &[u8]) -> Vec<u8> {
        let mut codificatore =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let Ok(()) = codificatore.write_all(contenuto) else {
            panic!("si comprime");
        };
        let Ok(byte) = codificatore.finish() else {
            panic!("si comprime");
        };
        byte
    }

    /// **Le destinazioni sono i blocchi compilati** (ADR-0186, decisione 1):
    /// si leggono, e sono indirizzi `https` delle fonti ufficiali.
    #[test]
    fn le_destinazioni_sono_i_blocchi_compilati() {
        let (Ok(attack), Ok(kev), Ok(cve)) = (
            Lock::of(ATTACK_LOCK),
            Lock::of(KEV_LOCK),
            Lock::of(CVE_LOCK),
        ) else {
            panic!("i blocchi si leggono");
        };
        let (Ok(pacchetto), Ok(licenza)) = (attack.file("/fotografia"), attack.file("/licenza"))
        else {
            panic!("il pacchetto e la licenza sono fissati");
        };
        assert!(
            pacchetto
                .url
                .starts_with("https://raw.githubusercontent.com/mitre-attack/")
        );
        assert!(
            licenza
                .url
                .starts_with("https://raw.githubusercontent.com/mitre-attack/")
        );
        assert!(pacchetto.sha256.is_some() && pacchetto.bytes > 0);
        assert_eq!(
            kev.text("/fonte/catalogo_url").ok().as_deref(),
            Some(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
        );
        assert_eq!(
            cve.text("/fonte/base_url").ok().as_deref(),
            Some("https://nvd.nist.gov/feeds/json/cve/2.0")
        );
        assert!(
            cve.years("/copertura/anni")
                .is_ok_and(|anni| !anni.is_empty())
        );
    }

    /// **Il `.meta` dichiara le misure, e fuori dal tetto si rifiuta.**
    #[test]
    fn il_meta_dichiara_le_misure() {
        let meta = b"lastModifiedDate:2026-11-06T03:00:01-05:00\r\nsize:700000\r\nzipSize:70000\r\ngzSize:69000\r\nsha256:ABCD\r\n";
        assert_eq!(
            DeclaredYear::of(meta).ok(),
            Some(DeclaredYear {
                bytes: 700_000,
                gz_bytes: 69_000
            })
        );
        for sbagliato in [
            &b"size:10\ngzSize:20\n"[..],
            b"size:0\ngzSize:0\n",
            b"gzSize:10\n",
            b"size:99999999999\ngzSize:10\n",
        ] {
            assert!(DeclaredYear::of(sbagliato).is_err());
        }
    }

    /// **Un gzip che produce più o meno di quanto dichiarato non si tiene**
    /// (decisione 4): il tetto ferma una bomba di decompressione prima che
    /// scriva oltre la misura.
    #[test]
    fn un_gzip_fuori_misura_non_si_tiene() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella");
        };
        let compresso = cartella.path().join("anno.json.gz");
        let decompresso = cartella.path().join("anno.json");
        let contenuto = vec![b'a'; 100_000];
        let Ok(()) = std::fs::write(&compresso, gz(&contenuto)) else {
            panic!("si scrive");
        };
        assert!(decompress_capped(&compresso, &decompresso, 100_000).is_ok());
        assert_eq!(
            std::fs::read(&decompresso).ok().map(|byte| byte.len()),
            Some(100_000)
        );

        assert!(
            decompress_capped(&compresso, &decompresso, 1_000).is_err(),
            "più del dichiarato"
        );
        assert!(!decompresso.exists(), "il file oltre misura non resta");
        assert!(
            decompress_capped(&compresso, &decompresso, 200_000).is_err(),
            "meno del dichiarato"
        );
        assert!(!decompresso.exists());
    }

    fn archivio() -> lisi_storage::Database {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        database
    }

    fn persona() -> lisi_core::text::Actor {
        let Ok(attore) = lisi_core::text::Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn adesso() -> lisi_core::Timestamp {
        lisi_core::Timestamp::from_millis(1_762_400_000_000)
    }

    fn rifiutata(_: &str, _: lisi_platform::https::BodyLimit) -> lisi_platform::https::Fetched {
        lisi_platform::https::Fetched::Refused(lisi_platform::https::FetchRefusal::Unreachable {
            code: 12007,
        })
    }

    fn file_rifiutato(_: &str, _: &std::path::Path, _: u64) -> lisi_platform::https::Downloaded {
        lisi_platform::https::Downloaded::Refused(lisi_platform::https::FetchRefusal::Unreachable {
            code: 12007,
        })
    }

    /// Scrive byte che non sono il pacchetto fissato.
    fn file_sbagliato(
        _: &str,
        percorso: &std::path::Path,
        attesi: u64,
    ) -> lisi_platform::https::Downloaded {
        let Ok(()) = std::fs::write(percorso, vec![b'x'; usize::try_from(attesi).unwrap_or(0)])
        else {
            panic!("si scrive");
        };
        lisi_platform::https::Downloaded::Saved { bytes: attesi }
    }

    fn righe_d_audit(database: &lisi_storage::Database) -> usize {
        database
            .audit_entries()
            .map(|righe| {
                righe
                    .iter()
                    .filter(|riga| riga.action.as_str() == "fotografia_scaricata")
                    .count()
            })
            .unwrap_or_default()
    }

    /// **Una fonte che non risponde lascia una riga d'audit e nessuna
    /// fotografia** (ADR-0186, decisione 2): il rifiuto si dice, e niente si
    /// importa.
    #[test]
    fn una_fonte_che_non_risponde_lascia_l_audit_e_nessuna_fotografia() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella");
        };
        let mut database = archivio();
        {
            let mut servizio = super::SnapshotDownloadService::with(
                &mut database,
                rifiutata,
                file_rifiutato,
                cartella.path().to_path_buf(),
            );
            assert!(matches!(
                servizio.download_kev(&persona(), adesso()),
                Err(crate::error::ServiceError::SnapshotDownloadRefused { .. })
            ));
            assert!(servizio.download_cve(&persona(), adesso()).is_err());
            assert!(servizio.download_attack(&persona(), adesso()).is_err());
        }
        assert_eq!(
            righe_d_audit(&database),
            3,
            "ogni passaggio in rete si scrive"
        );
        assert_eq!(database.attack_snapshots().ok().map(|f| f.len()), Some(0));
    }

    /// **Un pacchetto ATT&CK che non ha l'impronta fissata non si tiene**
    /// (ADR-0186, decisione 5): la cartella dei file scaricati si toglie.
    #[test]
    fn un_pacchetto_attack_diverso_non_si_tiene() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella");
        };
        let mut database = archivio();
        {
            let mut servizio = super::SnapshotDownloadService::with(
                &mut database,
                rifiutata,
                file_sbagliato,
                cartella.path().to_path_buf(),
            );
            let Err(errore) = servizio.download_attack(&persona(), adesso()) else {
                panic!("un pacchetto diverso si rifiuta");
            };
            assert!(
                errore.operator_message().contains("impronta"),
                "{}",
                errore.operator_message()
            );
        }
        assert_eq!(database.attack_snapshots().ok().map(|f| f.len()), Some(0));
        let rimasti = std::fs::read_dir(cartella.path())
            .map(Iterator::count)
            .unwrap_or(0);
        assert_eq!(rimasti, 0, "i file scaricati non restano");
    }
}

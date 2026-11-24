//! Il catalogo CISA KEV, in archivio.
//!
//! # La domanda per cui queste tabelle esistono
//!
//! «CISA elenca questo identificativo fra le vulnerabilità sfruttate note»,
//! chiesto **offline** di un `CVE-…` comparso in un contenuto monitorato.
//!
//! E la risposta ha **due esiti asimmetrici**: *elencata* afferma — per bocca di
//! CISA — *non elencata* **non sa**. Non esistono tre esiti come per le CVE,
//! perché le due assenze non sono distinguibili dal dato, e inventare una
//! distinzione che il dato non contiene sarebbe peggio che averne due
//! (ADR-0061).
//!
//! # Che cosa non si fa, mai
//!
//! Non si contatta nulla. Il file arriva da `scripts/fetch-kev.ps1`.

use lisi_core::model::cve::CveId;
use lisi_core::model::kev::{KevCatalogIdentity, KevEntry, KevResolution, RansomwareUse};
use lisi_core::text::Actor;
use lisi_core::{KevSnapshotId, Timestamp};

use crate::Database;
use crate::error::{StorageError, StorageResult};

/// Una fotografia del catalogo come sta in archivio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKevSnapshot {
    /// Identificatore di riga.
    pub id: KevSnapshotId,
    /// L'identità del catalogo: versione e istante di rilascio.
    pub catalog: KevCatalogIdentity,
    /// Quante voci il catalogo **dichiara** di avere.
    pub declared_count: u64,
    /// Quante voci sono state accettate quando la fotografia è stata scritta.
    ///
    /// **Non è un conteggio che si ricalcola**: è ciò che era vero nella
    /// transazione che ha creato la fotografia, ed è il metro con cui la
    /// completezza si verifica.
    pub expected_entries: u64,
    /// Quante voci sono state lasciate fuori, ciascuna con il proprio motivo.
    pub omitted_count: u64,
    /// L'impronta di ciò che è stato acquisito.
    ///
    /// **Non viene dalla fonte.** CISA non ne pubblica alcuna: l'ha calcolata
    /// `scripts/fetch-kev.ps1` al momento dell'acquisizione, e dice che il file
    /// non è cambiato da allora.
    pub acquired_sha256: String,
    /// La fonte, registrata perché la frase possa nominare chi afferma.
    pub attribution: String,
    /// Chi l'ha importata.
    pub imported_by: Actor,
    /// Quando.
    pub imported_at: Timestamp,
    /// Quante voci contiene davvero.
    pub entry_count: u64,
}

/// Una fotografia da registrare, con tutto ciò che la compone.
///
/// # Perché è una struttura e non otto argomenti
///
/// Perché una fotografia si scrive **intera o per niente**, e otto argomenti in
/// fila si scambiano di posto in silenzio: due `u64` accanto — quanti ne
/// dichiara il catalogo e quanti ne sono stati omessi — sarebbero scambiabili
/// senza che nulla se ne accorga, e produrrebbero una fotografia che mente sulla
/// propria completezza.
pub struct NewKevSnapshot<'a> {
    /// L'identità del catalogo: versione e istante di rilascio.
    pub catalog: &'a KevCatalogIdentity,
    /// Quante voci il catalogo **dichiara** di avere.
    pub declared_count: u64,
    /// Quante voci sono state lasciate fuori, ciascuna con il proprio motivo.
    pub omitted_count: u64,
    /// L'impronta di ciò che è stato acquisito — **calcolata da noi**.
    pub acquired_sha256: &'a str,
    /// La fonte, registrata perché la frase possa nominare chi afferma.
    pub attribution: &'a str,
    /// Le voci accettate, tutte.
    pub entries: &'a [KevEntry],
    /// Chi la importa.
    pub imported_by: &'a Actor,
    /// Quando.
    pub imported_at: Timestamp,
}

impl Database {
    /// Registra una fotografia **intera**: la riga e tutte le sue voci.
    ///
    /// # Perché tutto in una transazione sola, e non a blocchi
    ///
    /// Perché una fotografia **parziale non deve poter esistere**, e una volta
    /// scritta non si potrebbe più correggere: i trigger la rendono immutabile e
    /// incancellabile. Una riga senza le proprie voci risponderebbe «non
    /// elencata» a una domanda a cui CISA risponde di sì — ed è l'unica risposta
    /// che questa fotografia non deve mai sbagliare.
    ///
    /// La fotografia CVE scrive a blocchi perché ha più di centomila voci e
    /// tenerle in memoria costerebbe centinaia di megabyte. **Il catalogo KEV ne
    /// ha millesettecento**: qui quel compromesso non serve, e pagarlo
    /// significherebbe accettare un rischio in cambio di nulla.
    ///
    /// I conteggi si scrivono con le voci, nella stessa transazione, e non si
    /// aggiornano mai: `expected_entries + omitted_count = declared_count` è un
    /// `CHECK` dello schema.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce o se i conteggi non
    /// tornano — nel qual caso **non viene scritto nulla**.
    pub fn record_kev_snapshot(
        &mut self,
        snapshot: &NewKevSnapshot<'_>,
    ) -> StorageResult<KevSnapshotId> {
        let transaction = self.connection.transaction()?;

        let id: i64 = transaction.query_row(
            "INSERT INTO kev_snapshots (
                 catalog_version, date_released, declared_count, expected_entries,
                 omitted_count, acquired_sha256, attribution, imported_by, imported_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             RETURNING id",
            rusqlite::params![
                snapshot.catalog.version(),
                snapshot.catalog.released_at(),
                i64::try_from(snapshot.declared_count).unwrap_or(i64::MAX),
                i64::try_from(snapshot.entries.len()).unwrap_or(i64::MAX),
                i64::try_from(snapshot.omitted_count).unwrap_or(i64::MAX),
                snapshot.acquired_sha256,
                snapshot.attribution,
                snapshot.imported_by.as_str(),
                snapshot.imported_at.as_millis(),
            ],
            |row| row.get(0),
        )?;

        {
            // NIENTE `OR IGNORE`: una voce che non entra deve FARLO SAPERE.
            //
            // Un identificativo ripetuto e' l'unica strada per cui una voce
            // potrebbe sparire in silenzio, ed e' precisamente la regola che
            // questo modulo dichiara. I duplicati li riconosce e li omette il
            // servizio, con il proprio motivo; se uno arrivasse fin qui, questa
            // scrittura fallisce e la transazione non lascia nulla.
            let mut statement = transaction.prepare(
                "INSERT INTO kev_entries (
                     snapshot_id, cve_id, vendor_project, product, vulnerability_name,
                     date_added, short_description, ransomware_use
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for entry in snapshot.entries {
                statement.execute(rusqlite::params![
                    id,
                    entry.cve_id().as_str(),
                    entry.vendor_project(),
                    entry.product(),
                    entry.vulnerability_name(),
                    entry.date_added(),
                    entry.short_description(),
                    entry.ransomware_use().as_str(),
                ])?;
            }
        }

        transaction.commit()?;
        Ok(KevSnapshotId::new(id))
    }

    /// Le fotografie del catalogo in archivio, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è più
    /// interpretabile.
    pub fn kev_snapshots(&self) -> StorageResult<Vec<StoredKevSnapshot>> {
        let mut statement = self.connection.prepare(
            "SELECT id, catalog_version, date_released, declared_count, expected_entries,
                    omitted_count, acquired_sha256, attribution, imported_by, imported_at
             FROM kev_snapshots
             ORDER BY imported_at DESC, id DESC",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, i64>(9)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (
                id,
                catalog_version,
                date_released,
                declared_count,
                expected_entries,
                omitted_count,
                acquired_sha256,
                attribution,
                imported_by,
                imported_at,
            ) = riga?;

            let Ok(imported_by) = Actor::try_new(&imported_by) else {
                return Err(StorageError::CorruptedRow {
                    detail: "operatore della fotografia KEV non interpretabile",
                });
            };
            let Ok(catalog) = KevCatalogIdentity::new(&catalog_version, &date_released) else {
                return Err(StorageError::CorruptedRow {
                    detail: "una fotografia KEV senza identità non è interpretabile",
                });
            };

            let id = KevSnapshotId::new(id);
            trovate.push(StoredKevSnapshot {
                id,
                catalog,
                declared_count: u64::try_from(declared_count).unwrap_or(0),
                expected_entries: u64::try_from(expected_entries).unwrap_or(0),
                omitted_count: u64::try_from(omitted_count).unwrap_or(0),
                acquired_sha256,
                attribution,
                imported_by,
                imported_at: Timestamp::from_millis(imported_at),
                entry_count: self.kev_entry_count(id)?,
            });
        }
        Ok(trovate)
    }

    /// Quante voci contiene una fotografia.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn kev_entry_count(&self, snapshot_id: KevSnapshotId) -> StorageResult<u64> {
        let quante: i64 = self.connection.query_row(
            "SELECT count(*) FROM kev_entries WHERE snapshot_id = ?1",
            rusqlite::params![snapshot_id.get()],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(quante).unwrap_or(0))
    }

    /// Risolve un identificativo dentro una fotografia del catalogo.
    ///
    /// # Perché l'identità del catalogo si legge sempre
    ///
    /// Perché l'esito negativo **non è raccontabile senza**: «non elencata» da
    /// solo si legge come «non sfruttata», e l'unica cosa che delimita
    /// quell'assenza è il momento in cui il catalogo è stato rilasciato.
    ///
    /// # Perché l'esito negativo si rifiuta di uscire da una fotografia
    /// incompleta
    ///
    /// Perché è **l'unica risposta che questa fotografia non deve mai
    /// sbagliare**. Una fotografia a cui mancassero le voci risponderebbe «non
    /// elencata» a una domanda a cui CISA risponde di sì, e lo farebbe con la
    /// stessa faccia dell'esito giusto.
    ///
    /// [`Self::record_kev_snapshot`] scrive riga e voci **in una transazione
    /// sola**, perciò questo stato non dovrebbe esistere. La verifica è la
    /// seconda difesa, per un archivio danneggiato o toccato da fuori, e si paga
    /// **solo sul ramo negativo**: chi trova la voce non conta nulla.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, se la fotografia non è in
    /// archivio, se una riga non è più interpretabile, o se la fotografia non
    /// contiene le voci che dichiara.
    pub fn resolve_kev(
        &self,
        snapshot_id: KevSnapshotId,
        id: &CveId,
    ) -> StorageResult<KevResolution> {
        let identita: Option<(String, String, i64)> = self
            .connection
            .query_row(
                "SELECT catalog_version, date_released, expected_entries
                 FROM kev_snapshots WHERE id = ?1",
                rusqlite::params![snapshot_id.get()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;

        let Some((catalog_version, date_released, expected_entries)) = identita else {
            return Err(StorageError::NotFound {
                entity: "fotografia_kev",
                id: snapshot_id.get(),
            });
        };
        let Ok(catalog) = KevCatalogIdentity::new(&catalog_version, &date_released) else {
            return Err(StorageError::CorruptedRow {
                detail: "una fotografia KEV senza identità non è interpretabile",
            });
        };

        let trovata = self
            .connection
            .query_row(
                "SELECT vendor_project, product, vulnerability_name, date_added,
                        short_description, ransomware_use
                 FROM kev_entries
                 WHERE snapshot_id = ?1 AND cve_id = ?2",
                rusqlite::params![snapshot_id.get(), id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            short_description,
            ransomware_use,
        )) = trovata
        else {
            // SOLO QUI SI CONTA, e solo perche' si sta per dire «non elencata».
            let presenti = self.kev_entry_count(snapshot_id)?;
            if presenti != u64::try_from(expected_entries).unwrap_or(u64::MAX) {
                return Err(StorageError::CorruptedRow {
                    detail: "una fotografia KEV incompleta non può rispondere «non elencata»",
                });
            }
            return Ok(KevResolution::NotListed { catalog });
        };

        let (Ok(ransomware_use), Ok(entry_id)) = (
            RansomwareUse::try_new(&ransomware_use),
            CveId::try_new(id.as_str()),
        ) else {
            return Err(StorageError::CorruptedRow {
                detail: "voce di una fotografia KEV non interpretabile",
            });
        };

        let Ok(entry) = KevEntry::new(
            entry_id,
            &vendor_project,
            &product,
            &vulnerability_name,
            &date_added,
            &short_description,
            ransomware_use,
        ) else {
            return Err(StorageError::CorruptedRow {
                detail: "voce di una fotografia KEV non ricomponibile",
            });
        };

        Ok(KevResolution::Listed(Box::new(entry)))
    }
}

use rusqlite::OptionalExtension as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::database;

    const IMPRONTA: &str = "5d41402abc4b2a76b9719d911017c592f1a2b3c4d5e6f708192a3b4c5d6e7f80";

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn identificativo(raw: &str) -> CveId {
        let Ok(id) = CveId::try_new(raw) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        id
    }

    fn catalogo() -> KevCatalogIdentity {
        let Ok(identita) = KevCatalogIdentity::new("2026.09.10", "2026-09-10T19:00:05.1949Z")
        else {
            panic!("l'identità di prova deve essere valida");
        };
        identita
    }

    fn voce(id: &str, dichiarazione: &str) -> KevEntry {
        let Ok(uso) = RansomwareUse::try_new(dichiarazione) else {
            panic!("la dichiarazione di prova deve essere valida");
        };
        let Ok(voce) = KevEntry::new(
            identificativo(id),
            "MikroTik",
            "RouterOS",
            "MikroTik RouterOS Argument Delimiters Vulnerability",
            "2026-09-10",
            "RouterOS contiene un difetto che permette l'elevazione di privilegi.",
            uso,
        ) else {
            panic!("la voce di prova deve essere valida");
        };
        voce
    }

    /// Archivio con una fotografia che elenca due voci.
    fn archivio() -> (Database, KevSnapshotId) {
        let mut database = database();
        let Ok(id) = database.record_kev_snapshot(&NewKevSnapshot {
            catalog: &catalogo(),
            declared_count: 2,
            omitted_count: 0,
            acquired_sha256: IMPRONTA,
            attribution: "CISA — Known Exploited Vulnerabilities Catalog (CC0 1.0 Universal)",
            entries: &[
                voce("CVE-2026-86060", RansomwareUse::UNKNOWN),
                voce("CVE-2026-11111", RansomwareUse::KNOWN),
            ],
            imported_by: &attore(),
            imported_at: Timestamp::from_millis(1_757_000_000_000),
        }) else {
            panic!("la fotografia deve potersi registrare");
        };
        (database, id)
    }

    #[test]
    fn una_fotografia_si_apre_e_si_rilegge() {
        let (database, id) = archivio();
        let Ok(fotografie) = database.kev_snapshots() else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(fotografie.len(), 1);
        assert_eq!(fotografie[0].id, id);
        assert_eq!(fotografie[0].entry_count, 2);
        assert_eq!(fotografie[0].declared_count, 2);
        assert_eq!(fotografie[0].expected_entries, 2);
        assert_eq!(fotografie[0].omitted_count, 0);
        assert_eq!(fotografie[0].catalog.version(), "2026.09.10");
        assert_eq!(fotografie[0].acquired_sha256, IMPRONTA);
        assert!(fotografie[0].attribution.contains("CISA"));
    }

    /// **Elencata.**
    #[test]
    fn un_identificativo_elencato_si_trova() {
        let (database, id) = archivio();
        let Ok(esito) = database.resolve_kev(id, &identificativo("CVE-2026-86060")) else {
            panic!("la risoluzione deve riuscire");
        };
        let KevResolution::Listed(voce) = esito else {
            panic!("la voce doveva essere elencata");
        };
        assert_eq!(voce.vendor_project(), "MikroTik");
        assert!(!voce.ransomware_use().is_known());
    }

    /// **Non elencata: e l'esito porta con sé l'identità del catalogo.**
    ///
    /// Senza di essa la frase direbbe soltanto «non elencata», che si legge come
    /// «non sfruttata».
    #[test]
    fn un_identificativo_assente_non_e_elencato_e_porta_l_identita_del_catalogo() {
        let (database, id) = archivio();
        let Ok(esito) = database.resolve_kev(id, &identificativo("CVE-2019-1234")) else {
            panic!("la risoluzione deve riuscire");
        };
        let KevResolution::NotListed { catalog } = esito else {
            panic!("l'esito doveva essere «non elencata»");
        };
        assert_eq!(catalog.version(), "2026.09.10");
        assert_eq!(catalog.released_at(), "2026-09-10T19:00:05.1949Z");
    }

    /// La dichiarazione sul ransomware si rilegge com'è stata scritta.
    #[test]
    fn la_dichiarazione_sul_ransomware_si_rilegge_invariata() {
        let (database, id) = archivio();
        let Ok(esito) = database.resolve_kev(id, &identificativo("CVE-2026-11111")) else {
            panic!("la risoluzione deve riuscire");
        };
        let KevResolution::Listed(voce) = esito else {
            panic!("la voce doveva essere elencata");
        };
        assert!(voce.ransomware_use().is_known());
        assert_eq!(voce.ransomware_use().as_str(), RansomwareUse::KNOWN);
    }

    /// Registrare due volte non duplica.
    #[test]
    fn un_identificativo_ripetuto_rifiuta_l_intera_fotografia() {
        let mut database = database();
        let esito = database.record_kev_snapshot(&NewKevSnapshot {
            catalog: &catalogo(),
            declared_count: 2,
            omitted_count: 0,
            acquired_sha256: IMPRONTA,
            attribution: "CISA",
            entries: &[
                voce("CVE-2026-86060", RansomwareUse::UNKNOWN),
                voce("CVE-2026-86060", RansomwareUse::KNOWN),
            ],
            imported_by: &attore(),
            imported_at: Timestamp::from_millis(1_757_000_000_000),
        });
        assert!(
            esito.is_err(),
            "un identificativo ripetuto non deve entrare in silenzio"
        );

        let Ok(fotografie) = database.kev_snapshots() else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert!(
            fotografie.is_empty(),
            "una registrazione rifiutata non deve lasciare una fotografia in archivio"
        );
    }

    /// **Una fotografia che non torna non è rappresentabile.**
    ///
    /// Ogni voce del catalogo o è entrata o è stata omessa con il proprio
    /// motivo, e lo schema lo pretende.
    #[test]
    fn i_conteggi_di_una_fotografia_devono_tornare() {
        let mut database = database();
        let esito = database.record_kev_snapshot(&NewKevSnapshot {
            catalog: &catalogo(),
            // Il catalogo ne dichiara cinque; ne entrano due e nessuna e' omessa.
            declared_count: 5,
            omitted_count: 0,
            acquired_sha256: IMPRONTA,
            attribution: "CISA",
            entries: &[
                voce("CVE-2026-86060", RansomwareUse::UNKNOWN),
                voce("CVE-2026-11111", RansomwareUse::KNOWN),
            ],
            imported_by: &attore(),
            imported_at: Timestamp::from_millis(1_757_000_000_000),
        });
        assert!(
            esito.is_err(),
            "una fotografia i cui conteggi non tornano non deve essere scrivibile"
        );
    }

    /// **Una fotografia incompleta non può rispondere «non elencata».**
    ///
    /// È l'unica risposta che questa fotografia non deve mai sbagliare.
    /// `record_kev_snapshot` scrive tutto in una transazione, perciò lo stato è
    /// costruito qui a mano: è la seconda difesa, per un archivio danneggiato.
    #[test]
    fn una_fotografia_incompleta_non_risponde_non_elencata() {
        let database = database();
        let Ok(_) = database.connection.execute(
            "INSERT INTO kev_snapshots (
                 catalog_version, date_released, declared_count, expected_entries,
                 omitted_count, acquired_sha256, attribution, imported_by, imported_at
             ) VALUES ('2026.09.10', '2026-09-10T19:00:05Z', 2, 2, 0, ?1, 'CISA', 'operatore', 1)",
            rusqlite::params![IMPRONTA],
        ) else {
            panic!("la riga di prova deve potersi scrivere");
        };

        let id = KevSnapshotId::new(database.connection.last_insert_rowid());
        let esito = database.resolve_kev(id, &identificativo("CVE-2026-86060"));
        assert!(
            matches!(esito, Err(StorageError::CorruptedRow { .. })),
            "una fotografia senza le voci che dichiara non deve poter dire «non elencata»"
        );
    }

    /// Una fotografia che non è in archivio non è una riga corrotta.
    #[test]
    fn una_fotografia_inesistente_si_dichiara_non_trovata() {
        let database = database();
        let esito = database.resolve_kev(KevSnapshotId::new(999), &identificativo("CVE-2026-1234"));
        assert!(matches!(
            esito,
            Err(StorageError::NotFound {
                entity: "fotografia_kev",
                ..
            })
        ));
    }

    /// **Una fotografia non si modifica e non si cancella.**
    #[test]
    fn una_fotografia_non_si_modifica_ne_si_cancella() {
        let (database, _) = archivio();
        for sql in [
            "UPDATE kev_snapshots SET catalog_version = '1999.01.01'",
            "DELETE FROM kev_snapshots",
            "UPDATE kev_entries SET short_description = 'altro'",
            "DELETE FROM kev_entries",
        ] {
            assert!(
                database.connection.execute(sql, []).is_err(),
                "«{sql}» non doveva essere ammesso"
            );
        }
    }

    /// **Lo schema rifiuta una fotografia senza identità.**
    #[test]
    fn lo_schema_rifiuta_una_fotografia_senza_identita() {
        let database = database();
        for (versione, rilascio) in [("   ", "2026-09-10T19:00:05Z"), ("2026.09.10", "  ")] {
            assert!(
                database
                    .connection
                    .execute(
                        "INSERT INTO kev_snapshots (
                             catalog_version, date_released, declared_count, expected_entries,
                             omitted_count, acquired_sha256, attribution, imported_by, imported_at
                         ) VALUES (?1, ?2, 0, 0, 0, ?3, 'CISA', 'operatore', 1)",
                        rusqlite::params![versione, rilascio, IMPRONTA],
                    )
                    .is_err(),
                "una fotografia senza identità non doveva essere ammessa"
            );
        }
    }

    /// **Lo schema non ha un posto per l'ordine che KEV rivolge ad altri.**
    ///
    /// `requiredAction`, `dueDate` e `forensicTriage` obbligano le agenzie
    /// federali civili statunitensi. Ciò che non entra non può essere mostrato
    /// per errore.
    #[test]
    fn lo_schema_non_ha_colonne_per_scadenze_o_azioni_imposte() {
        let database = database();
        for sql in [
            "SELECT due_date FROM kev_entries",
            "SELECT required_action FROM kev_entries",
            "SELECT forensic_triage FROM kev_entries",
            "SELECT cwes FROM kev_entries",
            "SELECT notes FROM kev_entries",
        ] {
            assert!(
                database.connection.prepare(sql).is_err(),
                "«{sql}» non doveva essere interrogabile: quella colonna non deve esistere"
            );
        }
    }
}

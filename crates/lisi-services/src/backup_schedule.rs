//! Le copie di sicurezza pianificate (BACKUP-SCHEDULE-01, ADR-0191, DEC-476).
//!
//! # Le stesse regole della copia a mano
//!
//! La copia la scrive [`BackupService::write_to`]: del solo utente, con il
//! foglio, o non si scrive (SEC-01). La pianificazione decide soltanto
//! **quando** e **dove**, e registra ogni tentativo.
//!
//! # Un fallimento non tace
//!
//! [`pending_failure`] dice se l'ultimo tentativo pianificato è fallito e
//! nessuna copia è riuscita dopo: il centro diagnostico lo mostra come un
//! guasto, e la fascia di prontezza lo dice al prossimo avvio (ADR-0191,
//! decisione 5).
//!
//! # La conservazione tocca soltanto le copie pianificate
//!
//! Dopo una copia riuscita, quelle pianificate registrate oltre le ultime N si
//! tolgono, copia e foglio, dalla cartella della pianificazione e con il nome
//! registrato. Una copia fatta a mano non è nel registro, e non si tocca mai.

use std::path::{Path, PathBuf};

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, Timestamp};
use lisi_storage::Database;
pub use lisi_storage::repository::backup_schedule::StoredScheduledBackup;
use lisi_storage::repository::backup_schedule::{NewScheduledBackup, StoredBackupSchedule};

use crate::backup::BackupService;
use crate::error::{ServiceError, ServiceResult};

/// L'azione d'audit di una pianificazione scelta, cambiata o spenta.
pub const SCHEDULE_AUDIT_ACTION: &str = "copie_pianificate_scelte";
/// L'azione d'audit di una copia pianificata riuscita.
pub const SCHEDULED_AUDIT_ACTION: &str = "copia_pianificata";
/// L'azione d'audit di una copia pianificata fallita.
pub const FAILED_AUDIT_ACTION: &str = "copia_pianificata_fallita";
/// L'azione d'audit di una copia pianificata tolta dalla conservazione.
pub const REMOVED_AUDIT_ACTION: &str = "copia_pianificata_tolta";

/// I limiti dichiarati (ADR-0191, decisione 1).
pub const MAX_INTERVAL_DAYS: u32 = 30;
/// Quante copie al più si tengono.
pub const MAX_KEEP: u32 = 30;

const GIORNO: i64 = 86_400_000;

/// La pianificazione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSchedule {
    /// La cartella in cui escono le copie.
    pub destination: PathBuf,
    /// Ogni quanti giorni, da 1 a 30.
    pub interval_days: u32,
    /// Quante copie pianificate tenere, da 1 a 30.
    pub keep: u32,
}

impl BackupSchedule {
    /// La pianificazione, in una frase.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Una copia {} in «{}»; si tengono le ultime {} copie pianificate.",
            if self.interval_days == 1 {
                String::from("ogni giorno")
            } else {
                format!("ogni {} giorni", self.interval_days)
            },
            self.destination.display(),
            self.keep
        )
    }
}

/// Com'è andata una copia pianificata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledOutcome {
    /// La copia è stata scritta.
    Written {
        /// La copia.
        archive: PathBuf,
        /// Quante copie vecchie la conservazione ha tolto.
        removed: usize,
    },
    /// La copia non è stata scritta.
    Failed {
        /// Perché.
        reason: String,
    },
}

impl ScheduledOutcome {
    /// La frase per una persona.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Written { archive, removed } => {
                let mut testo = format!("Copia pianificata scritta: «{}».", archive.display());
                if *removed > 0 {
                    testo.push_str(&format!(
                        " Tolte le copie pianificate più vecchie: {removed}."
                    ));
                }
                testo
            }
            Self::Failed { reason } => format!(
                "La copia pianificata NON è stata scritta: {reason} Finché una copia non \
                 riesce, il controllo all'avvio lo ricorda."
            ),
        }
    }
}

/// Se l'ultima copia pianificata è fallita e nessuna copia è riuscita dopo:
/// quando, e perché.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn pending_failure(database: &Database) -> ServiceResult<Option<(Timestamp, String)>> {
    let Some(ultimo) = database.last_scheduled_backup()? else {
        return Ok(None);
    };
    if ultimo.attempt.outcome != "fallita" {
        return Ok(None);
    }
    // Una copia riuscita dopo, anche fatta a mano, rimedia.
    let rimedio = database.last_audit_at(crate::diagnostics::BACKUP_AUDIT_ACTION)?;
    if rimedio.is_some_and(|istante| istante > ultimo.attempt.attempted_at) {
        return Ok(None);
    }
    Ok(Some((
        ultimo.attempt.attempted_at,
        ultimo.attempt.detail.unwrap_or_default(),
    )))
}

/// Il servizio delle copie pianificate, attorno a quello delle copie.
#[derive(Debug)]
pub struct BackupScheduleService {
    backup: BackupService,
}

impl BackupScheduleService {
    /// Il servizio, attorno all'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self {
            backup: BackupService::new(database),
        }
    }

    fn database(&self) -> &Database {
        self.backup.database()
    }

    /// La pianificazione, se accesa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn schedule(&self) -> ServiceResult<Option<BackupSchedule>> {
        Ok(self
            .database()
            .backup_schedule()?
            .map(|scelta| BackupSchedule {
                destination: PathBuf::from(scelta.destination),
                interval_days: scelta.interval_days,
                keep: scelta.keep,
            }))
    }

    /// Gli ultimi tentativi, i più recenti prima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn attempts(&self, limit: usize) -> ServiceResult<Vec<StoredScheduledBackup>> {
        Ok(self.database().scheduled_backups(limit)?)
    }

    /// Accende, cambia o spegne la pianificazione. Soltanto l'amministratore.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// [`ServiceError::BackupScheduleRefused`] per una cartella che non c'è o numeri
    /// fuori dai limiti; un errore se la scrittura non riesce.
    pub fn choose(
        &mut self,
        schedule: Option<&BackupSchedule>,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !mode.allows(RestrictedAction::ChooseBackupSchedule) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseBackupSchedule,
            });
        }
        let conservata = match schedule {
            None => None,
            Some(scelta) => {
                if !(1..=MAX_INTERVAL_DAYS).contains(&scelta.interval_days)
                    || !(1..=MAX_KEEP).contains(&scelta.keep)
                {
                    return Err(ServiceError::BackupScheduleRefused {
                        reason: format!(
                            "l'intervallo va da 1 a {MAX_INTERVAL_DAYS} giorni, e le copie \
                             da tenere da 1 a {MAX_KEEP}"
                        ),
                    });
                }
                if !scelta.destination.is_dir() {
                    return Err(ServiceError::BackupScheduleRefused {
                        reason: format!("«{}» non è una cartella", scelta.destination.display()),
                    });
                }
                Some(StoredBackupSchedule {
                    destination: scelta.destination.to_string_lossy().into_owned(),
                    interval_days: scelta.interval_days,
                    keep: scelta.keep,
                })
            }
        };
        let dettaglio = schedule.map_or_else(
            || String::from("spenta"),
            |scelta| {
                format!(
                    "ogni {} giorni, si tengono {}",
                    scelta.interval_days, scelta.keep
                )
            },
        );
        let audit = audit_entry(actor, SCHEDULE_AUDIT_ACTION, &dettaglio, Some(mode), now)?;
        self.backup
            .database_mut()
            .save_backup_schedule(conservata.as_ref(), actor, &audit)?;
        Ok(())
    }

    /// Se una copia pianificata è dovuta adesso.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn is_due(&self, now: Timestamp) -> ServiceResult<bool> {
        let Some(scelta) = self.schedule()? else {
            return Ok(false);
        };
        let Some(ultimo) = self.database().last_scheduled_backup()? else {
            return Ok(true);
        };
        let intervallo = i64::from(scelta.interval_days).saturating_mul(GIORNO);
        Ok(now
            .as_millis()
            .saturating_sub(ultimo.attempt.attempted_at.as_millis())
            >= intervallo)
    }

    /// Fa la copia pianificata se è dovuta, la registra, e applica la
    /// conservazione. `None` se non era dovuta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non si legge o il registro non si
    /// scrive. Una copia che non si scrive non è un errore: è un
    /// [`ScheduledOutcome::Failed`], registrato.
    pub fn run_if_due(
        &mut self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<Option<ScheduledOutcome>> {
        if !self.is_due(now)? {
            return Ok(None);
        }
        let Some(scelta) = self.schedule()? else {
            return Ok(None);
        };
        let esito = match self.backup.write_to(&scelta.destination, actor, now) {
            Ok(copia) if copia.needs_attention() => Err(String::from(
                "la copia è stata scritta ma la rilettura non è riuscita: non fidarsi di quella \
                 copia.",
            )),
            Ok(copia) => Ok(copia.archive),
            Err(errore) => Err(errore.operator_message()),
        };
        match esito {
            Ok(archivio) => {
                let nome = archivio
                    .file_name()
                    .map(|nome| nome.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let audit = audit_entry(actor, SCHEDULED_AUDIT_ACTION, &nome, None, now)?;
                self.backup.database_mut().insert_scheduled_backup(
                    &NewScheduledBackup {
                        attempted_at: now,
                        outcome: String::from("riuscita"),
                        file_name: Some(nome),
                        detail: None,
                    },
                    &audit,
                )?;
                let removed = self.conserva(&scelta, actor, now)?;
                Ok(Some(ScheduledOutcome::Written {
                    archive: archivio,
                    removed,
                }))
            }
            Err(motivo) => {
                let motivo: String = motivo.chars().take(1000).collect();
                let audit = audit_entry(actor, FAILED_AUDIT_ACTION, &motivo, None, now)?;
                self.backup.database_mut().insert_scheduled_backup(
                    &NewScheduledBackup {
                        attempted_at: now,
                        outcome: String::from("fallita"),
                        file_name: None,
                        detail: Some(motivo.clone()),
                    },
                    &audit,
                )?;
                Ok(Some(ScheduledOutcome::Failed { reason: motivo }))
            }
        }
    }

    /// Toglie le copie pianificate oltre le ultime `keep`, soltanto dalla
    /// cartella della pianificazione e con il nome registrato.
    fn conserva(
        &mut self,
        scelta: &BackupSchedule,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<usize> {
        let tenute = self.database().kept_scheduled_backups()?;
        let mut tolte = 0_usize;
        for vecchia in tenute
            .iter()
            .skip(usize::try_from(scelta.keep).unwrap_or(usize::MAX))
        {
            let Some(nome) = vecchia.attempt.file_name.as_deref() else {
                continue;
            };
            let copia = scelta.destination.join(nome);
            let foglio = copia.with_extension("txt");
            let mut fatto = Vec::new();
            for file in [&copia, &foglio] {
                if file.is_file() {
                    if let Err(errore) = std::fs::remove_file(file) {
                        tracing::warn!(%errore, "una copia pianificata vecchia non si toglie");
                        continue;
                    }
                    fatto.push(nome_di(file));
                }
            }
            // Se la copia non c'è più (spostata, tolta a mano), lo si dice e
            // non la si cerca più.
            let dettaglio = if fatto.is_empty() {
                format!("{nome}: non era più nella cartella")
            } else {
                fatto.join(", ")
            };
            let audit = audit_entry(actor, REMOVED_AUDIT_ACTION, &dettaglio, None, now)?;
            self.backup
                .database_mut()
                .mark_scheduled_backup_removed(vecchia.id, &audit)?;
            tolte += 1;
        }
        Ok(tolte)
    }
}

fn nome_di(file: &Path) -> String {
    file.file_name()
        .map(|nome| nome.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn audit_entry(
    actor: &Actor,
    action: &str,
    detail: &str,
    mode: Option<OperatingMode>,
    now: Timestamp,
) -> ServiceResult<NewAuditEntry> {
    let dettaglio: String = detail
        .chars()
        .filter(|carattere| !carattere.is_control())
        .take(240)
        .collect();
    Ok(NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(action)?,
        entity: AuditEntity::try_new("archivio")?,
        entity_id: None,
        actor_mode: mode,
        detail: Some(AuditDetail::try_new(&dettaglio)?),
        recorded_at: now,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, Timestamp};

    use super::{BackupSchedule, BackupScheduleService, ScheduledOutcome, pending_failure};
    use crate::error::ServiceError;

    const GIORNO: i64 = 86_400_000;

    fn servizio() -> BackupScheduleService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        BackupScheduleService::new(database)
    }

    fn persona() -> Actor {
        let Ok(attore) = Actor::try_new("amministratore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn al_giorno(giorno: i64) -> Timestamp {
        Timestamp::from_millis(1_762_300_000_000 + giorno * GIORNO)
    }

    fn cartella() -> tempfile::TempDir {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve crearsi");
        };
        cartella
    }

    fn pianifica(servizio: &mut BackupScheduleService, dove: &Path, giorni: u32, quante: u32) {
        let Ok(()) = servizio.choose(
            Some(&BackupSchedule {
                destination: dove.to_path_buf(),
                interval_days: giorni,
                keep: quante,
            }),
            OperatingMode::Administrator,
            &persona(),
            al_giorno(0),
        ) else {
            panic!("la pianificazione si deve scegliere");
        };
    }

    #[test]
    fn la_pianificazione_e_dell_amministratore_e_ha_limiti() {
        let mut servizio = servizio();
        let dove = cartella();
        let scelta = BackupSchedule {
            destination: dove.path().to_path_buf(),
            interval_days: 1,
            keep: 3,
        };
        assert!(matches!(
            servizio.choose(
                Some(&scelta),
                OperatingMode::Operator,
                &persona(),
                al_giorno(0)
            ),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
        let mut fuori = scelta.clone();
        fuori.keep = 31;
        assert!(matches!(
            servizio.choose(
                Some(&fuori),
                OperatingMode::Administrator,
                &persona(),
                al_giorno(0)
            ),
            Err(ServiceError::BackupScheduleRefused { .. })
        ));
        let mut assente = scelta.clone();
        assente.destination = dove.path().join("non-esiste");
        assert!(
            servizio
                .choose(
                    Some(&assente),
                    OperatingMode::Administrator,
                    &persona(),
                    al_giorno(0)
                )
                .is_err()
        );
        assert_eq!(servizio.schedule().ok(), Some(None), "niente è cambiato");
        assert!(
            !servizio.is_due(al_giorno(5)).unwrap_or(true),
            "spenta non è mai dovuta"
        );
    }

    #[test]
    fn la_copia_parte_quando_e_dovuta_e_la_conservazione_tiene_le_ultime() {
        let mut servizio = servizio();
        let dove = cartella();
        pianifica(&mut servizio, dove.path(), 1, 2);

        let mut scritte = Vec::new();
        for giorno in 0..4 {
            assert!(servizio.is_due(al_giorno(giorno)).unwrap_or(false));
            let Ok(Some(ScheduledOutcome::Written { archive, .. })) =
                servizio.run_if_due(&persona(), al_giorno(giorno))
            else {
                panic!("la copia del giorno {giorno} si deve scrivere");
            };
            scritte.push(archive);
            // Non due volte nello stesso giorno.
            assert_eq!(
                servizio.run_if_due(&persona(), al_giorno(giorno)).ok(),
                Some(None)
            );
        }
        // Restano le ultime due, con i loro fogli; le prime due sono tolte.
        assert!(!scritte[0].exists() && !scritte[1].exists());
        assert!(scritte[2].exists() && scritte[3].exists());
        assert!(!scritte[0].with_extension("txt").exists());
        assert!(scritte[3].with_extension("txt").exists());

        // Una copia fatta a mano nella stessa cartella non si tocca mai.
        let a_mano = dove.path().join("copia-a-mano.sqlite3");
        let Ok(()) = std::fs::write(&a_mano, b"a mano") else {
            panic!("il file deve scriversi");
        };
        let Ok(Some(_)) = servizio.run_if_due(&persona(), al_giorno(4)) else {
            panic!("la copia del quinto giorno si deve scrivere");
        };
        assert!(a_mano.exists());
    }

    #[test]
    fn un_fallimento_resta_in_vista_finche_una_copia_non_riesce() {
        let mut servizio = servizio();
        let dove = cartella();
        pianifica(&mut servizio, dove.path(), 1, 3);
        // La cartella sparisce: la copia pianificata fallisce, e lo si registra.
        let percorso = dove.path().to_path_buf();
        drop(dove);
        let Ok(Some(ScheduledOutcome::Failed { reason })) =
            servizio.run_if_due(&persona(), al_giorno(1))
        else {
            panic!("la copia doveva fallire");
        };
        assert!(!reason.is_empty());
        let Ok(Some((quando, motivo))) = pending_failure(servizio.database()) else {
            panic!("il fallimento deve restare in vista");
        };
        assert_eq!(quando, al_giorno(1));
        assert_eq!(motivo, reason);

        // Il giorno dopo la cartella c'è di nuovo: la copia riesce e rimedia.
        let Ok(()) = std::fs::create_dir_all(&percorso) else {
            panic!("la cartella deve ricrearsi");
        };
        let Ok(Some(ScheduledOutcome::Written { .. })) =
            servizio.run_if_due(&persona(), al_giorno(2))
        else {
            panic!("la copia doveva riuscire");
        };
        assert_eq!(pending_failure(servizio.database()).ok(), Some(None));
        let _ = std::fs::remove_dir_all(&percorso);
    }
}

//! La memoria dei comandi già visti (HUB-CMD-01, ADR-0089).
//!
//! # L'effetto e la memoria nella stessa transazione
//!
//! [`Database::apply_command_once`] esegue l'effetto **dentro** la transazione
//! che scrive l'esito. Le due cose non possono separarsi: se l'effetto stesse
//! in una transazione e la memoria in un'altra, esisterebbe un istante in cui
//! l'effetto c'è e la memoria no — e una ripetizione in quell'istante
//! **raddoppierebbe**, che è esattamente ciò che ADR-0042 decisione 8 vieta.
//!
//! La transazione è `IMMEDIATE` per la stessa ragione dell'arruolamento: si
//! legge prima e si scrive dopo, e due comandi concorrenti finirebbero entrambi
//! a leggere «non l'ho mai visto».

use lisi_core::Timestamp;
use lisi_core::model::hub_command::{CommandKey, CommandOutcome, CommandVerdict};
use lisi_core::text::HubEventDetail;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::millis;

/// Forma conservata di un esito eseguito.
const ESEGUITO: &str = "eseguito";
/// Forma conservata di un esito rifiutato.
const RIFIUTATO: &str = "rifiutato";

impl Database {
    /// Esegue un comando **una volta sola**.
    ///
    /// Se la coppia *(dispositivo, identificativo)* è già stata vista,
    /// `effetto` **non viene chiamato** e si restituisce
    /// [`CommandVerdict::Replay`] con l'esito di allora.
    ///
    /// `effetto` riceve la transazione: ciò che scrive è atomico con la memoria
    /// del comando. Se restituisce `Err`, **tutto** viene annullato — effetto e
    /// memoria — e il client può ripetere.
    ///
    /// # Errori
    ///
    /// L'errore di `effetto`, o un errore d'archivio.
    pub fn apply_command_once<E>(
        &mut self,
        key: &CommandKey,
        now: Timestamp,
        effetto: E,
    ) -> StorageResult<CommandVerdict>
    where
        E: FnOnce(&Transaction<'_>) -> StorageResult<CommandOutcome>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // Già visto? Allora l'esito è quello di allora, e l'effetto non si tocca.
        let conservato: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT outcome_kind, outcome_detail
                   FROM hub_commands
                  WHERE device_id = ?1 AND command_id = ?2",
                params![key.device.as_str(), key.command_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some(riga) = conservato {
            transaction.commit()?;
            return Ok(CommandVerdict::Replay(leggi_esito(riga)?));
        }

        let esito = effetto(&transaction)?;
        let (kind, detail) = match &esito {
            CommandOutcome::Done { detail } => {
                (ESEGUITO, detail.as_ref().map(HubEventDetail::as_str))
            }
            CommandOutcome::Refused { reason } => (RIFIUTATO, Some(reason.as_str())),
        };
        transaction.execute(
            "INSERT INTO hub_commands (device_id, command_id, outcome_kind, outcome_detail, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                key.device.as_str(),
                key.command_id.as_str(),
                kind,
                detail,
                millis(now)
            ],
        )?;
        transaction.commit()?;
        Ok(CommandVerdict::Applied(esito))
    }

    /// L'esito di un comando già visto, se c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se la riga conservata
    /// non è interpretabile.
    pub fn command_outcome(&self, key: &CommandKey) -> StorageResult<Option<CommandOutcome>> {
        self.connection
            .query_row(
                "SELECT outcome_kind, outcome_detail
                   FROM hub_commands
                  WHERE device_id = ?1 AND command_id = ?2",
                params![key.device.as_str(), key.command_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .map(leggi_esito)
            .transpose()
    }
}

/// Interpreta una riga di esito.
fn leggi_esito(riga: (String, Option<String>)) -> StorageResult<CommandOutcome> {
    let (kind, detail) = riga;
    match kind.as_str() {
        ESEGUITO => Ok(CommandOutcome::Done {
            detail: detail.as_deref().map(HubEventDetail::try_new).transpose()?,
        }),
        RIFIUTATO => {
            let Some(reason) = detail else {
                return Err(StorageError::CorruptedRow {
                    detail: "un rifiuto conservato senza ragione",
                });
            };
            Ok(CommandOutcome::Refused {
                reason: HubEventDetail::try_new(&reason)?,
            })
        }
        _ => Err(StorageError::CorruptedRow {
            detail: "l'esito conservato non è né eseguito né rifiutato",
        }),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::hub_command::{CommandId, CommandKey, CommandOutcome, CommandVerdict};
    use lisi_core::model::identity::{DEVICE_ID_BYTES, DeviceId};
    use lisi_core::text::HubEventDetail;

    use crate::database::Database;
    use crate::error::StorageError;

    fn archivio() -> Database {
        let Ok(database) = Database::open_in_memory() else {
            panic!("archivio di prova");
        };
        database
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_700_000_000)
    }

    fn chiave(seme: u8, id: &str) -> CommandKey {
        let Ok(command_id) = CommandId::parse(id) else {
            panic!("identificativo di prova");
        };
        CommandKey {
            device: DeviceId::from_random_bytes(&[seme; DEVICE_ID_BYTES]),
            command_id,
        }
    }

    fn dettaglio(testo: &str) -> HubEventDetail {
        let Ok(valore) = HubEventDetail::try_new(testo) else {
            panic!("dettaglio di prova");
        };
        valore
    }

    /// Un effetto che conta quante volte è stato eseguito, scrivendo davvero.
    fn conta(transaction: &rusqlite::Transaction<'_>) -> crate::error::StorageResult<()> {
        transaction.execute(
            "CREATE TABLE IF NOT EXISTS prova_effetto (id INTEGER PRIMARY KEY AUTOINCREMENT)",
            [],
        )?;
        transaction.execute("INSERT INTO prova_effetto DEFAULT VALUES", [])?;
        Ok(())
    }

    fn effetti(archivio: &Database) -> i64 {
        archivio
            .connection
            .query_row("SELECT count(*) FROM prova_effetto", [], |row| row.get(0))
            .unwrap_or(0)
    }

    #[test]
    fn repeating_a_command_does_not_run_it_twice_and_gives_back_the_outcome_of_then() {
        let mut archivio = archivio();
        let chiave = chiave(1, "comando-uno");

        let Ok(CommandVerdict::Applied(CommandOutcome::Done { detail })) = archivio
            .apply_command_once(&chiave, adesso(), |transaction| {
                conta(transaction)?;
                Ok(CommandOutcome::Done {
                    detail: Some(dettaglio("monitoraggio avviato")),
                })
            })
        else {
            panic!("il primo comando deve essere eseguito");
        };
        assert_eq!(
            detail.map(|d| d.as_str().to_owned()),
            Some(String::from("monitoraggio avviato"))
        );
        assert_eq!(effetti(&archivio), 1);

        // La ripetizione: l'effetto NON si tocca.
        let Ok(CommandVerdict::Replay(CommandOutcome::Done { detail })) = archivio
            .apply_command_once(&chiave, adesso(), |transaction| {
                conta(transaction)?;
                Ok(CommandOutcome::Done { detail: None })
            })
        else {
            panic!("la ripetizione deve restituire l'esito di allora");
        };
        assert_eq!(
            detail.map(|d| d.as_str().to_owned()),
            Some(String::from("monitoraggio avviato")),
            "l'esito è quello di allora, non quello di adesso"
        );
        assert_eq!(effetti(&archivio), 1, "l'effetto non si è ripetuto");
    }

    #[test]
    fn the_same_identifier_from_another_device_is_another_command() {
        let mut archivio = archivio();
        for seme in [1_u8, 2] {
            let Ok(CommandVerdict::Applied(_)) =
                archivio.apply_command_once(&chiave(seme, "stesso-id"), adesso(), |transaction| {
                    conta(transaction)?;
                    Ok(CommandOutcome::Done { detail: None })
                })
            else {
                panic!("ogni dispositivo ha il proprio spazio di identificativi");
            };
        }
        assert_eq!(effetti(&archivio), 2);
    }

    #[test]
    fn a_refusal_is_remembered_too_and_is_not_retried() {
        let mut archivio = archivio();
        let chiave = chiave(1, "comando-rifiutato");
        let Ok(CommandVerdict::Applied(CommandOutcome::Refused { .. })) = archivio
            .apply_command_once(&chiave, adesso(), |_| {
                Ok(CommandOutcome::Refused {
                    reason: dettaglio("il perimetro è già attivo"),
                })
            })
        else {
            panic!("un rifiuto è un esito");
        };

        let Ok(CommandVerdict::Replay(CommandOutcome::Refused { reason })) = archivio
            .apply_command_once(&chiave, adesso(), |_| {
                panic!("un comando già rifiutato non si riesegue")
            })
        else {
            panic!("la ripetizione deve restituire il rifiuto di allora");
        };
        assert_eq!(reason.as_str(), "il perimetro è già attivo");
    }

    #[test]
    fn an_effect_that_fails_leaves_no_memory_and_the_client_can_repeat() {
        let mut archivio = archivio();
        let chiave = chiave(1, "comando-fallito");
        let esito = archivio.apply_command_once(&chiave, adesso(), |transaction| {
            conta(transaction)?;
            Err(StorageError::CorruptedRow {
                detail: "l'effetto non riesce",
            })
        });
        assert!(esito.is_err());
        assert_eq!(effetti(&archivio), 0, "l'effetto è stato annullato");
        assert_eq!(
            archivio.command_outcome(&chiave).ok(),
            Some(None),
            "e non è rimasta memoria del comando"
        );

        // Il client ripete, e stavolta riesce.
        let Ok(CommandVerdict::Applied(_)) =
            archivio.apply_command_once(&chiave, adesso(), |transaction| {
                conta(transaction)?;
                Ok(CommandOutcome::Done { detail: None })
            })
        else {
            panic!("dopo un fallimento il comando si può ripetere");
        };
        assert_eq!(effetti(&archivio), 1);
    }

    #[test]
    fn an_outcome_is_never_rewritten() {
        let mut archivio = archivio();
        let chiave = chiave(1, "comando-fermo");
        let _ = archivio.apply_command_once(&chiave, adesso(), |_| {
            Ok(CommandOutcome::Done { detail: None })
        });
        let modifica = archivio.connection.execute(
            "UPDATE hub_commands SET outcome_kind = 'rifiutato' WHERE command_id = 'comando-fermo'",
            [],
        );
        assert!(modifica.is_err());
        let cancellazione = archivio.connection.execute(
            "DELETE FROM hub_commands WHERE command_id = 'comando-fermo'",
            [],
        );
        assert!(cancellazione.is_err());
    }
}

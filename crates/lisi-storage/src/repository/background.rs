//! Il segno di vita del custode e i passaggi di mano (SERVICE-01, ADR-0203,
//! migrazione 0094).

use lisi_core::Timestamp;
use lisi_core::model::background::{Keeper, LastSign, accounts_from_text, accounts_to_text};

use crate::Database;
use crate::error::StorageResult;
use crate::repository::millis;

/// Un passaggio di mano registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHandover {
    /// L'identificativo.
    pub id: i64,
    /// Chi l'ha lasciata.
    pub released_by: Keeper,
    /// Il suo ultimo segno di vita.
    pub released_at: Timestamp,
    /// Chi l'ha presa.
    pub taken_by: Keeper,
    /// Quando.
    pub taken_at: Timestamp,
    /// Gli account ripresi.
    pub accounts: Vec<i64>,
}

impl Database {
    /// Scrive il segno di vita di chi tiene l'acquisizione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn record_keeper_sign(
        &self,
        keeper: Keeper,
        at: Timestamp,
        linked_accounts: &[i64],
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE background_keeper SET keeper = ?1, alive_at = ?2, linked_accounts = ?3 \
             WHERE id = 1",
            rusqlite::params![
                keeper.as_str(),
                millis(at),
                accounts_to_text(linked_accounts)
            ],
        )?;
        Ok(())
    }

    /// L'ultimo segno di vita, se qualcuno l'ha scritto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_keeper_sign(&self) -> StorageResult<Option<LastSign>> {
        let (keeper, at, accounts): (Option<String>, Option<i64>, String) =
            self.connection.query_row(
                "SELECT keeper, alive_at, linked_accounts FROM background_keeper WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        Ok(match (keeper.as_deref().and_then(Keeper::parse), at) {
            (Some(keeper), Some(at)) => Some(LastSign {
                keeper,
                at: Timestamp::from_millis(at),
                linked_accounts: accounts_from_text(&accounts),
            }),
            _ => None,
        })
    }

    /// Registra un passaggio di mano.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, o se i due custodi
    /// sono lo stesso o gli istanti vanno all'indietro.
    pub fn insert_background_handover(
        &self,
        last: &LastSign,
        taken_by: Keeper,
        taken_at: Timestamp,
    ) -> StorageResult<i64> {
        self.connection.execute(
            "INSERT INTO background_handovers \
             (released_by, released_at, taken_by, taken_at, accounts) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                last.keeper.as_str(),
                millis(last.at),
                taken_by.as_str(),
                millis(taken_at),
                accounts_to_text(&last.linked_accounts)
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    /// Gli ultimi passaggi di mano, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn background_handovers(&self, limite: u32) -> StorageResult<Vec<StoredHandover>> {
        let mut statement = self.connection.prepare(
            "SELECT id, released_by, released_at, taken_by, taken_at, accounts \
             FROM background_handovers ORDER BY taken_at DESC, id DESC LIMIT ?1",
        )?;
        let righe = statement.query_map([limite], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut passaggi = Vec::new();
        for riga in righe {
            let (id, lasciata, lasciata_alle, presa, presa_alle, account) = riga?;
            if let (Some(released_by), Some(taken_by)) =
                (Keeper::parse(&lasciata), Keeper::parse(&presa))
            {
                passaggi.push(StoredHandover {
                    id,
                    released_by,
                    released_at: Timestamp::from_millis(lasciata_alle),
                    taken_by,
                    taken_at: Timestamp::from_millis(presa_alle),
                    accounts: accounts_from_text(&account),
                });
            }
        }
        Ok(passaggi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archivio() -> Database {
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        database
    }

    /// **Il segno di vita si riscrive e si rilegge.**
    #[test]
    fn il_segno_di_vita_si_riscrive() {
        let database = archivio();
        assert_eq!(database.last_keeper_sign().ok(), Some(None));
        let Ok(()) =
            database.record_keeper_sign(Keeper::Window, Timestamp::from_millis(5_000), &[2, 9])
        else {
            panic!("il segno deve scriversi");
        };
        let Ok(()) =
            database.record_keeper_sign(Keeper::Service, Timestamp::from_millis(7_000), &[9])
        else {
            panic!("il segno deve riscriversi");
        };
        assert_eq!(
            database.last_keeper_sign().ok(),
            Some(Some(LastSign {
                keeper: Keeper::Service,
                at: Timestamp::from_millis(7_000),
                linked_accounts: vec![9],
            }))
        );
    }

    /// **Un passaggio resta com'è**: non si riscrive, non si toglie, e non va
    /// da un custode a sé stesso.
    #[test]
    fn un_passaggio_non_cambia_e_non_si_toglie() {
        let database = archivio();
        let lasciata = LastSign {
            keeper: Keeper::Window,
            at: Timestamp::from_millis(1_000),
            linked_accounts: vec![4],
        };
        let Ok(id) = database.insert_background_handover(
            &lasciata,
            Keeper::Service,
            Timestamp::from_millis(4_000),
        ) else {
            panic!("il passaggio deve registrarsi");
        };
        assert!(
            database
                .connection
                .execute(
                    "UPDATE background_handovers SET taken_at = 0 WHERE id = ?1",
                    [id]
                )
                .is_err()
        );
        assert!(
            database
                .connection
                .execute("DELETE FROM background_handovers WHERE id = ?1", [id])
                .is_err()
        );
        assert!(
            database
                .insert_background_handover(
                    &lasciata,
                    Keeper::Window,
                    Timestamp::from_millis(5_000)
                )
                .is_err(),
            "lo stesso custode non passa la mano a sé stesso"
        );
        let Ok(passaggi) = database.background_handovers(10) else {
            panic!("i passaggi devono leggersi");
        };
        assert_eq!(passaggi.len(), 1);
        assert_eq!(passaggi[0].accounts, vec![4]);
    }
}

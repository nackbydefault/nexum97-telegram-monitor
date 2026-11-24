//! Lo stato di «Scopri NEXUM» (TOUR-01, ADR-0134, migrazione 0057).
//!
//! Una riga sola, o nessuna. **Nessuna riga** vuol dire che il tour non è mai
//! stato proposto, e chi legge riceve [`TourStatus::NeverProposed`]: è lo stato
//! da cui dipende la proposta del primo avvio, e una riga predefinita lo
//! cancellerebbe.
//!
//! Non è audit: nessun attore, nessun testo libero. Le colonne sono chiuse dai
//! `CHECK` dello schema.

use lisi_core::model::tour::{TourPhase, TourRecord, TourStatus, TourStepKey};
use rusqlite::OptionalExtension;

use crate::database::Database;
use crate::error::StorageResult;

impl Database {
    /// Lo stato del tour su questa postazione.
    ///
    /// Una chiave di passo che non ha la forma ammessa si legge come assente:
    /// il servizio farà ricominciare il tour, che è la risposta prudente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn tour_state(&self) -> StorageResult<TourStatus> {
        let riga: Option<(String, i64, Option<String>, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT state, tour_version, last_step, completed_version
                 FROM tour_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        Ok(riga.map_or(
            TourStatus::NeverProposed,
            |(fase, versione, passo, completata)| {
                TourStatus::Recorded(TourRecord {
                    phase: TourPhase::from_stored(&fase),
                    tour_version: u32::try_from(versione).unwrap_or(1),
                    last_step: passo.as_deref().and_then(TourStepKey::parse),
                    completed_version: completata.and_then(|v| u32::try_from(v).ok()),
                })
            },
        ))
    }

    /// Scrive lo stato del tour, sostituendo l'unica riga o creandola.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce o se lo stato viola un
    /// vincolo dello schema (per esempio un passo su un tour non in corso).
    pub fn save_tour_state(&self, record: &TourRecord, now_ms: i64) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO tour_state (id, state, tour_version, last_step, completed_version, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET
                 state = excluded.state,
                 tour_version = excluded.tour_version,
                 last_step = excluded.last_step,
                 completed_version = excluded.completed_version,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                record.phase.as_str(),
                i64::from(record.tour_version),
                record.last_step.as_ref().map(TourStepKey::as_str),
                record.completed_version.map(i64::from),
                now_ms,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::tour::{TourPhase, TourRecord, TourStatus, TourStepKey};

    use crate::test_support::database;

    fn in_corso(passo: &str) -> TourRecord {
        TourRecord {
            phase: TourPhase::InProgress,
            tour_version: 1,
            last_step: TourStepKey::parse(passo),
            completed_version: None,
        }
    }

    /// **Un archivio nuovo non ha la riga**: il tour non è mai stato proposto.
    #[test]
    fn un_archivio_nuovo_non_ha_mai_proposto_il_tour() {
        let database = database();
        let Ok(stato) = database.tour_state() else {
            panic!("lo stato deve leggersi");
        };
        assert_eq!(stato, TourStatus::NeverProposed);
    }

    #[test]
    fn lo_stato_si_scrive_e_si_rilegge() {
        let database = database();
        let Ok(()) = database.save_tour_state(&in_corso("storico"), 10) else {
            panic!("lo stato deve scriversi");
        };
        assert_eq!(
            database.tour_state().ok(),
            Some(TourStatus::Recorded(in_corso("storico")))
        );

        let completato = TourRecord {
            phase: TourPhase::Completed,
            tour_version: 1,
            last_step: None,
            completed_version: Some(1),
        };
        let Ok(()) = database.save_tour_state(&completato, 20) else {
            panic!("lo stato deve riscriversi");
        };
        assert_eq!(
            database.tour_state().ok(),
            Some(TourStatus::Recorded(completato))
        );
    }

    /// **Lo schema rifiuta ciò che il tour non deve conservare**: un passo su
    /// un tour che non è in corso, un completamento senza versione, una fase
    /// inventata, un passo che è testo libero.
    #[test]
    fn lo_schema_rifiuta_uno_stato_incoerente() {
        let database = database();
        let saltato_con_passo = TourRecord {
            phase: TourPhase::Skipped,
            tour_version: 1,
            last_step: TourStepKey::parse("fonti"),
            completed_version: None,
        };
        assert!(database.save_tour_state(&saltato_con_passo, 1).is_err());

        let completato_senza_versione = TourRecord {
            phase: TourPhase::Completed,
            tour_version: 1,
            last_step: None,
            completed_version: None,
        };
        assert!(
            database
                .save_tour_state(&completato_senza_versione, 1)
                .is_err()
        );

        for sql in [
            "INSERT INTO tour_state (id, state, tour_version, updated_at)
             VALUES (1, 'novita', 1, 0)",
            "INSERT INTO tour_state (id, state, tour_version, last_step, updated_at)
             VALUES (1, 'in_corso', 1, 'il mio numero 333', 0)",
            "INSERT INTO tour_state (id, state, tour_version, updated_at)
             VALUES (2, 'saltato', 1, 0)",
        ] {
            assert!(
                database.connection.execute(sql, []).is_err(),
                "lo schema deve rifiutare: {sql}"
            );
        }
    }

    /// **Nessuna colonna può portare un segreto o un attore**: le colonne sono
    /// quelle dichiarate, e nessun'altra.
    #[test]
    fn lo_stato_non_ha_colonne_per_segreti_o_attori() {
        let database = database();
        let Ok(mut statement) = database
            .connection
            .prepare("SELECT name FROM pragma_table_info('tour_state') ORDER BY cid")
        else {
            panic!("le colonne devono leggersi");
        };
        let Ok(colonne) = statement.query_map([], |row| row.get::<_, String>(0)) else {
            panic!("le colonne devono leggersi");
        };
        let colonne: Vec<String> = colonne.filter_map(Result::ok).collect();
        assert_eq!(
            colonne,
            [
                "id",
                "state",
                "tour_version",
                "last_step",
                "completed_version",
                "updated_at"
            ]
        );
    }
}

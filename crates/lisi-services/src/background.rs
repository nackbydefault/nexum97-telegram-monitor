//! Il monitoraggio in background e il passaggio di mano (SERVICE-01,
//! ADR-0203).
//!
//! La regola sta in `lisi_core::model::background`; qui si legge l'ultimo
//! segno di vita, si registra il passaggio o l'interruzione, e si riscrive il
//! segno di chi ha preso.
//!
//! # Gli account da riprendere sono quelli della persona
//!
//! L'accesso a Telegram resta un gesto della persona (ADR-0146). Il custode che
//! prende riprende **soltanto** gli account che erano collegati quando l'altro
//! ha lasciato: la persona li aveva collegati, e il passaggio continua quel
//! gesto. Dopo un'interruzione non riprende nulla.

use lisi_core::Timestamp;
use lisi_core::model::background::{Keeper, continues};
use lisi_storage::Database;
pub use lisi_storage::repository::background::StoredHandover;
use lisi_storage::repository::interruption::StoredInterruption;

use crate::error::ServiceResult;

/// Quanti passaggi mostra la schermata.
pub const SHOWN: u32 = 10;

/// Com'è andata la presa dell'acquisizione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Takeover {
    /// L'altro custode aveva lasciato da poco: è un passaggio di mano.
    Continued {
        /// Il passaggio registrato.
        handover_id: i64,
        /// Gli account da riprendere.
        accounts: Vec<i64>,
    },
    /// Non c'era un passaggio: le interruzioni aperte, come all'avvio di
    /// sempre (ADR-0064).
    Interrupted(Vec<StoredInterruption>),
}

/// Prende l'acquisizione per `taker`.
///
/// # Errori
///
/// Restituisce un errore se la lettura o una scrittura non riescono.
pub fn take_over(
    database: &mut Database,
    taker: Keeper,
    now: Timestamp,
) -> ServiceResult<Takeover> {
    if let Some(ultimo) = database.last_keeper_sign()?
        && continues(&ultimo, taker, now)
    {
        // La chiusura ordinata di prima, se c'è, vale per questo avvio e per
        // nessun altro: si svuota anche qui (ADR-0195).
        database.take_orderly_closure()?;
        let handover_id = database.insert_background_handover(&ultimo, taker, now)?;
        database.record_keeper_sign(taker, now, &ultimo.linked_accounts)?;
        return Ok(Takeover::Continued {
            handover_id,
            accounts: ultimo.linked_accounts,
        });
    }
    let aperte = crate::interruption::detect_all_on_startup(database, now)?;
    database.record_keeper_sign(taker, now, &[])?;
    Ok(Takeover::Interrupted(aperte))
}

/// Scrive il segno di vita di chi tiene l'acquisizione, con gli account che
/// la persona ha collegato.
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce.
pub fn sign(
    database: &Database,
    keeper: Keeper,
    now: Timestamp,
    linked_accounts: &[i64],
) -> ServiceResult<()> {
    database.record_keeper_sign(keeper, now, linked_accounts)?;
    Ok(())
}

/// Lascia l'acquisizione **senza** passarla: chi viene dopo non continua.
///
/// Si chiama quando la persona chiude il programma, o quando il servizio si
/// ferma per lo spegnimento: allora nessuno deve riprendere da sé.
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce.
pub fn release_without_handover(
    database: &Database,
    keeper: Keeper,
    now: Timestamp,
) -> ServiceResult<()> {
    // Un segno di vita vecchio quanto la tolleranza più uno non continua mai.
    let scaduto = Timestamp::from_millis(
        now.as_millis() - lisi_core::model::background::HANDOVER_TOLERANCE_MS - 1,
    );
    database.record_keeper_sign(keeper, scaduto, &[])?;
    Ok(())
}

/// Gli ultimi passaggi di mano.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn recent(database: &Database) -> ServiceResult<Vec<StoredHandover>> {
    Ok(database.background_handovers(SHOWN)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::open_in_memory_database;

    fn archivio() -> Database {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        database
    }

    /// **Il servizio che arriva in tempo continua, e riprende gli account
    /// della persona.**
    #[test]
    fn il_servizio_in_tempo_continua_con_gli_account_della_persona() {
        let mut database = archivio();
        let Ok(()) = sign(
            &database,
            Keeper::Window,
            Timestamp::from_millis(10_000),
            &[7],
        ) else {
            panic!("il segno deve scriversi");
        };
        let esito = take_over(
            &mut database,
            Keeper::Service,
            Timestamp::from_millis(25_000),
        );
        let Ok(Takeover::Continued { accounts, .. }) = esito else {
            panic!("deve essere un passaggio di mano: {esito:?}");
        };
        assert_eq!(accounts, vec![7]);
        let Ok(passaggi) = recent(&database) else {
            panic!("i passaggi devono leggersi");
        };
        assert_eq!(passaggi.len(), 1);
        assert_eq!(
            passaggi[0].taken_at.as_millis() - passaggi[0].released_at.as_millis(),
            15_000
        );
    }

    /// **La persona che chiude il programma non passa la mano**: il servizio
    /// che arriva dopo non riprende nulla.
    #[test]
    fn chi_chiude_il_programma_non_passa_la_mano() {
        let mut database = archivio();
        let Ok(()) =
            release_without_handover(&database, Keeper::Window, Timestamp::from_millis(10_000))
        else {
            panic!("il rilascio deve scriversi");
        };
        let esito = take_over(
            &mut database,
            Keeper::Service,
            Timestamp::from_millis(10_500),
        );
        assert!(matches!(esito, Ok(Takeover::Interrupted(_))), "{esito:?}");
        assert_eq!(
            database.background_handovers(10).map(|p| p.len()).ok(),
            Some(0)
        );
    }

    /// **Dopo un'interruzione il segno di chi ha preso non porta account**:
    /// un passaggio successivo non ne riprende.
    #[test]
    fn dopo_un_interruzione_non_si_riprende_nulla() {
        let mut database = archivio();
        let Ok(Takeover::Interrupted(_)) =
            take_over(&mut database, Keeper::Window, Timestamp::from_millis(1_000))
        else {
            panic!("senza segno di vita è l'avvio di sempre");
        };
        let Ok(Some(segno)) = database.last_keeper_sign() else {
            panic!("il segno di chi ha preso deve esserci");
        };
        assert!(segno.linked_accounts.is_empty());
    }
}

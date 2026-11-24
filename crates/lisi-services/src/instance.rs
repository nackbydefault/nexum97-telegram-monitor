//! Una sola istanza del programma per cartella dati
//! (OPERATOR-E2E-REMEDIATION-01, F-01).
//!
//! # Il difetto che chiude
//!
//! Lo stato del blocco della postazione vive in memoria, nel processo che lo
//! ha fatto scattare. Una seconda copia del programma, aperta con un doppio
//! clic dal menu Start, nasceva **sbloccata** sullo stesso archivio: mostrava
//! Storico e Avvisi a chi passava davanti, mentre la prima, bloccata, continuava
//! a monitorare senza che nulla lo segnalasse. La revisione di sicurezza della
//! correzione di F-01 l'ha indicata come la via più semplice per aggirare il
//! blocco.
//!
//! # Come
//!
//! Un file nella cartella dati del modo del processo, tenuto con un **blocco
//! esclusivo del sistema operativo** finché il processo vive. Il blocco non è
//! una convenzione: Windows lo rilascia anche se il processo termina in modo
//! anomalo, quindi un'uscita brusca non lascia la postazione senza programma.
//!
//! La cartella è quella **del modo** (ADR-0129): l'Esercitazione ha la propria,
//! e una copia in Esercitazione può stare accanto a quella operativa — con il
//! proprio archivio sintetico, senza Telegram.
//!
//! # Che cosa non fa
//!
//! Non impedisce a chi controlla la macchina di terminare il processo e
//! riaprirlo: allora la postazione riparte sbloccata, come è sempre stato
//! dichiarato. Il blocco di NEXUM/97 protegge dal passante; la protezione che
//! regge fra un avvio e l'altro è il blocco di Windows.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

use crate::error::{ServiceError, ServiceResult};

/// Il nome del file tenuto bloccato dall'istanza in corso.
pub const INSTANCE_FILE: &str = "istanza.lock";

/// L'istanza in corso. Finché vive, nessun'altra si apre sulla stessa cartella.
///
/// Il blocco si rilascia quando il valore esce di scena, cioè alla fine del
/// processo: va tenuto per tutta la durata di `run`.
#[derive(Debug)]
pub struct InstanceGuard {
    _file: File,
}

/// Prende l'istanza sulla cartella dati del modo del processo.
///
/// Restituisce `Ok(None)` se un'altra istanza la tiene già.
///
/// # Errori
///
/// Restituisce un errore se la cartella non è determinabile o il file non si
/// apre: il chiamante decide se partire comunque.
pub fn acquire() -> ServiceResult<Option<InstanceGuard>> {
    acquire_in(&crate::data_directory::application_directory()?)
}

/// Come [`acquire`], sulla cartella indicata: il seam delle prove.
///
/// # Errori
///
/// Restituisce un errore se la cartella non si crea o il file non si apre.
pub fn acquire_in(directory: &Path) -> ServiceResult<Option<InstanceGuard>> {
    std::fs::create_dir_all(directory).map_err(|errore| ServiceError::SessionUnavailable {
        reason: format!("cartella dati non creabile: {errore}"),
    })?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(INSTANCE_FILE))
        .map_err(|errore| ServiceError::SessionUnavailable {
            reason: format!(
                "il file che impedisce una seconda copia del programma non si apre: {errore}"
            ),
        })?;
    match file.try_lock() {
        Ok(()) => Ok(Some(InstanceGuard { _file: file })),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(errore)) => Err(ServiceError::SessionUnavailable {
            reason: format!(
                "il file che impedisce una seconda copia del programma non si blocca: {errore}"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::acquire_in;

    /// **Una seconda istanza sulla stessa cartella non si apre, e dopo la
    /// chiusura della prima sì.**
    #[test]
    fn la_seconda_istanza_non_si_apre() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(Some(prima)) = acquire_in(cartella.path()) else {
            panic!("la prima istanza deve aprirsi");
        };
        assert!(
            matches!(acquire_in(cartella.path()), Ok(None)),
            "la seconda istanza non deve aprirsi finché la prima vive"
        );
        drop(prima);
        assert!(
            matches!(acquire_in(cartella.path()), Ok(Some(_))),
            "chiusa la prima, se ne apre un'altra"
        );
    }

    /// **Due cartelle diverse — operativa ed Esercitazione — non si
    /// escludono.**
    #[test]
    fn due_cartelle_diverse_non_si_escludono() {
        let (Ok(operativa), Ok(esercitazione)) = (tempfile::tempdir(), tempfile::tempdir()) else {
            panic!("le cartelle temporanee devono potersi creare");
        };
        let Ok(Some(_prima)) = acquire_in(operativa.path()) else {
            panic!("l'istanza operativa deve aprirsi");
        };
        assert!(matches!(acquire_in(esercitazione.path()), Ok(Some(_))));
    }
}

//! La configurazione dell'applicazione, consumata al primo avvio
//! (APP-CREDENTIALS-01, ADR-0204).
//!
//! Il pacchetto privato, o `Provisioning.ps1` dell'amministratore, mette
//! accanto al programma il file di distribuzione. Qui il programma lo importa
//! nella cartella dei dati, protetto con DPAPI, e lo cancella. Vale per la
//! finestra e per il servizio, che gira con lo stesso utente (ADR-0203): chi
//! parte per primo lo consuma.
//!
//! Il registro delle operazioni dice che cosa è successo, mai i valori.

use lisi_services::Database;
use lisi_services::accounts::AccountService;
use lisi_services::app_credentials::{
    ImportOutcome, distribution_file_beside, import_distribution_file,
};

/// Importa il file di distribuzione, se c'è, e lo registra in `archivio`.
pub fn importa(archivio: Option<Database>) {
    let Ok(programma) = std::env::current_exe() else {
        return;
    };
    let Some(file) = distribution_file_beside(&programma) else {
        return;
    };
    let Ok(cartella) = lisi_services::telegram_runtime::account_data_root() else {
        return;
    };
    let esito = match import_distribution_file(&file, &cartella) {
        Ok(ImportOutcome::Absent) => return,
        Ok(esito) => esito,
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "configurazione dell'applicazione non importata"
            );
            return;
        }
    };
    tracing::info!(esito = ?esito, "configurazione dell'applicazione");
    let (Some(archivio), Ok(autore)) = (archivio, crate::operator::audit_actor()) else {
        return;
    };
    if let Err(errore) = AccountService::new(archivio).record_application_configuration(
        esito,
        &autore,
        lisi_core::time::anchored_now(),
    ) {
        tracing::warn!(
            kind = errore.kind(),
            "importazione della configurazione non registrata"
        );
    }
}

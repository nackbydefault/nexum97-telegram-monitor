//! L'installazione del servizio del monitoraggio in background, chiesta
//! dall'installatore o dalle Impostazioni (SERVICE-01 parte 2, ADR-0203
//! decisione 9).
//!
//! # I comandi
//!
//! - `--installa-servizio`: il processo della persona legge il suo nome di
//!   Windows e chiede i permessi dell'amministratore per un secondo processo;
//! - `--installa-servizio-per <utente>`: il secondo processo, con i permessi,
//!   fa chiedere a Windows la password di quell'utente, la prova e crea il
//!   servizio;
//! - `--rimuovi-servizio` e `--rimuovi-servizio-elevato`: lo stesso per
//!   toglierlo, e soltanto se c'è;
//! - `--ferma-servizio` e `--avvia-servizio`: per l'aggiornamento, senza
//!   permessi dell'amministratore, che l'installazione ha dato all'utente.
//!
//! Il nome dell'utente lo legge il processo della persona, non quello con i
//! permessi: se l'amministratore è un'altra persona, il servizio deve girare
//! comunque con l'utente di chi usa il programma.
//!
//! # Gli esiti
//!
//! Il processo finisce con [`RIUSCITO`], [`RIFIUTATO`] se la persona chiude
//! una finestra, o [`NON_RIUSCITO`]. L'installatore non si ferma per un esito
//! diverso da zero: il prodotto si installa comunque, e lo stato del servizio
//! si legge in Impostazioni.

use lisi_core::model::background::{SERVICE_ARGUMENT, SERVICE_NAME};
use lisi_platform::background_service::{ServiceState, own_account_name, state};
use lisi_platform::service_install::{
    Elevated, ask_password, install, is_elevated, remove, run_elevated, start, stop,
};

/// Il servizio è a posto.
pub const RIUSCITO: i32 = 0;
/// Qualcosa non è riuscito.
pub const NON_RIUSCITO: i32 = 1;
/// La persona ha chiuso la finestra dei permessi o della password.
pub const RIFIUTATO: i32 = 2;

/// Il comando del secondo processo, con i permessi.
const PER: &str = "--installa-servizio-per";

/// Quante volte si può riscrivere una password sbagliata.
const TENTATIVI: usize = 3;

/// Il comando chiesto, se `argomenti` ne contiene uno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comando {
    /// Installare per la persona di questo processo.
    Installa,
    /// Installare per `utente`, con i permessi.
    InstallaPer(String),
    /// Togliere.
    Rimuovi,
    /// Togliere, con i permessi.
    RimuoviElevato,
    /// Fermare, prima di sostituire i file.
    Ferma,
    /// Avviare, dopo averli sostituiti.
    Avvia,
}

/// Legge il comando dagli argomenti del programma.
#[must_use]
pub fn comando(argomenti: &[String]) -> Option<Comando> {
    let mut resto = argomenti.iter().skip(1);
    match resto.next()?.as_str() {
        "--installa-servizio" => Some(Comando::Installa),
        PER => resto
            .next()
            .map(|utente| Comando::InstallaPer(utente.clone())),
        "--rimuovi-servizio" => Some(Comando::Rimuovi),
        "--rimuovi-servizio-elevato" => Some(Comando::RimuoviElevato),
        "--ferma-servizio" => Some(Comando::Ferma),
        "--avvia-servizio" => Some(Comando::Avvia),
        _ => None,
    }
}

/// Esegue il comando e dice l'esito.
#[must_use]
pub fn esegui(comando: &Comando) -> i32 {
    match comando {
        Comando::Installa => match own_account_name() {
            Ok(utente) => con_i_permessi(&[PER, " \"", &utente, "\""].concat()),
            Err(_) => NON_RIUSCITO,
        },
        Comando::InstallaPer(utente) => installa_per(utente),
        Comando::Rimuovi => match state(SERVICE_NAME) {
            Ok(ServiceState::NotInstalled) => RIUSCITO,
            Ok(_) => con_i_permessi("--rimuovi-servizio-elevato"),
            Err(_) => NON_RIUSCITO,
        },
        Comando::RimuoviElevato => esito(remove(SERVICE_NAME).is_ok()),
        Comando::Ferma => esito(stop(SERVICE_NAME).is_ok()),
        Comando::Avvia => esito(start(SERVICE_NAME).is_ok()),
    }
}

fn esito(riuscito: bool) -> i32 {
    if riuscito { RIUSCITO } else { NON_RIUSCITO }
}

/// Avvia questo stesso programma con i permessi dell'amministratore.
fn con_i_permessi(argomenti: &str) -> i32 {
    let Ok(programma) = std::env::current_exe() else {
        return NON_RIUSCITO;
    };
    match run_elevated(&programma, argomenti) {
        Ok(Elevated::Exited(codice)) => i32::try_from(codice).unwrap_or(NON_RIUSCITO),
        Ok(Elevated::Declined) => RIFIUTATO,
        Err(_) => NON_RIUSCITO,
    }
}

/// La riga di comando con cui Windows avvia il servizio.
fn riga_di_comando() -> Option<String> {
    let programma = std::env::current_exe().ok()?;
    Some(format!("\"{}\" {SERVICE_ARGUMENT}", programma.display()))
}

fn installa_per(utente: &str) -> i32 {
    if !is_elevated() {
        return NON_RIUSCITO;
    }
    let Some(comando) = riga_di_comando() else {
        return NON_RIUSCITO;
    };
    let didascalia = crate::lingua::tr("Monitoraggio con Windows chiuso");
    let messaggio = crate::lingua::tr(
        "Scrivere la password di Windows di questo utente. Il monitoraggio continuerà anche \
         quando si esce da Windows. La password la conserva Windows, non il programma.",
    );
    for _ in 0..TENTATIVI {
        match ask_password(utente, didascalia, messaggio) {
            Ok(Some(credenziali)) => {
                return esito(
                    install(
                        SERVICE_NAME,
                        lisi_core::branding::PRODUCT_NAME,
                        crate::lingua::tr(
                            "Continua il monitoraggio quando la persona esce da Windows.",
                        ),
                        &comando,
                        &credenziali,
                    )
                    .is_ok(),
                );
            }
            Ok(None) => return RIFIUTATO,
            Err(_) => {}
        }
    }
    NON_RIUSCITO
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argomenti(resto: &[&str]) -> Vec<String> {
        std::iter::once("programma.exe")
            .chain(resto.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    /// **I comandi si riconoscono**, e senza utente non si installa per
    /// nessuno.
    #[test]
    fn i_comandi_si_riconoscono() {
        assert_eq!(
            comando(&argomenti(&["--installa-servizio"])),
            Some(Comando::Installa)
        );
        assert_eq!(
            comando(&argomenti(&[
                "--installa-servizio-per",
                "UFFICIO\\Mario Rossi"
            ])),
            Some(Comando::InstallaPer("UFFICIO\\Mario Rossi".to_owned()))
        );
        assert_eq!(comando(&argomenti(&["--installa-servizio-per"])), None);
        assert_eq!(
            comando(&argomenti(&["--ferma-servizio"])),
            Some(Comando::Ferma)
        );
        assert_eq!(comando(&argomenti(&["--esercitazione"])), None);
        assert_eq!(comando(&argomenti(&[])), None);
    }

    /// **Fermare e avviare un servizio che non c'è riesce**: è
    /// l'aggiornamento di chi la casella non l'ha scelta.
    #[cfg(windows)]
    #[test]
    fn senza_servizio_fermare_e_avviare_riesce() {
        if state(SERVICE_NAME).ok() == Some(ServiceState::NotInstalled) {
            assert_eq!(esegui(&Comando::Ferma), RIUSCITO);
            assert_eq!(esegui(&Comando::Avvia), RIUSCITO);
            assert_eq!(esegui(&Comando::Rimuovi), RIUSCITO);
        }
    }
}

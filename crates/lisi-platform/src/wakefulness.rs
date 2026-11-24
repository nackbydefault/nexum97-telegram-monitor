// TERZO modulo del crate autorizzato a contenere `unsafe`, dopo `browser` e
// `window_chrome`. La deroga e' esplicita, circoscritta a un solo file e
// visibile in diff (ADR-0003, ADR-0021). Vale solo su Windows.
#![cfg_attr(windows, allow(unsafe_code))]

//! Mantenere il sistema sveglio mentre un monitoraggio e' in corso.
//!
//! # Il problema, e la sua misura
//!
//! In sospensione Windows congela ogni processo: non gira nulla, non si riceve
//! nulla. Un monitoraggio avviato la sera e trovato la mattina ha in realta'
//! smesso di osservare al primo timeout di risparmio energetico - e non lo
//! diceva a nessuno.
//!
//! Non e' il caso raro: e' il caso **normale** su una postazione lasciata
//! accesa, ed e' la ragione per cui un monitoraggio lungo non poteva essere
//! creduto.
//!
//! # Che cosa si chiede al sistema, e che cosa no
//!
//! Si chiede `ES_SYSTEM_REQUIRED`: **il sistema non si sospende**.
//!
//! Non si chiede `ES_DISPLAY_REQUIRED`, che terrebbe acceso anche lo schermo.
//! Uno schermo acceso tutta la notte su una postazione condivisa mostra
//! materiale acquisito a chiunque passi, consuma, e non serve a nulla:
//! l'acquisizione avviene tanto a schermo spento. **Lo schermo si spegne, il
//! sistema resta sveglio.**
//!
//! # Che cosa questo non impedisce
//!
//! Uno **spegnimento voluto**, un riavvio, o una sospensione chiesta
//! esplicitamente dall'operatore. Non e' un modo per impedire a chi usa il
//! computer di spegnerlo: e' un modo per impedire che si addormenti da solo
//! mentre sta lavorando per noi.
//!
//! Non impedisce nemmeno l'ibernazione forzata da una politica aziendale, ne'
//! la chiusura del coperchio su un portatile quando la politica lo impone.
//!
//! # Invarianti di sicurezza
//!
//! 1. `SetThreadExecutionState` riceve **solo costanti note** del sistema;
//!    nessun dato esterno raggiunge la chiamata.
//! 2. Non si passano puntatori: l'unico argomento e' un intero di bandiere.
//! 3. L'esito e' interpretato secondo il contratto documentato — zero significa
//!    fallito — senza dereferenziare nulla.
//! 4. Lo stato e' **per thread** e vale finche' quel thread vive: va chiesto
//!    dal thread dell'interfaccia, che vive quanto l'applicazione. Chiamarlo da
//!    un thread che termina lo lascerebbe cadere senza che nessuno se ne
//!    accorga.
//! 5. Nessuna memoria di Windows viene allocata o liberata.

use crate::error::{PlatformError, PlatformResult};

/// Lo stato richiesto vale finche' non viene cambiato, e non per una sola
/// chiamata.
#[cfg(windows)]
const ES_CONTINUOUS: u32 = 0x8000_0000;

/// Il sistema non deve sospendersi. Lo schermo puo' spegnersi.
#[cfg(windows)]
const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;

/// Chiede al sistema di non sospendersi.
///
/// Va chiamata dal thread dell'interfaccia: lo stato e' per thread e cade con
/// esso.
///
/// # Errori
///
/// Restituisce [`PlatformError::WakefulnessRefused`] se il sistema rifiuta la
/// richiesta. **Non e' fatale**: significa che la postazione potra'
/// sospendersi, non che il monitoraggio sia compromesso — al risveglio
/// riprende, e il recupero della cronologia colma il vuoto.
#[cfg(windows)]
pub fn keep_system_awake() -> PlatformResult<()> {
    set_execution_state(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
}

/// Restituisce al sistema la facolta' di sospendersi.
///
/// Va chiamata all'arresto del monitoraggio. Dimenticarla terrebbe sveglia la
/// postazione per sempre, che e' un difetto silenzioso e antipatico: chi lo
/// subisce non ha modo di collegarlo a questo programma.
///
/// # Errori
///
/// Restituisce [`PlatformError::WakefulnessRefused`] se il sistema rifiuta.
#[cfg(windows)]
pub fn allow_system_sleep() -> PlatformResult<()> {
    set_execution_state(ES_CONTINUOUS)
}

#[cfg(windows)]
fn set_execution_state(flags: u32) -> PlatformResult<()> {
    use windows_sys::Win32::System::Power::SetThreadExecutionState;

    // SAFETY: le invarianti sono in testa al modulo. L'unico argomento e' un
    // intero composto da costanti note; non si passano puntatori e non si
    // alloca nulla. Il valore restituito e' lo stato precedente, confrontato
    // con zero secondo il contratto documentato e mai dereferenziato.
    let previous = unsafe { SetThreadExecutionState(flags) };

    if previous == 0 {
        return Err(PlatformError::WakefulnessRefused);
    }

    Ok(())
}

/// Fuori da Windows non c'e' alcuno stato di esecuzione da chiedere.
#[cfg(not(windows))]
pub fn keep_system_awake() -> PlatformResult<()> {
    Ok(())
}

/// Fuori da Windows non c'e' alcuno stato di esecuzione da restituire.
#[cfg(not(windows))]
pub fn allow_system_sleep() -> PlatformResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{allow_system_sleep, keep_system_awake};

    #[test]
    #[cfg(windows)]
    fn asking_and_releasing_both_succeed_and_leave_the_system_free() {
        // Il test non verifica che la postazione resti sveglia - non e'
        // osservabile da un processo - ma che le due chiamate riescano e che
        // **la seconda venga fatta**. Il difetto vero di questo modulo non e'
        // non tenere sveglio: e' tenere sveglio per sempre dimenticandosi di
        // rilasciare, ed e' un difetto che chi lo subisce non collega mai a
        // questo programma.
        assert!(keep_system_awake().is_ok(), "la richiesta deve riuscire");
        assert!(
            allow_system_sleep().is_ok(),
            "il rilascio deve riuscire, ed e' quello che conta"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn outside_windows_both_are_harmless() {
        assert!(keep_system_awake().is_ok());
        assert!(allow_system_sleep().is_ok());
    }
}

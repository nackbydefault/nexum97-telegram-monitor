//! Il segnale che l'archivio dei contenuti è cambiato fuori dal pompaggio.
//!
//! # Perché esiste (INSTALLED-APP-E2E-01, E2E01-05)
//!
//! Il ridisegno dal vivo di Storico, Monitoraggio e Notifiche parte quando il
//! pompaggio ingerisce qualcosa. Ma i contenuti entrano anche per un comando
//! dell'operatore: l'archiviazione dello storico, il recupero di un periodo, il
//! recupero dopo un'interruzione. Il 16 ottobre, dopo l'archiviazione di 717
//! messaggi, il Monitoraggio diceva ancora «0 contenuti acquisiti», finché non
//! si cambiava schermata.
//!
//! Chi archivia **segna**; il timer del ridisegno **ritira**. Un segnale e non
//! una chiamata, per la stessa ragione di `fresh_content` in `main.rs`: le
//! schermate da ridisegnare nascono dopo i comandi che le cambiano.

use std::cell::Cell;

thread_local! {
    /// Vive sul filo dell'interfaccia, l'unico che archivia per comando e
    /// l'unico che ridisegna.
    static CAMBIATO: Cell<bool> = const { Cell::new(false) };
}

/// Segna che l'archivio dei contenuti è cambiato.
pub fn mark() {
    CAMBIATO.with(|cambiato| cambiato.set(true));
}

/// Ritira il segnale: `true` se qualcuno aveva segnato dall'ultima volta.
pub fn take() -> bool {
    CAMBIATO.with(|cambiato| cambiato.replace(false))
}

#[cfg(test)]
mod tests {
    use super::{mark, take};

    #[test]
    fn il_segnale_si_ritira_una_volta_sola() {
        let _ = take();
        assert!(!take(), "nessuno ha segnato");
        mark();
        mark();
        assert!(take(), "segnato, si ritira");
        assert!(!take(), "ritirato, non si ripete");
    }
}

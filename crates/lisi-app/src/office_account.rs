//! L'account d'ufficio, secondo Telegram, nella pagina Account
//! (NEXUM97-IDENTITY-02, ADR-0153, DG-07, F-140).
//!
//! Un comando chiede a Telegram, con `getMe`, chi è l'account collegato, e la
//! frase del servizio dice la risposta con l'istante della richiesta. Nessun
//! temporizzatore la chiama: si chiede quando qualcuno lo chiede.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::Database;
use slint::ComponentHandle;

use crate::AppWindow;
use crate::account::SharedSession;

/// L'archivio della pagina, con una connessione propria.
pub type SharedOfficeAccount = Rc<RefCell<Database>>;

/// Mostra l'ultima lettura registrata, se c'è.
pub fn refresh(window: &AppWindow, archivio: &SharedOfficeAccount) {
    match lisi_services::office_account::latest(&archivio.borrow()) {
        Ok(Some(lettura)) => {
            window.set_office_account_sentence(crate::lingua::schermo(lettura.as_sentence()));
        }
        Ok(None) => {}
        Err(errore) => {
            tracing::warn!(kind = errore.kind(), "letture dell'account non leggibili");
            window.set_office_account_sentence(crate::lingua::schermo(
                "Le letture dell'account non sono leggibili in questo momento.",
            ));
        }
    }
}

/// Collega il comando.
pub fn wire(window: &AppWindow, archivio: &SharedOfficeAccount, session: &SharedSession) {
    let handle = window.as_weak();
    let archivio = Rc::clone(archivio);
    let session = Rc::clone(session);
    window.on_office_account_read(move || {
        if crate::lock::refuse_while_locked("office_account_read") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let Ok(operatore) = crate::operator::audit_actor() else {
            window.set_office_account_sentence(crate::lingua::schermo(
                "Non si riesce a stabilire chi stia agendo su questa postazione: la lettura non \
                 parte.",
            ));
            return;
        };
        // Il connettore resta dentro i servizi: qui passa solo il runtime
        // dell'account autorizzato (ADR-0010).
        let esito = {
            let mut sessione = session.borrow_mut();
            let mut prestito = archivio.borrow_mut();
            match sessione.runtime_mut() {
                Some(runtime) => lisi_services::office_account::read(
                    Some(runtime.connector_mut()),
                    &mut prestito,
                    &operatore,
                    crate::account::now(),
                ),
                None => lisi_services::office_account::read(
                    None,
                    &mut prestito,
                    &operatore,
                    crate::account::now(),
                ),
            }
        };
        match esito {
            Ok(lettura) => {
                window.set_office_account_sentence(crate::lingua::schermo(lettura.as_sentence()));
            }
            Err(errore) => {
                window
                    .set_office_account_sentence(crate::lingua::schermo(errore.operator_message()));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    const THIS_MODULE: &str = include_str!("office_account.rs");

    /// **La lettura parte soltanto da un comando** (A4, minaccia 14): il
    /// modulo non ha temporizzatori.
    #[test]
    fn la_lettura_parte_soltanto_da_un_comando() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        assert!(
            !produzione.contains("Timer"),
            "nessun temporizzatore chiede getMe"
        );
        assert_eq!(
            produzione.matches("office_account::read(").count(),
            2,
            "le due chiamate del solo gestore, con e senza account"
        );
        assert!(produzione.contains("window.on_office_account_read("));
    }
}

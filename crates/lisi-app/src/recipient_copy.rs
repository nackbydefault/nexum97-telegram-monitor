//! «Copia cifrata per chi riceve» (ENCRYPT-02 parte 3, ADR-0190, DEC-475).
//!
//! Nella schermata Report, dopo che il pacchetto è stato prodotto,
//! l'operatore sceglie il file del certificato di chi lo riceve; la schermata
//! ne mostra titolare, emittente, scadenza e impronta, perché li confronti con
//! chi riceve, e soltanto allora cifra. Questo modulo è l'unico punto
//! dell'interfaccia che parla con [`RecipientCopyService`], e non decide
//! niente di suo.
//!
//! L'archivio sta in un `thread_local`, come quello della firma: scrive il
//! registro delle copie e l'audit.

use std::cell::RefCell;
use std::path::PathBuf;

use lisi_core::Timestamp;
use lisi_services::Database;
use lisi_services::recipient_copy::{RecipientCertificate, RecipientCopyService, read_certificate};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;
use crate::report::SharedReport;

thread_local! {
    /// L'archivio su cui si registrano le copie, aperto all'avvio.
    static ARCHIVIO: RefCell<Option<Database>> = const { RefCell::new(None) };
    /// Il certificato scelto e mostrato, finché non se ne sceglie un altro.
    static SCELTO: RefCell<Option<RecipientCertificate>> = const { RefCell::new(None) };
    /// L'elenco delle impronte dell'ultimo pacchetto di evidenze prodotto.
    static EVIDENZE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Se in questa sessione è stato prodotto un pacchetto di evidenze.
#[must_use]
pub fn has_evidence() -> bool {
    EVIDENZE.with(|evidenze| evidenze.borrow().is_some())
}

/// Ricorda l'ultimo pacchetto di evidenze prodotto, per la sua copia.
pub fn remember_evidence(manifest: PathBuf) {
    EVIDENZE.with(|evidenze| *evidenze.borrow_mut() = Some(manifest));
}

/// Mette a disposizione l'archivio su cui si registrano le copie.
pub fn install(database: Option<Database>) {
    ARCHIVIO.with(|archivio| *archivio.borrow_mut() = database);
}

/// Il certificato, in una riga da confrontare con chi riceve.
fn riga_del_certificato(certificato: &RecipientCertificate) -> String {
    let impronta: String = certificato
        .sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let scadenza =
        Timestamp::from_millis(certificato.not_after_unix.saturating_mul(1000)).to_readable_local();
    format!(
        "Per: {} · emesso da {} · vale fino al {scadenza} · impronta {impronta}. \
         Confrontare titolare e impronta con chi riceve prima della cifratura.",
        certificato.subject, certificato.issuer
    )
}

/// Collega i comandi della schermata.
pub fn wire(window: &AppWindow, screen: &SharedReport) {
    {
        let handle = window.as_weak();
        window.on_recipient_choose(move || {
            if crate::lock::refuse_while_locked("recipient_choose") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            crate::dialogs::ask(
                &window,
                rfd::AsyncFileDialog::new()
                    .set_title("Scegliere il certificato di chi riceve")
                    .add_filter("Certificato", &["cer", "crt", "pem"]),
                crate::dialogs::Pick::File,
                "recipient_choose",
                move |window, file: PathBuf| match read_certificate(&file) {
                    Ok(certificato) => {
                        window.set_recipient_line(SharedString::from(riga_del_certificato(
                            &certificato,
                        )));
                        window.set_recipient_ready(true);
                        window.set_recipient_message(SharedString::new());
                        SCELTO.with(|scelto| *scelto.borrow_mut() = Some(certificato));
                    }
                    Err(frase) => {
                        SCELTO.with(|scelto| *scelto.borrow_mut() = None);
                        window.set_recipient_line(SharedString::new());
                        window.set_recipient_ready(false);
                        window.set_recipient_message(crate::lingua::schermo(format!(
                            "Il certificato non si usa: {frase}"
                        )));
                    }
                },
            );
        });
    }
    {
        let handle = window.as_weak();
        let screen = SharedReport::clone(screen);
        window.on_recipient_encrypt(move |quale| {
            if crate::lock::refuse_while_locked("recipient_encrypt") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let manifest = if quale.as_str() == "evidenze" {
                EVIDENZE.with(|evidenze| evidenze.borrow().clone())
            } else {
                crate::report::produced_manifest(&screen)
            };
            let frase = cifra(manifest);
            window.set_recipient_message(crate::lingua::schermo(frase));
        });
    }
}

/// Cifra il pacchetto appena prodotto per il certificato scelto.
fn cifra(manifest: Option<PathBuf>) -> String {
    let Some(manifest) = manifest else {
        return String::from("Prima va prodotto il pacchetto.");
    };
    let Some(certificato) = SCELTO.with(|scelto| scelto.borrow().clone()) else {
        return String::from("Prima va scelto il certificato di chi riceve.");
    };
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(_) => return String::from(crate::account::NON_SI_SA_CHI_OPERA),
    };
    let adesso = crate::account::now();
    ARCHIVIO
        .with(|archivio| {
            let mut archivio = archivio.borrow_mut();
            let database = archivio.as_mut()?;
            let mut servizio = RecipientCopyService::new(database);
            Some(
                match servizio.encrypt_package(&manifest, &certificato, &attore, adesso) {
                    Ok(esito) => esito.operator_message(),
                    Err(errore) => {
                        tracing::warn!(kind = errore.kind(), "copia per chi riceve rifiutata");
                        errore.operator_message()
                    }
                },
            )
        })
        .unwrap_or_else(|| {
            String::from("L'archivio non è aperto: la copia per chi riceve non è stata scritta.")
        })
}

#[cfg(test)]
mod tests {
    use super::{cifra, riga_del_certificato};
    use lisi_services::recipient_copy::RecipientCertificate;

    #[test]
    fn senza_pacchetto_o_senza_certificato_non_si_cifra_e_lo_si_dice() {
        assert_eq!(cifra(None), "Prima va prodotto il pacchetto.");
        assert_eq!(
            cifra(Some(std::path::PathBuf::from("manifest.txt"))),
            "Prima va scelto il certificato di chi riceve."
        );
    }

    #[test]
    fn la_riga_mostra_titolare_e_impronta_da_confrontare() {
        let riga = riga_del_certificato(&RecipientCertificate {
            subject: String::from("Ufficio destinatario"),
            issuer: String::from("Autorità di prova"),
            not_after_unix: 2_000_000_000,
            sha256: [0xab; 32],
            der: Vec::new(),
        });
        assert!(riga.contains("Ufficio destinatario"));
        assert!(riga.contains(&"ab".repeat(32)));
        assert!(riga.contains("Confrontare"));
    }
}

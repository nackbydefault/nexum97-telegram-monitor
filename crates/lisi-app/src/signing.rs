//! «Firma dell'ufficio» (SIGN-01 parte 4, ADR-0181, DEC-465).
//!
//! In Impostazioni l'amministratore sceglie il certificato con cui firma
//! l'ufficio, fra quelli con una chiave dell'archivio personale di Windows;
//! sotto, gli ultimi tentativi del registro. La schermata Report e quella dei
//! Dizionari chiedono qui la firma, quando l'operatore la vuole: questo modulo
//! è l'unico punto dell'interfaccia che parla con
//! [`DocumentSigningService`], e non decide niente di suo.
//!
//! L'archivio della firma è uno solo per la finestra e sta in un
//! `thread_local`, come quello del blocco: le schermate che firmano sono
//! diverse, la scelta del certificato è una.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::Path;
use std::rc::Rc;

use lisi_core::OperatingMode;
use lisi_services::document_signing::{
    DocumentSigningService, SigningCertificate, StoredDocumentSignature,
};
use lisi_services::{Database, ServiceError, station};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::AppWindow;

/// Quanti tentativi mostra il registro sulla schermata.
const SHOWN_SIGNATURES: usize = 10;

thread_local! {
    /// L'archivio su cui si firma, aperto all'avvio.
    static ARCHIVIO: RefCell<Option<Database>> = const { RefCell::new(None) };
    /// I certificati dell'ultimo elenco mostrato, nell'ordine del selettore.
    static ELENCO: RefCell<Vec<SigningCertificate>> = const { RefCell::new(Vec::new()) };
}

/// Mette a disposizione l'archivio su cui si firma.
pub fn install(database: Option<Database>) {
    ARCHIVIO.with(|archivio| *archivio.borrow_mut() = database);
}

/// Usa il servizio della firma, se l'archivio c'è.
fn con_il_servizio<R>(lavoro: impl FnOnce(&mut DocumentSigningService<'_>) -> R) -> Option<R> {
    ARCHIVIO.with(|archivio| {
        let mut archivio = archivio.borrow_mut();
        let database = archivio.as_mut()?;
        let mut servizio = DocumentSigningService::new(database);
        Some(lavoro(&mut servizio))
    })
}

/// La frase di un rifiuto del servizio, con il genere nel registro tecnico.
fn rifiuto(errore: &ServiceError) -> String {
    tracing::warn!(kind = errore.kind(), "firma dell'ufficio rifiutata");
    errore.operator_message()
}

/// L'impronta in esadecimale minuscolo, come la conserva il registro.
fn impronta(byte: &[u8; 32]) -> String {
    byte.iter().fold(String::with_capacity(64), |mut testo, b| {
        let _ = write!(testo, "{b:02x}");
        testo
    })
}

/// Firma il pacchetto appena prodotto: il manifest, e una copia di ogni PDF.
///
/// Restituisce le frasi degli esiti, una dopo l'altra.
#[must_use]
pub fn sign_report(manifest: &Path, pdfs: &[String]) -> String {
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(_) => return String::from(crate::account::NON_SI_SA_CHI_OPERA),
    };
    let adesso = crate::account::now();
    con_il_servizio(|servizio| {
        let mut frasi = Vec::new();
        match servizio.sign_package(manifest, &attore, adesso) {
            Ok(esito) => frasi.push(format!("Pacchetto. {}", esito.operator_message())),
            // Senza certificato o in Esercitazione non si chiede niente a
            // Windows, e non serve ripeterlo per ogni PDF.
            Err(errore) => return rifiuto(&errore),
        }
        for pdf in pdfs {
            match servizio.sign_report_pdf(manifest, pdf, &attore, adesso) {
                Ok(esito) => frasi.push(format!("«{pdf}». {}", esito.operator_message())),
                Err(errore) => frasi.push(format!("«{pdf}». {}", rifiuto(&errore))),
            }
        }
        frasi.join(" ")
    })
    .unwrap_or_else(|| String::from("L'archivio non è aperto: il pacchetto non è stato firmato."))
}

/// Che cosa si sa della firma accanto a un file, in una frase: manca, è
/// valida e di chi, o perché non lo è.
#[must_use]
pub fn signature_sentence(file: &Path) -> String {
    con_il_servizio(|servizio| servizio.check_signature(file).operator_message())
        .unwrap_or_default()
}

/// Firma un dizionario appena esportato.
#[must_use]
pub fn sign_dictionary(path: &Path) -> String {
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(_) => return String::from(crate::account::NON_SI_SA_CHI_OPERA),
    };
    con_il_servizio(|servizio| {
        match servizio.sign_exported_dictionary(path, &attore, crate::account::now()) {
            Ok(esito) => esito.operator_message(),
            Err(errore) => rifiuto(&errore),
        }
    })
    .unwrap_or_else(|| String::from("L'archivio non è aperto: il dizionario non è stato firmato."))
}

/// Una riga dell'elenco dei certificati, come si sceglie.
fn riga_del_certificato(certificato: &SigningCertificate) -> String {
    let scadenza =
        lisi_core::Timestamp::from_millis(certificato.not_after_unix.saturating_mul(1000))
            .to_readable_local();
    format!(
        "{}, rilasciato da {}, vale fino al {scadenza}",
        certificato.subject, certificato.issuer
    )
}

/// Il registro delle firme, dal più recente, in righe da leggere.
fn signatures_text(righe: &[StoredDocumentSignature]) -> String {
    if righe.is_empty() {
        return String::from("Nessuna firma finora.");
    }
    let mut testo = vec![String::from("Ultimi tentativi:")];
    for riga in righe.iter().take(SHOWN_SIGNATURES) {
        let che_cosa = match riga.kind.as_str() {
            "manifest" => "pacchetto",
            "dizionario" => "dizionario",
            _ => "copia del PDF",
        };
        let mut linea = format!(
            "{} — {}: {che_cosa} «{}», ",
            riga.requested_at.to_readable_local(),
            riga.requested_by,
            riga.file_name
        );
        if riga.outcome == "firmato" {
            linea.push_str("firmato");
            if riga.revocation.as_deref() == Some("non_saputo") {
                linea.push_str(" (la revoca non si è potuta controllare)");
            }
        } else {
            linea.push_str("non firmato");
            if let Some(perche) = &riga.outcome_detail {
                let _ = write!(linea, " ({perche})");
            }
        }
        testo.push(linea);
    }
    testo.join("\n")
}

/// Riporta nella schermata il certificato scelto, l'elenco e il registro.
pub fn refresh(window: &AppWindow) {
    let amministratore = station::persisted_mode_or_restricted() == OperatingMode::Administrator;
    window.set_signing_administrator(amministratore);
    let stato = con_il_servizio(|servizio| {
        let certificati = servizio.certificates();
        let scelto = servizio.chosen_certificate();
        let registro = servizio.signatures();
        (certificati, scelto, registro)
    });
    let Some((certificati, scelto, registro)) = stato else {
        window.set_signing_available(false);
        window.set_signing_chosen(crate::lingua::schermo(
            "L'archivio non è aperto: il programma non firma.",
        ));
        return;
    };

    let righe: Vec<SharedString> = certificati
        .iter()
        .map(|certificato| SharedString::from(riga_del_certificato(certificato)))
        .collect();
    window.set_signing_certificates(ModelRc::from(Rc::new(VecModel::from(righe))));
    window.set_signing_has_certificates(!certificati.is_empty());

    match scelto {
        Ok(Some(scelto)) => {
            let indice = certificati
                .iter()
                .position(|certificato| impronta(&certificato.sha256) == scelto.sha256);
            window.set_signing_index(indice.and_then(|i| i32::try_from(i).ok()).unwrap_or(0));
            let mut frase = format!(
                "Il certificato scelto è quello di «{}». Impronta: {}.",
                scelto.subject, scelto.sha256
            );
            if indice.is_none() {
                frase.push_str(
                    " Su questa postazione e per questo utente di Windows non c'è più. \
                     Finché non torna o non se ne sceglie un altro, il programma non firma.",
                );
            }
            window.set_signing_available(indice.is_some());
            window.set_signing_chosen(crate::lingua::schermo(frase));
        }
        Ok(None) => {
            window.set_signing_index(0);
            window.set_signing_available(false);
            window.set_signing_chosen(crate::lingua::schermo(
                "Nessun certificato scelto: il programma non firma.",
            ));
        }
        Err(errore) => {
            window.set_signing_available(false);
            window.set_signing_chosen(SharedString::from(rifiuto(&errore)));
        }
    }
    let registro = match registro {
        Ok(righe) => signatures_text(&righe),
        Err(errore) => rifiuto(&errore),
    };
    window.set_signing_register(SharedString::from(registro));
    ELENCO.with(|elenco| *elenco.borrow_mut() = certificati);
}

/// Sceglie il certificato in quella posizione dell'elenco, o lo toglie.
fn scegli(indice: Option<i32>) -> String {
    let impronta_scelta = match indice {
        None => None,
        Some(indice) => {
            let trovata = ELENCO.with(|elenco| {
                usize::try_from(indice)
                    .ok()
                    .and_then(|i| elenco.borrow().get(i).map(|c| impronta(&c.sha256)))
            });
            let Some(trovata) = trovata else {
                return String::from(
                    "Nessun certificato in quella posizione: si rilegge l'elenco.",
                );
            };
            Some(trovata)
        }
    };
    let attore = match crate::operator::audit_actor() {
        Ok(attore) => attore,
        Err(_) => return String::from(crate::account::NON_SI_SA_CHI_OPERA),
    };
    let modalita = station::persisted_mode_or_restricted();
    con_il_servizio(|servizio| {
        match servizio.choose_certificate(
            impronta_scelta.as_deref(),
            modalita,
            &attore,
            crate::account::now(),
        ) {
            Ok(()) if impronta_scelta.is_some() => String::from(
                "Certificato scelto. Da adesso il Report e i Dizionari offrono la firma.",
            ),
            Ok(()) => String::from("Certificato tolto: il programma non firma più."),
            Err(errore) => rifiuto(&errore),
        }
    })
    .unwrap_or_else(|| String::from("L'archivio non è aperto: niente è cambiato."))
}

/// Collega i comandi della sezione.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_signing_choose(move |indice| {
            if crate::lock::refuse_while_locked("signing_choose") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = scegli(Some(indice));
            refresh(&window);
            window.set_signing_message(crate::lingua::schermo(frase));
        });
    }
    {
        let handle = window.as_weak();
        window.on_signing_remove(move || {
            if crate::lock::refuse_while_locked("signing_remove") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = scegli(None);
            refresh(&window);
            window.set_signing_message(crate::lingua::schermo(frase));
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_services::document_signing::StoredDocumentSignature;

    use super::{install, sign_dictionary, signatures_text};

    fn riga(kind: &str, outcome: &str, detail: Option<&str>) -> StoredDocumentSignature {
        StoredDocumentSignature {
            id: 1,
            requested_by: String::from("operatore.prova"),
            requested_at: Timestamp::from_millis(1_762_400_000_000),
            kind: String::from(kind),
            file_name: String::from("relazione.pdf"),
            file_sha256: "a".repeat(64),
            certificate_sha256: "b".repeat(64),
            revocation: (outcome == "firmato").then(|| String::from("non_saputo")),
            outcome: String::from(outcome),
            outcome_detail: detail.map(String::from),
        }
    }

    /// **Il registro dice che cosa, se firmato e perché no**, e che la
    /// revoca non si è potuta controllare (ADR-0181, decisione 5).
    #[test]
    fn il_registro_dice_firmato_e_non_firmato_con_il_motivo() {
        assert_eq!(signatures_text(&[]), "Nessuna firma finora.");
        let testo = signatures_text(&[
            riga("pdf", "firmato", None),
            riga(
                "manifest",
                "non_firmato",
                Some("il pacchetto non è integro"),
            ),
        ]);
        assert!(testo.contains("copia del PDF «relazione.pdf», firmato"));
        assert!(testo.contains("la revoca non si è potuta controllare"));
        assert!(
            testo.contains("pacchetto «relazione.pdf», non firmato (il pacchetto non è integro)")
        );
    }

    /// **Senza archivio non si firma, e lo si dice.**
    #[test]
    fn senza_archivio_non_si_firma_e_lo_si_dice() {
        install(None);
        let frase = sign_dictionary(std::path::Path::new("dizionario.json"));
        assert!(frase.contains("non"), "{frase}");
    }
}

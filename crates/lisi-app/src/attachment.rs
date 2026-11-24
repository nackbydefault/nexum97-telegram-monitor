//! La scheda «Conservare l'allegato» di un contenuto, nello Storico e negli
//! Avvisi (ATTACH-01 parte 3, ADR-0177).
//!
//! # Che cosa fa
//!
//! Sotto il contenuto scelto, la frase di ciò che il mittente dichiara e, se
//! l'allegato è conservato, la sua impronta. Il comando apre la scheda con le
//! richieste già registrate e chiede di conservarlo, con la ragione. La
//! richiesta passa dal servizio, che decide i rifiuti e i tetti; qui si mostra
//! ciò che dice.
//!
//! # Che cosa non fa
//!
//! Non legge, non mostra e non apre i byte: nessuna anteprima, nessun «Apri»,
//! nessun file (ADR-0177, decisione 7). La guardia
//! `lisi_services::attachment_keeping::un_allegato_non_si_apre` sorveglia
//! anche questo modulo.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::ContentId;
use lisi_core::model::reason::OperationalReason;
use lisi_services::Database;
use lisi_services::attachment_keeping::{
    AttachmentKeepRequest, KeepAttempt, StoredAttachmentKeeping, describe, keep_attachment,
    keepings,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, AttachmentKeepingEntry};

/// L'archivio della scheda.
pub struct AttachmentScreen {
    archive: Database,
}

/// Condiviso fra i gestori dei comandi.
pub type SharedAttachment = Rc<RefCell<AttachmentScreen>>;

/// Crea la scheda sull'archivio indicato.
#[must_use]
pub fn create_service(archive: Option<Database>) -> Option<SharedAttachment> {
    Some(Rc::new(RefCell::new(AttachmentScreen {
        archive: archive?,
    })))
}

/// La frase che compare una volta, in ambra, sopra le richieste.
pub const CAVEAT: &str = "Il nome e il tipo li dichiara chi ha pubblicato: non dicono che \
                          cosa c'è nel file. Il programma conserva l'allegato con la sua \
                          impronta e non lo apre; conservarlo non vuol dire che sia innocuo.";

/// La frase dell'allegato di un contenuto, per la riga scelta. Vuota se il
/// contenuto non ne ha uno o se l'archivio non si legge: in quel caso il
/// comando non compare, e il registro lo dice.
#[must_use]
pub fn sentence(database: &Database, content_id: ContentId) -> String {
    match describe(database, content_id) {
        Ok(frase) => frase.unwrap_or_default(),
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "descrizione dell'allegato non leggibile"
            );
            String::new()
        }
    }
}

/// Una riga della scheda.
fn entry(richiesta: &StoredAttachmentKeeping) -> AttachmentKeepingEntry {
    let dettaglio = richiesta.outcome_detail.as_deref().unwrap_or_default();
    AttachmentKeepingEntry {
        when: crate::lingua::schermo(format!(
            "Chiesto il {} da {}",
            richiesta.requested_at.to_readable_local(),
            richiesta.requested_by
        )),
        motive: crate::lingua::schermo(format!("Ragione: «{}»", richiesta.reason)),
        outcome: SharedString::from(match richiesta.outcome.as_str() {
            "conservato" if dettaglio.is_empty() => String::from("Conservato"),
            "conservato" => format!("Conservato. {dettaglio}"),
            "fermato" => format!("Fermato da un tetto. {dettaglio}"),
            "rifiutato" => format!("Rifiutato da Telegram. {dettaglio}"),
            _ => format!("Non riuscito. {dettaglio}"),
        }),
        fingerprint: SharedString::from(richiesta.sha256.as_deref().map_or_else(
            String::new,
            |impronta| {
                format!(
                    "{} byte, impronta {impronta}",
                    richiesta.size.unwrap_or_default()
                )
            },
        )),
    }
}

/// Riporta nella scheda la frase e le richieste del contenuto aperto.
pub fn refresh(window: &AppWindow, screen: &SharedAttachment, message: Option<&str>) {
    if let Some(testo) = message {
        window.set_history_attachment_message(SharedString::from(testo));
    }
    let contenuto = window.get_history_attachment_content();
    if !window.get_history_attachment_open() || contenuto < 0 {
        return;
    }
    let contenuto = ContentId::new(i64::from(contenuto));
    let schermata = screen.borrow();
    window.set_history_attachment_sentence(SharedString::from(sentence(
        &schermata.archive,
        contenuto,
    )));
    let righe: Vec<AttachmentKeepingEntry> = match keepings(&schermata.archive, contenuto) {
        Ok(lette) => lette.iter().map(entry).collect(),
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "richieste dell'allegato non leggibili"
            );
            Vec::new()
        }
    };
    window.set_history_attachment_entries(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Chiede di conservare l'allegato del contenuto aperto. Restituisce la frase
/// per l'operatore.
fn ask(window: &AppWindow, screen: &SharedAttachment, session: Option<&SharedSession>) -> String {
    // Prima ciò che l'operatore può correggere nel campo, poi ciò che dipende
    // dalla postazione.
    let motivo = window.get_history_attachment_reason().to_string();
    let Ok(ragione) = OperationalReason::try_new(&motivo) else {
        return format!(
            "Scrivere una ragione operativa fra {} e {} caratteri; quella scritta ne ha {}. Chi \
             rilegge deve sapere perché l'allegato è stato conservato.",
            lisi_core::model::reason::MIN_REASON_CHARS,
            lisi_core::model::reason::MAX_REASON_CHARS,
            motivo.trim().chars().count(),
        );
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione: la richiesta non \
             parte.",
        );
    };
    let Some(session) = session else {
        return String::from(
            "Questa esecuzione non ha la sessione degli account: la richiesta non parte, e non è \
             registrata.",
        );
    };
    let contenuto = ContentId::new(i64::from(window.get_history_attachment_content()));
    // L'autorità si prende e si lascia, come per foto, biografia e stato: il
    // connettore si chiede subito dopo, con un prestito diverso.
    let richiesta = {
        let account = session.borrow();
        let Some(autorita) = account.authority() else {
            return account.refused("La richiesta di conservare l'allegato");
        };
        AttachmentKeepRequest::new(autorita, contenuto, operatore, ragione)
    };
    let mut account = session.borrow_mut();
    let Some(runtime) = account.runtime_mut() else {
        return String::from(
            "Nessun account d'ufficio collegato: la richiesta non parte, e non è registrata.",
        );
    };
    let uuid = runtime.account_uuid().clone();
    let mut screen = screen.borrow_mut();
    match keep_attachment(
        runtime.connector_mut(),
        &uuid,
        &mut screen.archive,
        &richiesta,
        crate::account::now(),
    ) {
        Ok(KeepAttempt::Recorded { outcome, .. }) => match outcome {
            "conservato" => String::from(
                "L'allegato è conservato nell'archivio, con la sua impronta. Il programma non lo \
                 apre.",
            ),
            "fermato" => String::from("Un tetto ha fermato la richiesta; resta registrata."),
            "rifiutato" => String::from("Telegram ha rifiutato; la richiesta resta registrata."),
            _ => String::from(
                "La richiesta non è arrivata a una risposta; resta registrata e si può riprovare.",
            ),
        },
        Ok(KeepAttempt::Refused(frase)) => frase,
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "richiesta dell'allegato non registrata"
            );
            errore.operator_message()
        }
    }
}

/// Chiude la scheda e ne toglie le righe. La frase della descrizione resta:
/// riguarda il contenuto scelto, non la scheda.
pub fn close(window: &AppWindow) {
    window.set_history_attachment_open(false);
    window.set_history_attachment_content(-1);
    window.set_history_attachment_entries(ModelRc::from(Rc::new(VecModel::from(Vec::<
        AttachmentKeepingEntry,
    >::new()))));
}

/// Collega i comandi della scheda.
pub fn wire(window: &AppWindow, screen: &SharedAttachment, session: Option<&SharedSession>) {
    window.set_history_attachment_caveat(crate::lingua::schermo(CAVEAT));
    {
        let weak = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_history_attachment_open_for(move |contenuto| {
            if crate::lock::refuse_while_locked("history_attachment_open_for") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            if contenuto < 0 {
                return;
            }
            window.set_history_attachment_content(contenuto);
            window.set_history_attachment_reason(SharedString::default());
            window.set_history_attachment_open(true);
            refresh(&window, &screen, Some(""));
        });
    }
    {
        let weak = window.as_weak();
        window.on_history_attachment_close(move || {
            if crate::lock::refuse_while_locked("history_attachment_close") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            close(&window);
        });
    }
    {
        let weak = window.as_weak();
        let screen = Rc::clone(screen);
        let session = session.map(Rc::clone);
        window.on_history_attachment_ask(move || {
            if crate::lock::refuse_while_locked("history_attachment_ask") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let frase = ask(&window, &screen, session.as_ref());
            refresh(&window, &screen, Some(&frase));
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::{ContentId, Timestamp};
    use lisi_services::attachment_keeping::StoredAttachmentKeeping;

    fn richiesta(outcome: &str, conservato: bool) -> StoredAttachmentKeeping {
        StoredAttachmentKeeping {
            id: 1,
            content_id: ContentId::new(7),
            account_uuid: None,
            requested_by: String::from("operatore.prova"),
            reason: String::from("Verifica del documento allegato a una minaccia"),
            requested_at: Timestamp::from_millis(1_800_000_000_000),
            outcome: String::from(outcome),
            outcome_detail: (outcome != "conservato").then(|| String::from("FILE_ID_INVALID")),
            size: conservato.then_some(18),
            sha256: conservato.then(|| "a".repeat(64)),
        }
    }

    /// **La riga dice chi ha chiesto, perché, l'esito e, se conservato,
    /// l'impronta; mai i byte** (ATTACH-01 parte 3). Prova negativa: un
    /// rifiuto non ha impronta.
    #[test]
    fn la_riga_dice_la_richiesta_e_l_impronta() {
        let conservata = super::entry(&richiesta("conservato", true));
        assert!(conservata.when.contains("operatore.prova"));
        assert!(conservata.motive.contains("minaccia"));
        assert_eq!(conservata.outcome.as_str(), "Conservato");
        assert_eq!(
            conservata.fingerprint.as_str(),
            format!("18 byte, impronta {}", "a".repeat(64))
        );

        let fermata = super::entry(&richiesta("fermato", false));
        assert!(fermata.outcome.starts_with("Fermato da un tetto."));
        let rifiutata = super::entry(&richiesta("rifiutato", false));
        assert!(rifiutata.outcome.starts_with("Rifiutato da Telegram."));
        assert!(
            rifiutata.fingerprint.is_empty(),
            "un rifiuto non ha impronta"
        );
    }

    /// **La scheda si apre per il contenuto, la richiesta senza ragione o senza
    /// sessione si rifiuta dicendolo, e la chiusura toglie le righe**
    /// (ATTACH-01 parte 3).
    #[test]
    fn la_scheda_si_apre_e_i_rifiuti_si_dicono() {
        use slint::Model;

        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova si costruisce");
        };
        let Ok(archivio) = lisi_services::Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        let Some(screen) = super::create_service(Some(archivio)) else {
            panic!("la scheda nasce");
        };
        super::wire(&window, &screen, None);
        assert_eq!(
            window.get_history_attachment_caveat().as_str(),
            super::CAVEAT
        );
        window.invoke_history_attachment_open_for(7);
        assert!(window.get_history_attachment_open());
        assert_eq!(window.get_history_attachment_content(), 7);
        assert_eq!(window.get_history_attachment_entries().row_count(), 0);

        window.invoke_history_attachment_ask();
        assert!(
            window
                .get_history_attachment_message()
                .contains("ragione operativa"),
            "{}",
            window.get_history_attachment_message()
        );
        window
            .set_history_attachment_reason("Verifica del documento allegato a una minaccia".into());
        window.invoke_history_attachment_ask();
        assert!(
            window
                .get_history_attachment_message()
                .contains("non parte"),
            "{}",
            window.get_history_attachment_message()
        );
        window.invoke_history_attachment_close();
        assert!(!window.get_history_attachment_open());
        assert_eq!(window.get_history_attachment_content(), -1);
    }
}

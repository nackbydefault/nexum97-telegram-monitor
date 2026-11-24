//! Dall'autore di un messaggio alla scheda del soggetto (NEXUM97-IDENTITY-02,
//! ADR-0153, GAP-12, F-135).
//!
//! # Che cosa fa
//!
//! Dove si vede l'autore di un messaggio — la pagina della conversazione e il
//! pannello del messaggio — mostra i soggetti a cui **una persona** ha
//! collegato quell'identificativo, con «Apri la scheda», e «Collega a un
//! soggetto», che porta alla schermata Persone con l'identificativo già
//! scritto.
//!
//! # Che cosa non fa, e una prova lo verifica
//!
//! Non collega nulla e non apre soggetti: il soggetto e il motivo li sceglie
//! l'operatore, con l'atto di PERS-06. Nessuna scrittura parte da qui.

use std::rc::Rc;

use lisi_services::Database;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, AuthorSubjectRow};

/// La schermata Persone.
const PAGINA_PERSONE: i32 = 14;

/// I soggetti collegati a un identificativo, pronti per l'interfaccia.
///
/// Una lettura che non riesce lascia l'elenco vuoto e lo registra: il comando
/// «Collega a un soggetto» resta, e non afferma nulla.
pub fn rows(database: &Database, identifier: &str) -> ModelRc<AuthorSubjectRow> {
    let righe: Vec<AuthorSubjectRow> =
        match lisi_services::subject_record::subjects_linked_to(database, identifier) {
            Ok(soggetti) => soggetti
                .iter()
                .map(|soggetto| AuthorSubjectRow {
                    id: i32::try_from(soggetto.person.get()).unwrap_or(-1),
                    label: SharedString::from(if soggetto.open {
                        soggetto.label.clone()
                    } else {
                        format!("{} (chiuso)", soggetto.label)
                    }),
                })
                .filter(|riga| riga.id > 0)
                .collect(),
            Err(errore) => {
                tracing::warn!(kind = errore.kind(), "soggetti dell'autore non leggibili");
                Vec::new()
            }
        };
    ModelRc::from(Rc::new(VecModel::from(righe)))
}

/// Collega i due comandi.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_author_open_subject(move |id| {
            if crate::lock::refuse_while_locked("author_open_subject") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.invoke_open_page(PAGINA_PERSONE);
            window.set_person_highlight(id);
            // Un'apertura della scheda, nel registro se acceso (ADR-0193).
            crate::consultations::subject_opened(i64::from(id));
            window.set_person_message(crate::lingua::schermo(
                "Aperta dall'autore di un messaggio: la scheda \u{e8} quella evidenziata qui sotto.",
            ));
        });
    }

    {
        let handle = window.as_weak();
        window.on_author_link_subject(move |identificativo| {
            if crate::lock::refuse_while_locked("author_link_subject") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // NESSUN COLLEGAMENTO PARTE DA QUI: si porta l'identificativo dove
            // una persona decide, e lo si dice.
            window.invoke_open_page(PAGINA_PERSONE);
            window.set_person_highlight(0);
            window.set_person_linking(0);
            window.set_person_link_identifier(identificativo.clone());
            window.set_person_message(crate::lingua::schermo(format!(
                "L'identificativo {identificativo} \u{e8} gi\u{e0} scritto. Si sceglie il soggetto \
                 con \u{ab}Collega un'identit\u{e0} osservata\u{bb} e si scrive il motivo. Nulla \u{e8} \
                 stato collegato."
            )));
        });
    }
}

#[cfg(test)]
mod tests {
    const THIS_MODULE: &str = include_str!("author_subject.rs");
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **Dall'autore non parte alcuna scrittura** (C1, minaccia 12).
    #[test]
    fn dall_autore_non_parte_alcuna_scrittura() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        for scrittura in [
            "insert_",
            "record(",
            "link_identity",
            "identity_link::",
            "PersonService",
            "write_note",
            "add_reference",
            "database_mut",
        ] {
            assert!(
                !produzione.contains(scrittura),
                "il modulo chiama «{scrittura}»: dall'autore non si collega nulla da soli"
            );
        }
        assert!(produzione.contains("set_person_link_identifier("));
        assert!(produzione.contains("Nulla \\u{e8} \\\n                 stato collegato."));
    }

    /// **Lo stesso componente nei due posti, e nessun comando per un canale**
    /// (C1, C2).
    #[test]
    fn lo_stesso_componente_nei_due_posti() {
        assert_eq!(UI.matches("AuthorSubjects {\n").count(), 2);
        let Some(inizio) = UI.find("component AuthorSubjects inherits VerticalLayout {") else {
            panic!("il componente deve esistere");
        };
        let Some(fine) = UI[inizio..].find("\n}\n") else {
            panic!("il componente deve chiudersi");
        };
        let componente = &UI[inizio..inizio + fine];
        assert!(
            componente.contains("if root.identifier != \"\": HudButton {"),
            "senza identificativo — un canale — non c'e' alcun comando"
        );
        assert!(componente.contains("Nessuna persona da collegare"));
    }
}

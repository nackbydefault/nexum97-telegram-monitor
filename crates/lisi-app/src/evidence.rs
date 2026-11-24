//! Il pacchetto di evidenze, nella schermata del workspace (PR-11, ADR-0127).
//!
//! # Che cosa fa
//!
//! Elenca i contenuti che il workspace scelto riferisce, ciascuno con una
//! spunta; mostra l'**anteprima** di ciò che uscirà mentre si sceglie; produce
//! il pacchetto soltanto con una ragione scritta, e soltanto dove si hanno i
//! fatti. **Nulla parte da solo**, e nulla che non sia spuntato esce.
//!
//! # Che cosa non fa
//!
//! Non compone i file e non decide che cosa sia un segreto: lo fa il servizio,
//! e le prove lo verificano sul pacchetto prodotto.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use lisi_core::model::reason::OperationalReason;
use lisi_core::model::workspace::ArchiveRefKind;
use lisi_core::{ContentId, WorkspaceId};
use lisi_services::Database;
use lisi_services::evidence_package::{self, EvidenceRequest};
use lisi_services::workspace::WorkspaceService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, EvidenceChoice, EvidencePackageRow};

/// La schermata: una connessione per leggere il workspace, una per produrre.
pub struct EvidenceScreen {
    workspaces: WorkspaceService,
    archive: Database,
    /// Il workspace a cui la scelta appartiene.
    workspace: i64,
    /// I contenuti spuntati, nell'ordine in cui si spuntano.
    chosen: Vec<i64>,
}

/// Schermata condivisa fra i gestori.
pub type SharedEvidence = Rc<RefCell<EvidenceScreen>>;

/// Crea la schermata sulle connessioni indicate.
#[must_use]
pub fn create_service(workspaces: Database, archive: Database) -> SharedEvidence {
    Rc::new(RefCell::new(EvidenceScreen {
        workspaces: WorkspaceService::new(workspaces),
        archive,
        workspace: 0,
        chosen: Vec::new(),
    }))
}

/// Riporta nella schermata le scelte, l'anteprima e i pacchetti prodotti.
pub fn refresh(window: &AppWindow, screen: &SharedEvidence) {
    let selezionato = i64::from(window.get_workspace_selected());
    let mut screen = screen.borrow_mut();
    if screen.workspace != selezionato {
        // Un altro workspace: la scelta ricomincia da capo.
        screen.workspace = selezionato;
        screen.chosen.clear();
        window.set_evidence_message(SharedString::default());
    }
    if selezionato <= 0 {
        window.set_evidence_choices(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_evidence_packages(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_evidence_preview(SharedString::default());
        return;
    }
    let workspace = WorkspaceId::new(selezionato);
    let voci = match screen.workspaces.contents(workspace) {
        Ok((_, elementi)) => elementi,
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "contenuti del workspace non leggibili"
            );
            Vec::new()
        }
    };
    let presenti: Vec<(i64, String)> = voci
        .iter()
        .filter(|voce| {
            voce.entry.item.kind() == ArchiveRefKind::Content && voce.target.is_present()
        })
        .map(|voce| {
            (
                voce.entry.item.target_id(),
                voce.target.as_sentence(ArchiveRefKind::Content),
            )
        })
        .collect();
    // Una spunta su un contenuto che il workspace non riferisce più si toglie.
    let ancora: BTreeSet<i64> = presenti.iter().map(|(id, _)| *id).collect();
    screen.chosen.retain(|id| ancora.contains(id));

    let scelte: Vec<EvidenceChoice> = presenti
        .iter()
        .filter_map(|(id, frase)| {
            Some(EvidenceChoice {
                content_id: i32::try_from(*id).ok()?,
                sentence: SharedString::from(frase.as_str()),
                chosen: screen.chosen.contains(id),
            })
        })
        .collect();
    window.set_evidence_choices(ModelRc::from(Rc::new(VecModel::from(scelte))));

    let scelti: Vec<ContentId> = screen.chosen.iter().copied().map(ContentId::new).collect();
    let anteprima = if scelti.is_empty() {
        String::new()
    } else {
        match evidence_package::preview_selection(&screen.archive, workspace, &scelti) {
            Ok(anteprima) => anteprima.sentence(),
            Err(errore) => errore.operator_message(),
        }
    };
    window.set_evidence_preview(SharedString::from(anteprima));

    let pacchetti: Vec<EvidencePackageRow> =
        match evidence_package::produced(&screen.archive, workspace) {
            Ok(righe) => righe
                .iter()
                .map(|riga| EvidencePackageRow {
                    reference: SharedString::from(riga.package_ref.as_str()),
                    when: SharedString::from(riga.produced_at.to_readable_local()),
                    who: SharedString::from(riga.produced_by.as_str()),
                    count: crate::lingua::schermo(format!("{} contenuti", riga.contents_count)),
                    motive: SharedString::from(riga.reason.as_str()),
                })
                .collect(),
            Err(errore) => {
                tracing::warn!(kind = errore.kind(), "registro dei pacchetti non leggibile");
                Vec::new()
            }
        };
    window.set_evidence_packages(ModelRc::from(Rc::new(VecModel::from(pacchetti))));
}

/// Produce il pacchetto con la scelta di adesso. Restituisce la frase per
/// l'operatore.
fn produce(
    screen: &SharedEvidence,
    session: &SharedSession,
    motivo: &str,
    con_allegati: bool,
) -> String {
    let Ok(ragione) = OperationalReason::try_new(motivo) else {
        return String::from(
            "Serve una ragione scritta: il materiale lascia l'ufficio, e chi rilegge il registro \
             deve sapere perché.",
        );
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from("Non si riesce a stabilire chi stia agendo su questa postazione.");
    };
    let mut screen = screen.borrow_mut();
    let workspace = WorkspaceId::new(screen.workspace);
    let scelti: Vec<ContentId> = screen.chosen.iter().copied().map(ContentId::new).collect();
    // CHI HA I FATTI PRODUCE I DOCUMENTI (TEAM-REPORT-01): senza l'autorità di
    // acquisizione la richiesta non esiste.
    let richiesta = {
        let sessione = session.borrow();
        let Some(autorita) = sessione.authority() else {
            return sessione.refused("Il pacchetto di evidenze");
        };
        match EvidenceRequest::new(autorita, workspace, &scelti, operatore, ragione) {
            // Gli allegati conservati escono soltanto se spuntati (ATTACH-01).
            Ok(richiesta) if con_allegati => richiesta.with_kept_attachments(),
            Ok(richiesta) => richiesta,
            Err(frase) => return String::from(frase),
        }
    };
    let destinazione = match evidence_package::destination(&screen.archive) {
        Ok(cartella) => cartella,
        Err(errore) => return errore.operator_message(),
    };
    match evidence_package::produce(
        &mut screen.archive,
        &richiesta,
        &destinazione,
        crate::account::now(),
    ) {
        Ok(esito) => {
            screen.chosen.clear();
            // La sua copia cifrata per chi riceve (ENCRYPT-02, ADR-0190).
            crate::recipient_copy::remember_evidence(
                esito.directory.join(evidence_package::MANIFEST_FILE),
            );
            format!(
                "Pacchetto {} prodotto, con {} file e l'elenco delle impronte per ultimo, in «{}».",
                esito.package_ref,
                esito.files.len(),
                esito.directory.display()
            )
        }
        Err(errore) => errore.operator_message(),
    }
}

/// Collega i comandi del pacchetto.
pub fn wire(window: &AppWindow, screen: &SharedEvidence, session: &SharedSession) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_evidence_refresh(move || {
            if crate::lock::refuse_while_locked("evidence_refresh") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            refresh(&window, &screen);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_evidence_toggle(move |contenuto| {
            if crate::lock::refuse_while_locked("evidence_toggle") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut screen = screen.borrow_mut();
                let id = i64::from(contenuto);
                if let Some(posizione) = screen.chosen.iter().position(|scelto| *scelto == id) {
                    screen.chosen.remove(posizione);
                } else {
                    screen.chosen.push(id);
                }
            }
            refresh(&window, &screen);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        let session = Rc::clone(session);
        window.on_evidence_produce(move || {
            if crate::lock::refuse_while_locked("evidence_produce") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = produce(
                &screen,
                &session,
                window.get_evidence_reason().as_str(),
                window.get_evidence_with_attachments(),
            );
            window.set_evidence_with_attachments(false);
            window.set_evidence_reason(SharedString::default());
            window.set_evidence_message(crate::lingua::schermo(frase));
            window.set_evidence_produced(crate::recipient_copy::has_evidence());
            refresh(&window, &screen);
        });
    }
}

#[cfg(test)]
mod tests {
    const THIS_MODULE: &str = include_str!("evidence.rs");
    const MAIN: &str = include_str!("main.rs");
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **Il pacchetto parte soltanto dal comando, con una ragione, e la
    /// schermata dice che cosa non è.**
    #[test]
    fn il_pacchetto_parte_soltanto_dal_comando() {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        assert_eq!(codice.matches("evidence_package::produce(").count(), 1);
        assert!(
            !MAIN.contains("evidence::produce"),
            "nessun avvio lo produce"
        );
        // Senza ragione e senza scelta il comando resta spento; in Esercitazione
        // resta spento comunque, e lo dice prima (UX-EXCELLENCE-02, SIM3-10).
        assert!(UI.contains(
            "enabled: !root.exercise-mode && root.evidence-reason != \"\" && root.evidence-preview != \"\";"
        ));
        assert!(crate::surface_text::assegna(
            UI,
            "testo",
            lisi_services::evidence_package::NOT_FORENSIC
        ));
        // Il nome non promette ciò che il pacchetto non è.
        assert!(crate::surface_text::assegna(
            UI,
            "label",
            "Produci il pacchetto di evidenze"
        ));
    }
}

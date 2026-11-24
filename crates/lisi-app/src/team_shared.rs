//! I raccoglitori dell'ufficio (TEAM-WS-01, ADR-0099).
//!
//! # Che cosa mostra
//!
//! Ciò che l'ufficio tiene insieme: i raccoglitori aperti e chiusi, chi li ha
//! aperti, quanti riferimenti hanno raccolto e quali.
//!
//! **Riferimenti, mai testi.** Un raccoglitore dice *che cosa e quale*; il
//! contenuto si chiede uno per volta dalla Revisione condivisa (ADR-0094), e
//! un raccoglitore che portasse i testi sarebbe la copia dell'archivio
//! dell'Hub con un nome diverso.
//!
//! # Chiudere non cancella
//!
//! Un raccoglitore chiuso smette di accettare elementi e **conserva** ciò che
//! ha raccolto: un raccoglitore che si svuotasse chiudendosi perderebbe il
//! lavoro di chi l'ha riempito.
//!
//! # Perché l'accesso si fa altrove
//!
//! L'accesso di una persona vale per **una connessione** (ADR-0097,
//! decisione 6), e questa schermata apre sessioni brevi. Chi vuole scrivere
//! entra dalla Revisione condivisa, che tiene la sessione aperta; qui si vede
//! chi è entrato, e i comandi che richiedono una persona compaiono solo
//! allora.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::hub_notes::{SharedWorkspace, SharedWorkspaceItem};
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::text::{DisplayName, Note};
use lisi_services::Database;
use lisi_services::device_identity::DeviceIdentityService;
use lisi_services::hub_catchup::HubCatchUpService;
use lisi_services::hub_client::{
    HubClientService, HubConnectionStore, HubReviewSession, ReviewSessionOutcome,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::accesso::SharedAccesso;
use crate::{AppWindow, SharedItemRow, SharedWorkspaceRow};

/// Righe che questa schermata chiede.
const RIGHE_A_SCHERMO: usize = 50;

/// Elementi che questa schermata chiede di un raccoglitore.
const ELEMENTI_A_SCHERMO: usize = 200;

/// L'indice della pagina nell'interfaccia.
///
/// Usato solo dalle prove che lo legano al file `.slint`.
#[cfg(test)]
const TEAM_SHARED_PAGE: i32 = 29;

/// Lo stato della schermata.
pub struct TeamShared {
    client: HubClientService,
    /// I raccoglitori, per l'ultima volta che si sono chiesti.
    workspaces: RefCell<Vec<SharedWorkspace>>,
    /// Ciò che un raccoglitore ha raccolto, quando qualcuno l'ha chiesto.
    items: RefCell<Vec<SharedWorkspaceItem>>,
    /// L'esito dell'ultima azione, per l'operatore.
    message: RefCell<String>,
    /// L'accesso di chi è entrato, **lo stesso della Revisione condivisa**.
    accesso: SharedAccesso,
    /// Il raccoglitore di cui si mostrano gli elementi, zero se nessuno
    /// (FINAL-REVIEW-01, FR-050).
    shown: std::cell::Cell<i64>,
}

/// Lo stato condiviso fra i gestori dei comandi.
pub type SharedTeamShared = Rc<TeamShared>;

/// Costruisce la schermata, se l'archivio e le configurazioni sono apribili.
#[must_use]
pub fn create_service(
    client_database: Option<Database>,
    accesso: &SharedAccesso,
) -> Option<SharedTeamShared> {
    let identita = DeviceIdentityService::default_location().ok()?;
    let configurazione = HubConnectionStore::default_location().ok()?;
    let client = HubClientService::new(
        HubCatchUpService::new(client_database?),
        identita,
        configurazione,
    )
    .with_default_office_networks()
    .with_screen_limits();

    Some(Rc::new(TeamShared {
        client,
        workspaces: RefCell::new(Vec::new()),
        items: RefCell::new(Vec::new()),
        message: RefCell::new(String::new()),
        accesso: Rc::clone(accesso),
        shown: std::cell::Cell::new(0),
    }))
}

impl TeamShared {
    /// Apre una sessione, o restituisce la frase che dice perché no.
    fn sessione(&self) -> Result<HubReviewSession, String> {
        match self.client.open_review_session(crate::account::now()) {
            Ok(ReviewSessionOutcome::Ready(sessione)) => Ok(*sessione),
            Ok(altro) => Err(altro
                .refusal_message()
                .unwrap_or_else(|| String::from("Il collegamento all'Hub non si è aperto."))),
            Err(errore) => Err(errore.operator_message()),
        }
    }

    /// Rilegge i raccoglitori dell'ufficio.
    fn reload(&self) -> String {
        let mut sessione = match self.sessione() {
            Ok(sessione) => sessione,
            Err(frase) => return frase,
        };
        let esito = sessione.shared_workspaces(RIGHE_A_SCHERMO);
        sessione.close();

        match esito {
            Ok(Some(raccoglitori)) => {
                let quanti = raccoglitori.len();
                *self.workspaces.borrow_mut() = raccoglitori;
                if quanti == 0 {
                    String::from("L'ufficio non tiene ancora nessun raccoglitore.")
                } else {
                    format!("{quanti} raccoglitori.")
                }
            }
            Ok(None) => {
                self.workspaces.borrow_mut().clear();
                String::from(
                    "Questo Hub non tiene i raccoglitori condivisi: ciò che si raccoglie resta \
                     su ciascuna postazione.",
                )
            }
            Err(errore) => errore.operator_message(),
        }
    }

    /// Apre un raccoglitore.
    ///
    /// Richiede che una persona sia entrata: l'accesso è **lo stesso** della
    /// Revisione condivisa, perché una sola persona per volta siede alla
    /// postazione (ADR-0097, decisione 6).
    fn open(&self, nome: &str, scopo: &str) -> String {
        let Ok(nome) = DisplayName::try_new(nome.trim()) else {
            return String::from("Il nome del raccoglitore non è utilizzabile.");
        };
        let scopo = scopo.trim();
        let descrizione = if scopo.is_empty() {
            None
        } else {
            match Note::try_new(scopo) {
                Ok(descrizione) => Some(descrizione),
                Err(_) => return String::from("La descrizione non è utilizzabile."),
            }
        };

        let esito = self
            .con_persona(|sessione| sessione.open_shared_workspace(&nome, descrizione.as_ref()));
        let frase = esito;
        let _ = self.reload();
        frase
    }

    /// Chiude un raccoglitore. **Non cancella niente.**
    fn close(&self, id: i64) -> String {
        if id <= 0 {
            return String::from("Nessun raccoglitore selezionato.");
        }
        let frase = self.con_persona(|sessione| sessione.close_shared_workspace(id));
        let _ = self.reload();
        frase
    }

    /// Mostra ciò che un raccoglitore ha raccolto.
    fn show_items(&self, id: i64) -> String {
        if id <= 0 {
            return String::from("Nessun raccoglitore selezionato.");
        }
        let mut sessione = match self.sessione() {
            Ok(sessione) => sessione,
            Err(frase) => return frase,
        };
        self.shown.set(id);
        let esito = sessione.workspace_items(id, ELEMENTI_A_SCHERMO);
        sessione.close();

        match esito {
            Ok(Some(elementi)) => {
                let quanti = elementi.len();
                *self.items.borrow_mut() = elementi;
                format!("{quanti} riferimenti raccolti.")
            }
            Ok(None) => {
                self.items.borrow_mut().clear();
                String::from("Questo Hub non tiene i raccoglitori condivisi.")
            }
            Err(errore) => errore.operator_message(),
        }
    }

    /// Mette un riferimento nel raccoglitore mostrato (FINAL-REVIEW-01, FR-050).
    ///
    /// Le richieste esistevano sul filo e l'Hub le serviva: nessun comando le
    /// mandava, e i raccoglitori dell'ufficio restavano vuoti per sempre.
    fn collect(&self, genere: i32, numero: &str) -> String {
        let raccoglitore = self.shown.get();
        if raccoglitore <= 0 {
            return String::from("Mostrare prima che cosa ha raccolto un raccoglitore aperto.");
        }
        let genere = match genere {
            1 => ArchiveRefKind::Source,
            2 => ArchiveRefKind::Report,
            _ => ArchiveRefKind::Content,
        };
        let Ok(numero) = numero.trim().parse::<i64>() else {
            return String::from("Il numero dell'elemento è un numero intero.");
        };
        let Ok(riferimento) = ArchiveRef::to(genere, numero) else {
            return String::from("Il numero dell'elemento non è utilizzabile.");
        };
        let frase =
            self.con_persona(|sessione| sessione.collect_in_workspace(raccoglitore, riferimento));
        let _ = self.show_items(raccoglitore);
        let _ = self.reload();
        frase
    }

    /// Toglie un riferimento dal raccoglitore mostrato (FINAL-REVIEW-01, FR-050).
    fn drop_item(&self, genere: &str, numero: i64) -> String {
        let raccoglitore = self.shown.get();
        let (Ok(genere), true) = (genere.parse::<ArchiveRefKind>(), raccoglitore > 0) else {
            return String::from("Elemento non riconosciuto.");
        };
        let Ok(riferimento) = ArchiveRef::to(genere, numero) else {
            return String::from("Elemento non riconosciuto.");
        };
        let frase =
            self.con_persona(|sessione| sessione.drop_from_workspace(raccoglitore, riferimento));
        let _ = self.show_items(raccoglitore);
        let _ = self.reload();
        frase
    }

    /// Fa una scrittura **dentro l'accesso di chi è entrato**.
    ///
    /// Senza persona non si scrive: un raccoglitore aperto da nessuno non ha
    /// un autore, e la schermata lo dice invece di aprire una sessione
    /// anonima in cui l'atto verrebbe rifiutato con parole più oscure.
    fn con_persona<F>(&self, azione: F) -> String
    where
        F: FnOnce(
            &mut HubReviewSession,
        ) -> lisi_services::error::ServiceResult<
            Option<lisi_services::hub_client::ReviewSubmission>,
        >,
    {
        let Some(esito) = self.accesso.con_sessione(azione) else {
            return String::from(
                "Per aprire o cambiare un raccoglitore occorre prima entrare come persona, \
                 dalla Revisione condivisa.",
            );
        };

        match esito {
            Ok(Some(risposta)) => risposta.detail,
            Ok(None) => String::from("Questo Hub non tiene i raccoglitori condivisi."),
            Err(errore) => errore.operator_message(),
        }
    }
}

/// Riporta nell'interfaccia i raccoglitori e ciò che hanno raccolto.
pub fn refresh(window: &AppWindow, service: &SharedTeamShared) {
    let righe: Vec<SharedWorkspaceRow> = service
        .workspaces
        .borrow()
        .iter()
        .map(|raccoglitore| SharedWorkspaceRow {
            id: i32::try_from(raccoglitore.id).unwrap_or(i32::MAX),
            name: SharedString::from(raccoglitore.name.as_str()),
            description: SharedString::from(
                raccoglitore
                    .description
                    .as_ref()
                    .map_or("", |testo| testo.as_str()),
            ),
            state: crate::lingua::schermo(raccoglitore.state.label()),
            open: raccoglitore.state.accepts_items(),
            summary: crate::lingua::schermo(format!(
                "{} riferimenti · aperto da persona.{} il {}",
                raccoglitore.items,
                raccoglitore.opened_by,
                raccoglitore.opened_at.to_readable_local()
            )),
        })
        .collect();
    window.set_shared_workspaces(ModelRc::from(Rc::new(VecModel::from(righe))));

    let elementi: Vec<SharedItemRow> = service
        .items
        .borrow()
        .iter()
        .map(|elemento| SharedItemRow {
            what: crate::lingua::schermo(format!(
                "{} {}",
                elemento.item.kind().as_label(),
                elemento.item.target_id()
            )),
            kind: SharedString::from(elemento.item.kind().as_str()),
            target: i32::try_from(elemento.item.target_id()).unwrap_or(0),
            added: crate::lingua::schermo(format!(
                "raccolto da persona.{} il {}",
                elemento.added_by,
                elemento.added_at.to_readable_local()
            )),
        })
        .collect();
    window.set_shared_items(ModelRc::from(Rc::new(VecModel::from(elementi))));
    let mostrato = service.shown.get();
    let aperto = service
        .workspaces
        .borrow()
        .iter()
        .any(|raccoglitore| raccoglitore.id == mostrato && raccoglitore.state.accepts_items());
    window.set_shared_shown_workspace(i32::try_from(mostrato).unwrap_or(0));
    window.set_shared_shown_open(aperto);

    window.set_shared_message(SharedString::from(service.message.borrow().clone()));
    window.set_shared_person(SharedString::from(
        service
            .accesso
            .person()
            .map_or_else(String::new, |persona| String::from(persona.as_str())),
    ));
}

/// Collega i comandi della schermata al servizio.
pub fn wire(window: &AppWindow, service: &SharedTeamShared) {
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_shared_shown(move || {
            let esito = service.reload();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_shared_refresh(move || {
            if crate::lock::refuse_while_locked("shared_refresh") {
                return;
            }
            let esito = service.reload();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_shared_open(move |nome, scopo| {
            if crate::lock::refuse_while_locked("shared_open") {
                return;
            }
            let esito = service.open(nome.as_str(), scopo.as_str());
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_shared_close(move |id| {
            if crate::lock::refuse_while_locked("shared_close") {
                return;
            }
            let esito = service.close(i64::from(id));
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_shared_show_items(move |id| {
            if crate::lock::refuse_while_locked("shared_show_items") {
                return;
            }
            let esito = service.show_items(i64::from(id));
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_shared_collect(move || {
            if crate::lock::refuse_while_locked("shared_collect") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let esito = service.collect(
                window.get_shared_collect_kind(),
                window.get_shared_collect_number().as_str(),
            );
            window.set_shared_collect_number(SharedString::new());
            *service.message.borrow_mut() = esito;
            refresh(&window, &service);
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_shared_drop(move |genere, numero| {
            if crate::lock::refuse_while_locked("shared_drop") {
                return;
            }
            let esito = service.drop_item(genere.as_str(), i64::from(numero));
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::TEAM_SHARED_PAGE;

    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **Un raccoglitore dell'ufficio si riempie e si svuota dalla schermata**
    /// (FINAL-REVIEW-01, FR-050): le richieste esistevano e nessun comando le
    /// mandava.
    #[test]
    fn a_shared_binder_can_be_filled_and_emptied() {
        const QUESTO_FILE: &str = include_str!("team_shared.rs");
        assert!(UI.contains("callback shared-collect();"));
        assert!(UI.contains("callback shared-drop(string, int);"));
        assert!(UI.contains("root.shared-collect();"));
        assert!(UI.contains("root.shared-drop(elemento.kind, elemento.target);"));
        let Some((produzione, _)) = QUESTO_FILE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere le sue prove");
        };
        assert!(produzione.contains("window.on_shared_collect("));
        assert!(produzione.contains("window.on_shared_drop("));
        assert!(produzione.contains("sessione.collect_in_workspace(raccoglitore, riferimento)"));
        assert!(produzione.contains("sessione.drop_from_workspace(raccoglitore, riferimento)"));
    }

    #[test]
    fn the_shared_page_index_matches_the_interface() {
        assert!(
            UI.contains(&format!("current-page == {TEAM_SHARED_PAGE}: Rectangle")),
            "la pagina dei raccoglitori con indice {TEAM_SHARED_PAGE} non è nell'interfaccia"
        );
        assert!(
            UI.contains(&format!("root.open-page({TEAM_SHARED_PAGE});")),
            "la voce di menu non naviga all'indice {TEAM_SHARED_PAGE}"
        );
    }

    /// **Un raccoglitore non mostra testi.**
    ///
    /// La pagina dice *che cosa e quale*. Se qualcuno vi aggiungesse il corpo
    /// di un contenuto, il raccoglitore diventerebbe la copia dell'archivio
    /// dell'Hub con un nome diverso (ADR-0099, decisione 5).
    #[test]
    fn a_workspace_shows_references_and_never_texts() {
        let pagina = crate::page_guard::corpo_della_pagina(
            u32::try_from(TEAM_SHARED_PAGE).unwrap_or_default(),
        );
        // Si guardano le righe che MOSTRANO qualcosa: «body» compare anche nei
        // nomi dei caratteri (`Typography.body`), e vietare la parola ovunque
        // sarebbe una guardia che non guarda ciò che crede.
        for riga in pagina.lines().map(str::trim) {
            if !riga.starts_with("text:") {
                continue;
            }
            for vietato in ["body", "corpo"] {
                assert!(
                    !riga.contains(vietato),
                    "la pagina dei raccoglitori mostra «{vietato}»: un raccoglitore porta \
                     riferimenti, mai testi — «{riga}»"
                );
            }
        }
    }
}

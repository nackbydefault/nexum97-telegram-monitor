//! «Iscritti» di una fonte, nella schermata Fonti, e la scelta
//! dell'amministratore in Impostazioni (MEMBERS-01, ADR-0201).
//!
//! La richiesta passa dal servizio, che decide i rifiuti: elenco non
//! abilitato, fonte senza identificativo, richiesta troppo vicina alla
//! precedente. Qui si mostra ciò che dice. Il telefono arriva già mascherato.

use std::cell::{Cell, RefCell};

use lisi_core::model::reason::OperationalReason;
use lisi_core::{OperatingMode, SourceId};
use lisi_services::members_listing::{
    MembersListingAttempt, MembersListingRequest, StoredMemberRow, StoredMembersListing, choose,
    enabled, outcome_sentence, recent, request_members, rows,
};
use lisi_services::{Database, station};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::AppWindow;
use crate::account::SharedSession;

thread_local! {
    /// L'archivio della sezione, aperto all'avvio.
    static ARCHIVIO: RefCell<Option<Database>> = const { RefCell::new(None) };
    /// La fonte di cui il pannello è aperto.
    static FONTE: Cell<Option<i64>> = const { Cell::new(None) };
}

/// Mette a disposizione l'archivio.
pub fn install(database: Option<Database>) {
    ARCHIVIO.with(|cella| *cella.borrow_mut() = database);
}

fn con_l_archivio<R>(lavoro: impl FnOnce(&mut Database) -> R) -> Option<R> {
    ARCHIVIO.with(|cella| cella.borrow_mut().as_mut().map(lavoro))
}

/// Una riga dell'elenco, per la schermata.
fn riga(iscritto: &StoredMemberRow) -> SharedString {
    let mut parti = vec![iscritto.user_id.to_string()];
    if let Some(nome) = &iscritto.display_name {
        parti.push(nome.clone());
    }
    if let Some(nome_utente) = &iscritto.username {
        parti.push(format!("@{nome_utente}"));
    }
    parti.push(iscritto.status.clone());
    if let Some(telefono) = &iscritto.masked_phone {
        parti.push(telefono.clone());
    }
    SharedString::from(parti.join("  ·  "))
}

/// Una richiesta registrata, in una frase.
fn storia(richiesta: &StoredMembersListing) -> String {
    let esito = outcome_sentence(
        &richiesta.outcome,
        richiesta.outcome_detail.as_deref(),
        richiesta.declared_total,
        usize::try_from(richiesta.received).unwrap_or(0),
        richiesta.stopped_at_cap,
    );
    format!(
        "{}: {} per la fonte n. {}, motivo «{}». {esito}",
        richiesta.requested_at.to_readable_local(),
        richiesta.requested_by,
        richiesta.source_id,
        richiesta.reason
    )
}

/// Riporta in schermata la scelta, e l'elenco della fonte aperta.
pub fn refresh(window: &AppWindow) {
    let modalita = station::persisted_mode_or_restricted();
    window.set_members_administrator(modalita == OperatingMode::Administrator);
    let abilitato = con_l_archivio(|archivio| enabled(archivio)).and_then(Result::ok);
    window.set_members_enabled(abilitato == Some(true));
    window.set_members_state(crate::lingua::schermo(match abilitato {
        Some(true) => {
            "Abilitato: dalla schermata Fonti si possono chiedere gli iscritti di un \
                       gruppo, con un motivo ogni volta."
        }
        Some(false) => "Spento: gli iscritti delle fonti non si chiedono.",
        None => "L'archivio non è aperto: la scelta non si legge.",
    }));
    let Some(fonte) = FONTE.with(Cell::get) else {
        return;
    };
    let dati = con_l_archivio(|archivio| {
        let richieste = recent(archivio).unwrap_or_default();
        let ultima = richieste
            .iter()
            .find(|richiesta| richiesta.source_id == fonte)
            .cloned();
        let righe = ultima
            .as_ref()
            .and_then(|richiesta| rows(archivio, richiesta.id).ok())
            .unwrap_or_default();
        (richieste, ultima, righe)
    });
    let Some((richieste, ultima, righe)) = dati else {
        return;
    };
    window.set_members_summary(crate::lingua::schermo(ultima.as_ref().map_or_else(
        String::new,
        |richiesta| {
            format!(
                "Ultima richiesta per questa fonte, {}: {}",
                richiesta.requested_at.to_readable_local(),
                outcome_sentence(
                    &richiesta.outcome,
                    richiesta.outcome_detail.as_deref(),
                    richiesta.declared_total,
                    righe.len(),
                    richiesta.stopped_at_cap,
                )
            )
        },
    )));
    let elenco: Vec<SharedString> = righe.iter().map(riga).collect();
    window.set_members_rows(ModelRc::new(VecModel::from(elenco)));
    let registro: Vec<String> = richieste.iter().map(storia).collect();
    window.set_members_history(SharedString::from(if registro.is_empty() {
        String::new()
    } else {
        format!("Richieste registrate:\n{}", registro.join("\n"))
    }));
}

/// Abilita o spegne l'elenco.
fn scegli(abilita: bool) -> String {
    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let modalita = station::persisted_mode_or_restricted();
    con_l_archivio(|archivio| {
        choose(archivio, abilita, modalita, &attore, crate::account::now())
            .unwrap_or_else(|errore| errore.operator_message())
    })
    .unwrap_or_else(|| String::from("L'archivio non è aperto: niente è cambiato."))
}

/// Chiede gli iscritti della fonte aperta. Restituisce la frase per
/// l'operatore.
fn chiedi(window: &AppWindow, session: Option<&SharedSession>) -> String {
    let Some(fonte) = FONTE.with(Cell::get) else {
        return String::from("Nessuna fonte scelta.");
    };
    let motivo = window.get_members_reason().to_string();
    let Ok(ragione) = OperationalReason::try_new(&motivo) else {
        return format!(
            "Il motivo va scritto, da {} a {} caratteri; ora ne ha {}.",
            lisi_core::model::reason::MIN_REASON_CHARS,
            lisi_core::model::reason::MAX_REASON_CHARS,
            motivo.trim().chars().count(),
        );
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let Some(session) = session else {
        return String::from(
            "Questa esecuzione non ha la sessione degli account: la richiesta non parte, e non è \
             registrata.",
        );
    };
    let richiesta = {
        let account = session.borrow();
        let Some(autorita) = account.authority() else {
            return account.refused("La richiesta degli iscritti");
        };
        MembersListingRequest::new(autorita, SourceId::new(fonte), operatore, ragione)
    };
    let mut account = session.borrow_mut();
    let Some(runtime) = account.runtime_mut() else {
        return String::from(
            "Nessun account d'ufficio collegato: la richiesta non parte, e non è registrata.",
        );
    };
    let uuid = runtime.account_uuid().clone();
    let esito = con_l_archivio(|archivio| {
        request_members(
            runtime.connector_mut(),
            Some(&uuid),
            archivio,
            &richiesta,
            crate::account::now(),
        )
    });
    match esito {
        None => String::from("L'archivio non è aperto: la richiesta non parte."),
        Some(Ok(MembersListingAttempt::Recorded { sentence, .. })) => {
            format!("Richiesta registrata. {sentence}")
        }
        Some(Ok(MembersListingAttempt::Refused(frase))) => frase,
        Some(Err(errore)) => {
            tracing::warn!(
                kind = errore.kind(),
                "richiesta degli iscritti non registrata"
            );
            errore.operator_message()
        }
    }
}

/// Collega i comandi della sezione e del pannello.
pub fn wire(window: &AppWindow, session: Option<&SharedSession>) {
    {
        let handle = window.as_weak();
        window.on_members_open_for(move |fonte, nome| {
            if crate::lock::refuse_while_locked("members_open_for") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            FONTE.with(|cella| cella.set(Some(i64::from(fonte))));
            window.set_members_title(crate::lingua::schermo(format!("Iscritti di {nome}")));
            window.set_members_reason(SharedString::default());
            window.set_members_message(SharedString::default());
            window.set_members_open(true);
            refresh(&window);
        });
    }
    {
        let handle = window.as_weak();
        window.on_members_close(move || {
            if crate::lock::refuse_while_locked("members_close") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            FONTE.with(|cella| cella.set(None));
            window.set_members_open(false);
            window.set_members_rows(ModelRc::default());
        });
    }
    {
        let handle = window.as_weak();
        let session = session.cloned();
        window.on_members_request(move || {
            if crate::lock::refuse_while_locked("members_request") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = chiedi(&window, session.as_ref());
            refresh(&window);
            window.set_members_message(crate::lingua::schermo(frase));
        });
    }
    {
        let handle = window.as_weak();
        window.on_members_enable(move || {
            if crate::lock::refuse_while_locked("members_enable") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                scelta_in_schermata(&window, true);
            }
        });
    }
    {
        let handle = window.as_weak();
        window.on_members_disable(move || {
            if crate::lock::refuse_while_locked("members_disable") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                scelta_in_schermata(&window, false);
            }
        });
    }
}

/// Abilita o spegne, e lo riporta in schermata.
fn scelta_in_schermata(window: &AppWindow, abilita: bool) {
    let frase = scegli(abilita);
    refresh(window);
    window.set_members_choice_message(crate::lingua::schermo(frase));
}

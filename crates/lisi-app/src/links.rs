//! Collegamento fra i comandi «Apri collegamento» e il servizio dei link.
//!
//! Non contiene logica: raccoglie l'URL dall'interfaccia e lo passa al servizio,
//! che lo valida, lo apre nel browser e ne lascia traccia (ADR-0018). Il
//! destinatario dell'apertura è quello di sistema.

use std::rc::Rc;

use lisi_services::links::{LinkService, SystemLinkOpener};

use crate::AppWindow;

/// Servizio dei collegamenti condiviso dal gestore.
pub type SharedLinks = Rc<LinkService>;

/// Crea il servizio dei collegamenti sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedLinks> {
    Some(Rc::new(LinkService::new(database)))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> lisi_services::ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Collega il comando di apertura al servizio.
pub fn wire(window: &AppWindow, links: &SharedLinks) {
    let links = Rc::clone(links);
    window.on_open_url(move |url| {
        if crate::lock::refuse_while_locked("open_url") {
            return;
        }
        let opener = SystemLinkOpener;
        let outcome =
            actor().and_then(|actor| links.open_url(url.as_str(), &actor, now(), &opener));
        if let Err(error) = outcome {
            // Un URL non apribile non è un guasto dell'applicazione: si registra
            // e non si mostra nulla di allarmante. Il motivo è privo dell'URL.
            tracing::warn!(kind = error.kind(), "collegamento non aperto");
        }
    });
}

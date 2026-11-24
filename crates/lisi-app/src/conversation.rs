//! La pagina della conversazione, aperta dal messaggio (ADR-0151, DG-01).
//!
//! # Che cosa fa questo modulo
//!
//! Porta nell'interfaccia ciò che [`lisi_services::conversation`] compone: la
//! prova dell'archivio, i messaggi attorno caricati a pagine, lo stato di ogni
//! lato, il collegamento ufficiale chiesto al momento, e la fotografia di
//! CTX-06. Non compone frasi proprie: le compongono i servizi (DEC-252).
//!
//! # Un solo ingresso
//!
//! Ogni schermata che apre una conversazione — Avvisi, Storico, Coda di
//! lavoro, Raccoglitori, Segnalibri, Grafo — chiama lo stesso gestore con
//! l'identificativo del contenuto: il bersaglio è lo stesso per costruzione
//! (F-119, GAP-10).
//!
//! # Che cosa NON fa
//!
//! **Non scrive niente su Telegram**: il connettore non ha alcun metodo che lo
//! faccia (`lisi-telegram::prohibitions`). **Non scrive niente nell'archivio**
//! guardando o caricando: l'unico atto è la fotografia, esplicita e motivata.

use std::rc::Rc;

use lisi_services::conversation::{Conversation, Direction};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::history::SharedHistory;
use crate::{AppWindow, ContextRow, SnapshotRow};

/// L'istante di adesso.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Collega i comandi della pagina.
pub fn wire(window: &AppWindow, screens: &SharedHistory, session: Option<&SharedSession>) {
    {
        // UN GESTO, LO STESSO BERSAGLIO DA OGNI INGRESSO (ADR-0151, decisione 2).
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let session = session.map(Rc::clone);
        window.on_conversation_open_requested(move |content_id, origin| {
            if crate::lock::refuse_while_locked("conversation_open_requested") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            open(
                &window,
                &screens,
                session.as_ref(),
                content_id,
                origin.as_str(),
            );
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_conversation_close(move || {
            if crate::lock::refuse_while_locked("conversation_close") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close(&window, &screens);
            }
        });
    }

    {
        // UN'ALTRA PAGINA DI PRECEDENTI (F-112): dal piu' vecchio gia' mostrato.
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let session = session.map(Rc::clone);
        window.on_conversation_load_older(move || {
            if crate::lock::refuse_while_locked("conversation_load_older") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                load(&window, &screens, session.as_ref(), Direction::Older);
            }
        });
    }

    {
        // UN'ALTRA PAGINA DI SUCCESSIVI: dal piu' recente gia' mostrato.
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let session = session.map(Rc::clone);
        window.on_conversation_load_newer(move || {
            if crate::lock::refuse_while_locked("conversation_load_newer") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                load(&window, &screens, session.as_ref(), Direction::Newer);
            }
        });
    }

    {
        // IL COLLEGAMENTO UFFICIALE, chiesto al momento e mai conservato
        // (DG-02, F-110, F-111).
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        let session = session.map(Rc::clone);
        window.on_conversation_request_link(move |content_id| {
            if crate::lock::refuse_while_locked("conversation_request_link") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                request_link(&window, &screens, session.as_ref(), content_id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let screens = Rc::clone(screens);
        window.on_conversation_take_snapshot(move |reason| {
            if crate::lock::refuse_while_locked("conversation_take_snapshot") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                take_snapshot(&window, &screens, reason.as_str());
            }
        });
    }
}

/// Apre la conversazione di un contenuto.
///
/// # Perché la pagina si apre anche quando Telegram non risponde
///
/// Perché la prova è nell'archivio (ADR-0151, decisione 5): il servizio
/// restituisce la conversazione con la lacuna e il perché, e la pagina li dice.
/// Soltanto un archivio che non si legge la tiene chiusa, e allora la frase
/// resta nella schermata da cui si è partiti.
fn open(
    window: &AppWindow,
    screens: &SharedHistory,
    session: Option<&SharedSession>,
    content_id: i32,
    origin: &str,
) {
    if content_id <= 0 {
        return;
    }
    let id = lisi_core::ContentId::new(i64::from(content_id));
    // Un'apertura della conversazione, nel registro se acceso (ADR-0193).
    crate::consultations::content_opened(i64::from(content_id));

    // Il connettore resta dentro i servizi: qui passa solo il runtime
    // dell'account autorizzato (ADR-0010).
    let esito = {
        let schermate = screens.borrow();
        let database = schermate.database();
        match session {
            Some(session) => {
                let mut sessione = session.borrow_mut();
                match sessione.runtime_mut() {
                    Some(runtime) => lisi_services::conversation::open(
                        database,
                        Some(runtime.connector_mut()),
                        id,
                        now(),
                    ),
                    None => lisi_services::conversation::open(database, None, id, now()),
                }
            }
            None => lisi_services::conversation::open(database, None, id, now()),
        }
    };

    let conversazione = match esito {
        Ok(conversazione) => conversazione,
        Err(errore) => {
            window.set_history_message(crate::lingua::schermo(errore.operator_message()));
            return;
        }
    };

    // Una pagina nuova non eredita nulla della precedente: ne' il collegamento
    // chiesto per un altro messaggio, ne' la ragione scritta per un'altra
    // fotografia.
    window.set_conversation_link_sentence(SharedString::default());
    window.set_conversation_link_url(SharedString::default());
    window.set_conversation_snapshot_reason(SharedString::default());
    window.set_conversation_snapshot_message(SharedString::default());
    window.set_conversation_origin(SharedString::from(origin));
    // LA PAGINA PUBBLICA DELLA FONTE (ADR-0165, decisione 4): offerta quando il
    // collegamento al messaggio non c'e'. Un indirizzo che non si legge non
    // offre nulla.
    let pagina = lisi_services::message_link::source_page(screens.borrow().database(), id)
        .ok()
        .flatten();
    window.set_conversation_source_url(SharedString::from(
        pagina.as_ref().map_or("", |pagina| pagina.url.as_str()),
    ));
    window.set_conversation_source_sentence(SharedString::from(
        pagina.map_or_else(String::new, |pagina| pagina.sentence),
    ));

    show(window, &conversazione);
    refresh_snapshots(window, screens, id);
    // DALL'AUTORE AL SOGGETTO (GAP-12): i soggetti collegati da una persona.
    let identificativo = conversazione
        .facts()
        .author_identifier
        .clone()
        .unwrap_or_default();
    window.set_conversation_author_subjects(crate::author_subject::rows(
        screens.borrow().database(),
        &identificativo,
    ));
    window.set_conversation_author_identifier(SharedString::from(identificativo));
    screens.borrow_mut().conversazione = Some(conversazione);
    window.set_conversation_open(true);

    // IL MESSAGGIO AL CENTRO, A PAGINA DISPOSTA (decisione 3). La pagina nasce
    // dopo questo gestore: si chiede di centrare un istante dopo, quando le
    // righe hanno la loro altezza.
    let ancora = window.as_weak();
    slint::Timer::single_shot(std::time::Duration::from_millis(150), move || {
        if let Some(window) = ancora.upgrade() {
            window.set_conversation_centre_request(
                window.get_conversation_centre_request().wrapping_add(1),
            );
        }
    });
}

/// Chiude la pagina e dimentica ciò che si stava guardando.
///
/// Tenerlo dopo la chiusura permetterebbe di conservare, un momento dopo, ciò
/// che non è più davanti agli occhi di nessuno (CTX-06). La schermata da cui si
/// è partiti resta com'era: la pagina le stava sopra.
fn close(window: &AppWindow, screens: &SharedHistory) {
    screens.borrow_mut().conversazione = None;
    window.set_conversation_open(false);
    window.set_conversation_older_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
    window.set_conversation_newer_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
    window.set_conversation_summary(SharedString::default());
    window.set_conversation_anchor(SharedString::default());
    window.set_conversation_anchor_now(SharedString::default());
    // Anche l'esito del confronto si svuota: un'etichetta rimasta da un altro
    // contenuto direbbe, per un istante, che i testi di QUESTO non coincidono.
    window.set_conversation_comparison_label(SharedString::default());
    window.set_conversation_texts_differ(false);
    window.set_conversation_link_sentence(SharedString::default());
    window.set_conversation_link_url(SharedString::default());
    window.set_conversation_snapshot_reason(SharedString::default());
    window.set_conversation_snapshot_message(SharedString::default());
    window.set_conversation_snapshot_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
    window.set_conversation_source_url(SharedString::default());
    window.set_conversation_source_sentence(SharedString::default());
}

/// Chiede a Telegram un'altra pagina da un lato.
///
/// Se l'apertura non aveva potuto leggere il contorno, caricare un lato non
/// basta: si riapre, e il messaggio dell'avviso torna a confrontarsi con ciò
/// che Telegram mostra adesso.
fn load(
    window: &AppWindow,
    screens: &SharedHistory,
    session: Option<&SharedSession>,
    direzione: Direction,
) {
    let (riaprire, contenuto) = {
        let schermate = screens.borrow();
        let Some(conversazione) = schermate.conversazione.as_ref() else {
            return;
        };
        (
            conversazione.needs_reopen(),
            conversazione.context().anchor.content_id,
        )
    };
    if riaprire {
        let origine = window.get_conversation_origin();
        let numero = i32::try_from(contenuto.get()).unwrap_or_default();
        open(window, screens, session, numero, origine.as_str());
        return;
    }

    let mut schermate = screens.borrow_mut();
    let Some(conversazione) = schermate.conversazione.as_mut() else {
        return;
    };
    match session {
        Some(session) => {
            let mut sessione = session.borrow_mut();
            match sessione.runtime_mut() {
                Some(runtime) => conversazione.load(Some(runtime.connector_mut()), direzione),
                None => conversazione.load(None, direzione),
            }
        }
        None => conversazione.load(None, direzione),
    };
    show(window, conversazione);
}

/// Una riga della conversazione, come la pagina la disegna.
fn row(messaggio: &lisi_services::context::ObservedMessage) -> ContextRow {
    ContextRow {
        when: SharedString::from(messaggio.published_at.to_readable_local()),
        text: SharedString::from(messaggio.text_to_show()),
        is_anchor: messaggio.is_anchor,
        // CHI E A CHE COSA SI LEGA: due frasi gia' composte dal servizio
        // (DEC-252). Qui non arriva alcuna struttura da interpretare.
        who: SharedString::from(messaggio.who.as_str()),
        relations: SharedString::from(messaggio.relations.as_deref().unwrap_or_default()),
        number: SharedString::from(messaggio.remote_message_id.as_str()),
    }
}

/// Porta nella pagina ciò che il servizio ha composto.
fn show(window: &AppWindow, conversazione: &Conversation) {
    let fatti = conversazione.facts();
    let contesto = conversazione.context();

    window.set_conversation_source_name(SharedString::from(fatti.source_name.as_str()));
    window.set_conversation_source_line(crate::lingua::schermo(format!(
        "{}  \u{b7}  identificativo {}",
        fatti.source_kind, fatti.source_identifier
    )));
    window.set_conversation_author(SharedString::from(fatti.author.as_str()));
    window.set_conversation_archived_url(SharedString::from(
        fatti.archived_url.as_deref().unwrap_or_default(),
    ));
    window.set_conversation_published(SharedString::from(
        contesto.anchor.published_at.to_readable_local(),
    ));
    window.set_conversation_acquired(SharedString::from(
        contesto.anchor.acquired_at.to_readable_local(),
    ));
    window.set_conversation_observed(SharedString::from(contesto.observed_at.to_readable_local()));
    window.set_conversation_content_id(
        i32::try_from(contesto.anchor.content_id.get()).unwrap_or_default(),
    );
    window.set_conversation_message_number(SharedString::from(
        contesto.anchor.remote_message_id.as_str(),
    ));

    // La frase la compone il servizio e non la ricompone la schermata
    // (DEC-252): dice per esteso che il contorno non e' una prova.
    window.set_conversation_summary(crate::lingua::schermo(conversazione.as_sentence()));
    window.set_conversation_anchor(SharedString::from(contesto.anchor.body.as_str()));
    match conversazione.anchor_now() {
        Some(adesso) => {
            window.set_conversation_anchor_now(SharedString::from(adesso.text.as_str()));
            window.set_conversation_anchor_now_when(SharedString::from(
                adesso.published_at.to_readable_local(),
            ));
        }
        None => {
            window.set_conversation_anchor_now(SharedString::default());
            window.set_conversation_anchor_now_when(SharedString::default());
        }
    }

    // IL CONFRONTO, COMPOSTO DAL MODELLO (CTX-05). Vuoto quando non e' stato
    // fatto — che non e' «coincidono».
    window.set_conversation_comparison_label(SharedString::from(contesto.comparison.map_or(
        "",
        lisi_core::model::context_state::ContextComparison::as_label,
    )));
    window.set_conversation_texts_differ(
        contesto
            .comparison
            .is_some_and(|confronto| confronto.divergence().texts_differ()),
    );

    let precedenti: Vec<ContextRow> = conversazione
        .messages(Direction::Older)
        .into_iter()
        .map(row)
        .collect();
    let successivi: Vec<ContextRow> = conversazione
        .messages(Direction::Newer)
        .into_iter()
        .map(row)
        .collect();
    window.set_conversation_older_rows(ModelRc::from(Rc::new(VecModel::from(precedenti))));
    window.set_conversation_newer_rows(ModelRc::from(Rc::new(VecModel::from(successivi))));

    window.set_conversation_older_state(crate::lingua::schermo(
        conversazione.side_sentence(Direction::Older),
    ));
    window.set_conversation_newer_state(crate::lingua::schermo(
        conversazione.side_sentence(Direction::Newer),
    ));
    window.set_conversation_can_load_older(
        conversazione.side(Direction::Older).can_load() || conversazione.needs_reopen(),
    );
    window.set_conversation_can_load_newer(
        conversazione.side(Direction::Newer).can_load() || conversazione.needs_reopen(),
    );
}

/// Chiede a Telegram il collegamento ufficiale al messaggio (DG-02).
///
/// Come la conversazione, il servizio riceve il runtime dell'account
/// autorizzato, se c'è, e non scrive nulla. Nessun indirizzo si compone.
fn request_link(
    window: &AppWindow,
    screens: &SharedHistory,
    session: Option<&SharedSession>,
    content_id: i32,
) {
    let id = lisi_core::ContentId::new(i64::from(content_id));
    let esito = {
        let schermate = screens.borrow();
        let database = schermate.database();
        match session {
            Some(session) => {
                let mut sessione = session.borrow_mut();
                match sessione.runtime_mut() {
                    Some(runtime) => lisi_services::message_link::request(
                        database,
                        Some(runtime.connector_mut()),
                        id,
                        now(),
                    ),
                    None => lisi_services::message_link::request(database, None, id, now()),
                }
            }
            None => lisi_services::message_link::request(database, None, id, now()),
        }
    };

    match esito {
        Ok(richiesta) => {
            window.set_conversation_link_sentence(crate::lingua::schermo(richiesta.as_sentence()));
            window
                .set_conversation_link_url(SharedString::from(richiesta.url().unwrap_or_default()));
        }
        Err(errore) => {
            window.set_conversation_link_url(SharedString::default());
            window
                .set_conversation_link_sentence(crate::lingua::schermo(errore.operator_message()));
        }
    }
}

/// Rilegge le fotografie già prese di un contenuto e le mostra.
///
/// Ognuna porta l'esito della propria verifica: una fotografia che non si
/// verifica va **detta**, e chi la legge non deve ricordarsi di chiederlo.
fn refresh_snapshots(
    window: &AppWindow,
    screens: &SharedHistory,
    content_id: lisi_core::ContentId,
) {
    let esito = lisi_services::context_snapshot::taken_of(screens.borrow().database(), content_id);
    let Ok(fotografie) = esito else {
        // Una lettura che non riesce non si nasconde: l'elenco resta vuoto e la
        // frase lo dice, invece di far credere che non ce ne siano.
        window.set_conversation_snapshot_message(crate::lingua::schermo(
            "Le fotografie gi\u{e0} prese non sono leggibili in questo momento: l'elenco qui \
             sotto non dice che non ce ne siano.",
        ));
        window.set_conversation_snapshot_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let righe: Vec<SnapshotRow> = fotografie
        .iter()
        .map(|fotografia| SnapshotRow {
            // LA FRASE LA COMPONE IL SERVIZIO (DEC-252).
            sentence: crate::lingua::schermo(fotografia.as_sentence()),
            intact: fotografia.intact,
        })
        .collect();
    window.set_conversation_snapshot_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Conserva la conversazione che si sta guardando.
///
/// # Che cosa questa funzione NON fa
///
/// **Non rilegge nulla da Telegram.** Conserva ciò che era stato mostrato —
/// tutti i messaggi caricati — tenuto in memoria: rileggerlo qui conserverebbe
/// qualcosa che nessuno ha guardato.
fn take_snapshot(window: &AppWindow, screens: &SharedHistory, reason: &str) {
    let Some(contesto) = screens
        .borrow()
        .conversazione
        .as_ref()
        .map(|conversazione| conversazione.context().clone())
    else {
        window.set_conversation_snapshot_message(crate::lingua::schermo(
            "Non c'\u{e8} alcuna conversazione aperta da conservare.",
        ));
        return;
    };

    let (Ok(attore), Ok(ragione)) = (
        crate::operator::audit_actor(),
        lisi_core::text::Note::try_new(reason),
    ) else {
        // Una ragione che non supera la validazione del dominio: la frase e'
        // quella del servizio, perche' il difetto e' lo stesso.
        window.set_conversation_snapshot_message(crate::lingua::schermo(
            lisi_services::ServiceError::SnapshotNeedsReason.operator_message(),
        ));
        return;
    };

    let content_id = contesto.anchor.content_id;
    let esito = {
        let mut prestito = screens.borrow_mut();
        lisi_services::context_snapshot::take(
            prestito.database_mut(),
            &contesto,
            &attore,
            &ragione,
            now(),
        )
    };

    match esito {
        Ok(_) => {
            // La ragione si svuota: lasciarla scritta inviterebbe a premere di
            // nuovo, e la seconda fotografia porterebbe la ragione della prima.
            window.set_conversation_snapshot_reason(SharedString::default());
            // UNA FOTOGRAFIA VUOTA SI DICE (ADR-0166, CA02-03).
            window.set_conversation_snapshot_message(SharedString::from(
                lisi_services::context_snapshot::taken_sentence(&contesto),
            ));
        }
        Err(errore) => {
            window.set_conversation_snapshot_message(crate::lingua::schermo(
                errore.operator_message(),
            ));
        }
    }

    refresh_snapshots(window, screens, content_id);
}

/// Le guardie della pagina della conversazione (ADR-0151), con quelle di
/// CTX-03…CTX-06 che stavano sul riquadro del contesto e ora la sorvegliano.
#[cfg(test)]
mod tests {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il trait del connettore: è lì che la sola lettura è garantita.
    const CONNETTORE: &str = include_str!("../../lisi-telegram/src/connector.rs");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("conversation.rs");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il corpo di una funzione del codice di produzione.
    ///
    /// Estrattore senza ripiego: se non trova la fine si ferma, invece di
    /// restituire il resto del file e rendere cieca la guardia (SIM-01).
    fn corpo(firma: &str) -> String {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find(firma) else {
            panic!("la funzione «{firma}» deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione «{firma}» deve chiudersi");
        };
        codice[inizio..inizio + fine].to_owned()
    }

    /// La pagina della conversazione.
    fn pagina() -> &'static str {
        let Some(inizio) = UI.find("component ConversationPage inherits Rectangle {") else {
            panic!("la pagina della conversazione deve esistere");
        };
        let Some(fine) = UI[inizio..].find("\ncomponent ContentScreen inherits Rectangle {") else {
            panic!("la pagina deve avere una fine riconoscibile");
        };
        &UI[inizio..inizio + fine]
    }

    /// Una riga della conversazione.
    fn riga() -> &'static str {
        let Some(inizio) = UI.find("component ConversationRow inherits Rectangle {") else {
            panic!("la riga della conversazione deve esistere");
        };
        let Some(fine) = UI[inizio..].find("component ConversationPage inherits Rectangle {")
        else {
            panic!("la riga deve avere una fine riconoscibile");
        };
        &UI[inizio..inizio + fine]
    }

    /// Il riquadro del messaggio dell'avviso.
    fn riquadro_della_prova() -> &'static str {
        let vista = pagina();
        let Some(inizio) = vista.find("ancora := Rectangle {") else {
            panic!("il riquadro della prova deve esistere");
        };
        let Some(fine) = vista[inizio..].find("for riga in root.newer-rows:") else {
            panic!("il riquadro deve finire prima dei successivi");
        };
        &vista[inizio..inizio + fine]
    }

    /// **La sola lettura non è una convenzione: il connettore non sa scrivere.**
    #[test]
    fn il_connettore_non_ha_alcun_metodo_che_scrive() {
        let firme: Vec<&str> = CONNETTORE
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("fn "))
            .collect();
        assert!(!firme.is_empty(), "il trait deve dichiarare dei metodi");

        for firma in firme {
            for scrittura in [
                "fn send",
                "fn react",
                "fn join",
                "fn leave",
                "fn edit",
                "fn delete",
                "fn post",
                "fn forward",
                "fn repost",
                "fn add_member",
                "fn set_reaction",
            ] {
                assert!(
                    !firma.starts_with(scrittura),
                    "il connettore dichiara «{firma}»: la conversazione \u{e8} di sola lettura \
                     perche' non c'e' nulla da chiamare, e questo lo rimetterebbe"
                );
            }
        }
    }

    /// **La pagina non offre alcun comando che scriva su Telegram** (F-109).
    #[test]
    fn la_pagina_non_offre_alcun_comando_che_scrive() {
        for riga in pagina()
            .lines()
            .chain(riga().lines())
            .map(str::trim)
            .filter(|riga| riga.starts_with("label:") || riga.starts_with("text: \""))
        {
            for vietato in [
                "Invia",
                "Rispondi",
                "Reagisci",
                "Modifica",
                "Elimina",
                "Unisciti",
                "Partecipa",
                "Inoltra",
                "Commenta",
                "Segnala a Telegram",
            ] {
                assert!(
                    !riga.contains(vietato),
                    "la pagina offre «{vietato}»: e' di sola lettura — «{riga}»"
                );
            }
        }
    }

    /// **La prova sta in un riquadro suo, al centro della conversazione**
    /// (ADR-0151, decisione 3; sostituisce «prima del contorno» di CTX-03).
    #[test]
    fn la_prova_sta_in_un_riquadro_suo_al_centro() {
        let vista = pagina();
        let (Some(precedenti), Some(prova), Some(successivi)) = (
            vista.find("for riga in root.older-rows:"),
            vista.find("text: root.context-anchor;"),
            vista.find("for riga in root.newer-rows:"),
        ) else {
            panic!("precedenti, prova e successivi devono comparire");
        };
        assert!(precedenti < prova, "la prova viene dopo i precedenti");
        assert!(prova < successivi, "la prova viene prima dei successivi");

        let riquadro = riquadro_della_prova();
        assert!(
            riquadro.contains("text: root.context-anchor;"),
            "la prova sta nel suo riquadro"
        );
        assert!(
            riquadro.contains("DALL'ARCHIVIO"),
            "il riquadro della prova deve dire da dove viene"
        );
        assert!(
            riquadro.contains("border-color: Palette.cyan;"),
            "il riquadro si distingue a vista, non soltanto per il titolo"
        );
    }

    /// **Ciò che Telegram mostra adesso sta accanto alla prova, mai al posto
    /// suo** (F-117).
    #[test]
    fn il_testo_di_adesso_sta_accanto_alla_prova() {
        let riquadro = riquadro_della_prova();
        let (Some(prova), Some(adesso)) = (
            riquadro.find("text: root.context-anchor;"),
            riquadro.find("text: root.anchor-now;"),
        ) else {
            panic!("i due testi devono comparire nel riquadro");
        };
        assert!(prova < adesso, "prima la prova, poi come si legge adesso");
        assert!(
            riquadro.contains("if root.anchor-now != \"\": Rectangle {"),
            "il testo di adesso compare soltanto se Telegram lo ha restituito"
        );
        assert!(
            riquadro.contains("COME SI LEGGE ADESSO SU TELEGRAM"),
            "il testo di adesso dice che cosa e'"
        );
    }

    /// **La frase che dice «non è una prova» si legge, e la compone il servizio.**
    #[test]
    fn la_frase_del_servizio_si_legge_e_non_si_ricompone() {
        let vista = pagina();
        let (Some(frase), Some(prova)) = (
            vista.find("text: root.context-summary;"),
            vista.find("text: root.context-anchor;"),
        ) else {
            panic!("la frase e la prova devono esserci");
        };
        assert!(
            frase < prova,
            "che cosa si sta guardando si legge prima di cio' che si guarda"
        );

        let codice = codice_senza_commenti();
        assert!(
            codice.contains("crate::lingua::schermo(conversazione.as_sentence())"),
            "la frase la compone il servizio, non la schermata"
        );
        for ricomposizione in ["non e' una prova", "non \u{e8} una prova", "stato corrente"] {
            assert!(
                !codice.contains(ricomposizione),
                "la schermata scrive «{ricomposizione}»: ricomporrebbe cio' che il servizio \
                 dichiara gia'"
            );
        }
    }

    /// **Guardare e caricare non scrivono niente** (criterio 10).
    #[test]
    fn guardare_e_caricare_non_scrivono_niente() {
        for firma in ["fn open(", "fn load(", "fn show(", "fn close("] {
            let corpo = corpo(firma);
            for scrittura in [
                "insert_",
                "append_audit",
                "record(",
                "save_",
                "update_",
                "database_mut",
                "context_snapshot::take",
            ] {
                assert!(
                    !corpo.contains(scrittura),
                    "«{firma}» chiama «{scrittura}»: guardare non e' un atto di cui qualcuno \
                     risponda"
                );
            }
        }
    }

    /// **La pagina non compare se nessuno la chiede.**
    #[test]
    fn la_pagina_non_compare_se_nessuno_la_chiede() {
        assert!(
            UI.contains("in-out property <bool> conversation-open: false;"),
            "la pagina deve partire chiusa"
        );
        assert!(
            UI.contains("if root.conversation-open: ConversationPage {"),
            "la pagina si disegna soltanto aperta"
        );
    }

    /// **Un gesto, lo stesso bersaglio da ogni ingresso** (F-105, F-119,
    /// GAP-10; criterio 1).
    ///
    /// Ogni ingresso passa l'identificativo del contenuto allo stesso
    /// gestore: un ingresso che passasse altro — la posizione della riga, un
    /// numero di messaggio — aprirebbe un bersaglio diverso senza che nulla lo
    /// dicesse.
    #[test]
    fn ogni_ingresso_apre_lo_stesso_bersaglio() {
        for ingresso in [
            "root.open-conversation(entry.content-id);",
            "root.open-conversation(root.selected);",
            "root.conversation-open-requested(content-id, \"Avvisi\");",
            "root.conversation-open-requested(content-id, \"Storico\");",
            "root.conversation-open-requested(riga.content-id, \"Coda di lavoro\");",
            "root.conversation-open-requested(voce.target-id, \"Raccoglitori\");",
            "root.conversation-open-requested(segno.target-id, \"Segnalibri\");",
            "root.conversation-open-requested(root.graph-centre-content, \"Grafo\");",
            // CONTEXT-02 (ADR-0165, DG-01): da Segnali cyber e da Persone.
            "root.conversation-open-requested(entry.first-content-id, \"Segnali cyber\");",
            "root.conversation-open-requested(voce.content-id, \"Persone\");",
            // CYBER-EVENTS-02 (ADR-0189): dagli eventi candidati dell'archivio.
            "root.conversation-open-requested(candidato.first-content-id, \"Segnali cyber\");",
        ] {
            assert_eq!(
                UI.matches(ingresso).count(),
                1,
                "l'ingresso «{ingresso}» deve esistere, e una volta sola"
            );
        }
        assert_eq!(
            UI.matches("root.conversation-open-requested(").count(),
            9,
            "nove ingressi diretti, e nessun altro che sfugga a questa prova"
        );
        assert_eq!(
            codice_senza_commenti()
                .matches("window.on_conversation_open_requested(")
                .count(),
            1,
            "un gestore solo apre la conversazione"
        );
    }

    /// **Dalla riga, con un gesto: non si sceglie prima la riga** (DG-01).
    #[test]
    fn dalla_riga_si_apre_con_un_gesto() {
        let Some(inizio) = UI.find("conversa-riga := HudButton {") else {
            panic!("il comando della riga deve esistere");
        };
        let Some(fine) = UI[inizio..].find("accessible-role: button;") else {
            panic!("il comando della riga deve chiudersi");
        };
        let comando = &UI[inizio..inizio + fine];
        assert!(comando.contains("root.open-conversation(entry.content-id);"));
        assert!(
            !comando.contains("root.select("),
            "aprire la conversazione non passa per la scelta della riga"
        );
    }

    /// **Esc torna indietro, le frecce scorrono** (F-108; criterio 12).
    #[test]
    fn la_tastiera_scorre_e_torna_indietro() {
        let vista = pagina();
        for tasto in [
            "Key.Escape",
            "Key.UpArrow",
            "Key.DownArrow",
            "Key.PageUp",
            "Key.PageDown",
            "Key.Home",
            "Key.End",
        ] {
            assert!(
                vista.contains(&format!("event.text == {tasto}")),
                "la pagina deve rispondere a {tasto}"
            );
        }
        assert!(vista.contains("init => {\n        pagina.focus();"));
        assert!(
            vista.contains("focus-on-click: false;"),
            "un clic sul testo non deve spendersi per prendere il fuoco"
        );
    }

    /// **Una voce del menu chiude la pagina** (criterio 12).
    #[test]
    fn una_voce_del_menu_chiude_la_pagina() {
        let Some((_, dopo)) = UI.split_once("public function open-page(page: int) {") else {
            panic!("la funzione open-page deve esistere");
        };
        let Some((corpo, _)) = dopo.split_once("\n    }\n") else {
            panic!("la funzione open-page deve chiudersi");
        };
        assert!(corpo.contains("if (root.conversation-open) {"));
        assert!(corpo.contains("root.conversation-close();"));
    }

    /// **Il messaggio si porta al centro, a pagina disposta** (F-106;
    /// criterio 3).
    #[test]
    fn il_messaggio_si_porta_al_centro() {
        let vista = pagina();
        assert!(vista.contains("changed centre-request => {"));
        assert!(
            vista.contains("-(ancora.y + ancora.height / 2 - filo.view-height / 2)"),
            "il centro e' quello del riquadro della prova"
        );
        assert!(
            crate::surface_text::assegna(vista, "label", "Torna al messaggio"),
            "chi ha scorso deve poter tornare al messaggio"
        );
        assert!(
            corpo("fn open(").contains("set_conversation_centre_request("),
            "aprire chiede di centrare"
        );
    }

    /// **A postazione bloccata la pagina non si vede e non risponde.**
    #[test]
    fn la_pagina_rispetta_il_blocco() {
        let Some(inizio) = UI.find("if root.conversation-open: ConversationPage {") else {
            panic!("la pagina deve essere usata");
        };
        let Some(fine) = UI[inizio..].find("origin: root.conversation-origin;") else {
            panic!("l'uso della pagina deve avere le sue proprieta'");
        };
        assert!(
            UI[inizio..inizio + fine].contains("visible: !root.station-locked;"),
            "la pagina si nasconde sotto il blocco"
        );
        let codice = codice_senza_commenti();
        let gestori = codice.matches("window.on_conversation_").count();
        let rifiuti = codice.matches("crate::lock::refuse_while_locked(").count();
        assert!(gestori >= 5, "i gestori devono esserci");
        assert!(
            rifiuti >= 5,
            "ogni gestore rifiuta a postazione bloccata ({rifiuti} rifiuti, {gestori} gestori)"
        );
    }

    /// **I metadati appartengono alla riga che descrivono.**
    #[test]
    fn i_metadati_stanno_dentro_la_riga_che_descrivono() {
        let riga = riga();
        assert!(riga.contains("text: root.riga.who;"));
        assert!(riga.contains("text: root.riga.relations;"));
        assert!(
            riga.contains("@tr(\"{}  ·  n. {}\", root.riga.when, root.riga.number)"),
            "ora e numero del messaggio stanno nella riga"
        );
    }

    /// **Chi ha scritto si legge dopo che cosa è scritto** (CTX-04).
    #[test]
    fn chi_ha_scritto_si_legge_dopo_che_cosa_e_scritto() {
        let riga = riga();
        let (Some(testo), Some(autore), Some(relazioni)) = (
            riga.find("text: root.riga.text;"),
            riga.find("text: root.riga.who;"),
            riga.find("text: root.riga.relations;"),
        ) else {
            panic!("le tre parti della riga devono esistere");
        };
        assert!(testo < autore, "che cosa e' scritto viene prima di chi");
        assert!(autore < relazioni, "a che cosa si lega viene dopo chi");
    }

    /// **Una relazione assente non disegna una riga vuota.**
    #[test]
    fn una_relazione_assente_non_lascia_una_riga_vuota() {
        assert!(riga().contains("if root.riga.relations != \"\": Text {"));
    }

    /// **L'autore, invece, si scrive sempre** (ADR-0053).
    #[test]
    fn l_autore_si_scrive_sempre_anche_quando_non_c_e() {
        assert!(!riga().contains("if root.riga.who != \"\":"));
    }

    /// **La schermata non ricompone le relazioni** (DEC-252).
    #[test]
    fn la_schermata_non_ricompone_le_relazioni() {
        let codice = codice_senza_commenti();
        for ricomposizione in [
            "In risposta",
            "Inoltrato",
            "Modificato dopo",
            "Scritto da",
            "discussione",
            "mittente",
        ] {
            assert!(
                !codice.contains(ricomposizione),
                "la schermata scrive «{ricomposizione}»: ricomporrebbe cio' che il servizio \
                 dichiara gia'"
            );
        }
    }

    /// **L'esito del confronto sta dentro il riquadro della prova** (CTX-05).
    #[test]
    fn l_esito_del_confronto_sta_nel_riquadro_della_prova() {
        let riquadro = riquadro_della_prova();
        let (Some(prova), Some(esito)) = (
            riquadro.find("text: root.context-anchor;"),
            riquadro.find("text: root.context-comparison-label;"),
        ) else {
            panic!("la prova e l'esito devono stare nel riquadro");
        };
        assert!(
            prova < esito,
            "l'esito viene dopo la prova a cui si riferisce"
        );
    }

    /// **Il confronto non è affidato al solo colore.**
    #[test]
    fn il_confronto_non_e_affidato_al_solo_colore() {
        let vista = pagina();
        let Some(inizio) = vista.find("text: root.context-comparison-label;") else {
            panic!("l'esito deve essere testo");
        };
        let blocco = &vista[inizio..];
        let Some(fine) = blocco.find('}') else {
            panic!("il blocco deve chiudersi");
        };
        assert!(
            blocco[..fine].contains("root.context-texts-differ"),
            "il colore accompagna il testo, e dipende dall'esito"
        );
    }

    /// **Senza confronto non compare alcun esito** (ADR-0053).
    #[test]
    fn senza_confronto_non_compare_alcun_esito() {
        assert!(pagina().contains("if root.context-comparison-label != \"\": Text {"));
    }

    /// **La schermata non decide l'esito del confronto** (DEC-252).
    #[test]
    fn la_schermata_non_decide_l_esito_del_confronto() {
        let codice = codice_senza_commenti();
        assert!(codice.contains("ContextComparison::as_label"));
        for ricomposizione in [
            "COINCIDONO",
            "coincidono",
            "modificato",
            "VersionChange",
            "Divergence::",
        ] {
            assert!(
                !codice.contains(ricomposizione),
                "la schermata scrive «{ricomposizione}»: deciderebbe da se' un esito che il \
                 modello dichiara gia'"
            );
        }
    }

    /// **Chiudere svuota anche l'esito del confronto.**
    #[test]
    fn chiudere_svuota_anche_l_esito() {
        let corpo = corpo("fn close(");
        assert!(corpo.contains("set_conversation_comparison_label(SharedString::default())"));
        assert!(corpo.contains("set_conversation_texts_differ(false)"));
    }

    /// **Chiudere dimentica ciò che si stava guardando** (CTX-06).
    #[test]
    fn chiudere_dimentica_cio_che_si_guardava() {
        let corpo = corpo("fn close(");
        assert!(
            corpo.contains("conversazione = None"),
            "la conversazione mostrata deve sparire con la pagina"
        );
        assert!(
            corpo.contains("set_conversation_snapshot_reason(SharedString::default())"),
            "anche la ragione scritta deve sparire: apparterrebbe a un altro contenuto"
        );
    }

    /// **Conservare è un atto esplicito, e sta dopo aver guardato** (CTX-06).
    #[test]
    fn il_comando_di_conservare_viene_dopo_aver_guardato() {
        assert_eq!(
            UI.matches("root.take-snapshot(").count(),
            1,
            "il comando che conserva deve essere uno solo"
        );
        let vista = pagina();
        let (Some(prova), Some(successivi), Some(comando)) = (
            vista.find("text: root.context-anchor;"),
            vista.find("for riga in root.newer-rows:"),
            vista.find("root.take-snapshot(root.snapshot-reason);"),
        ) else {
            panic!("le tre parti devono esistere, e il comando deve stare nella pagina");
        };
        assert!(prova < comando, "si conserva dopo aver visto la prova");
        assert!(
            successivi < comando,
            "si conserva dopo tutta la conversazione"
        );
    }

    /// **La ragione si chiede, e non si suppone.**
    #[test]
    fn la_ragione_si_chiede_nella_pagina() {
        let vista = pagina();
        assert!(vista.contains("value <=> root.snapshot-reason;"));
        assert!(vista.contains("root.take-snapshot(root.snapshot-reason);"));
    }

    /// **La pagina dichiara che una fotografia non è una prova acquisita, e
    /// che conserva tutto ciò che è caricato** (criterio 11).
    #[test]
    fn la_pagina_dichiara_che_una_fotografia_non_e_una_prova() {
        let vista = pagina();
        assert!(vista.contains("Non diventa una prova acquisita"));
        assert!(vista.contains("tutti i messaggi caricati qui"));
    }

    /// **Conservare non rilegge da Telegram**, e conserva la conversazione
    /// mostrata (criterio 11).
    #[test]
    fn conservare_non_rilegge_da_telegram() {
        let corpo = corpo("fn take_snapshot(");
        for rilettura in [
            "conversation::open(",
            "context::read(",
            "connector_mut()",
            "runtime_mut()",
            "fetch_context",
            ".load(",
        ] {
            assert!(
                !corpo.contains(rilettura),
                "il gesto chiama «{rilettura}»: conserverebbe cio' che nessuno ha guardato"
            );
        }
        assert!(
            corpo.contains("conversazione.context().clone()"),
            "il gesto conserva la conversazione gia' mostrata"
        );
    }

    /// **La schermata non compone la frase di una fotografia** (DEC-252).
    #[test]
    fn la_schermata_non_compone_la_frase_di_una_fotografia() {
        let codice = codice_senza_commenti();
        assert!(codice.contains("crate::lingua::schermo(fotografia.as_sentence())"));
        for ricomposizione in [
            "Fotografia presa da",
            "per questa ragione",
            "osservazione documentata",
            "L'impronta non corrisponde",
        ] {
            assert!(
                !codice.contains(ricomposizione),
                "la schermata scrive «{ricomposizione}»: ricomporrebbe cio' che il servizio \
                 dichiara gia'"
            );
        }
    }

    /// **Un'impronta che non torna si vede, e non solo per il colore.**
    #[test]
    fn un_impronta_che_non_torna_non_e_affidata_al_solo_colore() {
        let vista = pagina();
        let Some(inizio) = vista.find("text: fotografia.sentence;") else {
            panic!("la frase della fotografia deve comparire");
        };
        let blocco = &vista[inizio..];
        let Some(fine) = blocco.find("wrap: word-wrap;") else {
            panic!("il blocco deve chiudersi");
        };
        assert!(blocco[..fine].contains("fotografia.intact"));
    }

    /// **Il collegamento si chiede, non si compone** (F-110, F-111; criterio 9).
    #[test]
    fn il_collegamento_si_chiede_e_non_si_compone() {
        let vista = pagina();
        assert!(crate::surface_text::assegna(
            vista,
            "label",
            "Chiedi il collegamento a Telegram"
        ));
        assert!(
            vista.contains("if root.link-request-url != \"\": HudButton {"),
            "«Apri collegamento» compare solo se Telegram ne ha dato uno"
        );
        let codice = codice_senza_commenti();
        assert!(codice.contains("lisi_services::message_link::request("));
        for composto in ["t.me/", "https://", "tg://"] {
            assert!(
                !codice.contains(composto),
                "la schermata compone «{composto}»: un collegamento si chiede, non si fabbrica"
            );
        }
    }
}

//! Collegamento fra la sezione «Aggiornamenti» e il servizio che li esamina.
//!
//! # Che cosa questa schermata non può fare, e lo dice
//!
//! Non cerca, non scarica, non installa. ADR-0037 lo stabilisce e questo modulo
//! non ha alcun modo di contraddirlo: non esiste un client HTTP in questo
//! percorso, e il file da esaminare lo indica una persona.
//!
//! # Perché il motore era irraggiungibile, e perché conta
//!
//! `lisi-services::update` decideva su un manifesto, con ventitré prove, e **non
//! era invocato da nessuno**. È la stessa forma di difetto già chiusa tre volte
//! in questo progetto (DEC-226): una capacità costruita, collaudata e mai
//! raggiungibile da un operatore non esiste per l'ufficio che la paga.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::role::OperatingMode;
use lisi_services::station::persisted_mode_or_restricted;
use lisi_services::update::{Channel, UpdateDecision};
use lisi_services::update_review::{StoredUpdateSigner, UpdateReviewService, station_state};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// Servizio degli aggiornamenti condiviso fra i gestori.
pub type SharedUpdate = Rc<RefCell<UpdateReviewService>>;

/// Crea il servizio degli aggiornamenti sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedUpdate> {
    Some(Rc::new(RefCell::new(UpdateReviewService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> lisi_services::ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Che cosa questa postazione è, detto in una riga.
///
/// # Perché la versione di Windows compare qui
///
/// È metà del confronto che decide se un aggiornamento sia installabile. Se non
/// è leggibile, l'operatore deve saperlo **prima** di leggere un esito che
/// dichiara di non aver verificato il requisito minimo.
fn station_text(channel: Channel) -> String {
    let stato = station_state(channel);
    match stato.windows_version.as_deref() {
        Some(windows) => format!(
            "Questa postazione ha la versione {} del programma, su Windows {windows}.",
            stato.current_version
        ),
        None => format!(
            "Questa postazione ha la versione {} del programma. La versione di \
             Windows non è leggibile: il requisito minimo di un aggiornamento non \
             potrà essere confrontato.",
            stato.current_version
        ),
    }
}

/// Chiede all'operatore quale file esaminare.
///
/// # Perché il percorso si sceglie e non si digita
///
/// Un file scelto da una finestra di sistema esiste per costruzione, e non c'è un
/// testo da convalidare che possa contenere qualcosa di inatteso (DEC-113). Il
/// **contenuto** resta dato non fidato, e lo tratta il servizio.
fn manifest_dialog() -> rfd::AsyncFileDialog {
    rfd::AsyncFileDialog::new()
        .set_title("Scegliere il file che descrive l'aggiornamento")
        .add_filter("Descrizione di un aggiornamento", &["json"])
}

/// Esamina il file e restituisce il messaggio da mostrare, con l'esito.
///
/// # Perché «già aggiornato» non è un rifiuto
///
/// La schermata colora in ambra ciò che richiede attenzione. Una copia già
/// aggiornata non ne richiede, e colorarla come un rifiuto insegnerebbe a
/// ignorare il colore.
fn run(update: &SharedUpdate, manifest: &std::path::Path) -> (String, bool) {
    let outcome = {
        let service = update.borrow();
        actor().and_then(|actor| service.review_with_freshness(manifest, &actor, now()))
    };

    match outcome {
        Ok((decisione, freschezza)) => {
            let attenzione = matches!(decisione, UpdateDecision::Refused(_));
            if attenzione {
                tracing::warn!(
                    esito = decisione.audit_detail(),
                    "aggiornamento non accettato"
                );
            }

            // La freschezza si aggiunge in coda e NON cambia il colore: un
            // canale fermo non è un aggiornamento rifiutato, e colorarlo come
            // tale insegnerebbe a ignorare il colore — la stessa ragione per cui
            // «già aggiornato» non è ambra (ADR-0045).
            let mut messaggio = decisione.operator_message();
            if freschezza.worth_saying() {
                messaggio.push_str("\n\n");
                messaggio.push_str(&freschezza.as_sentence());
            }
            (messaggio, attenzione)
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "esame dell'aggiornamento non riuscito");
            (error.operator_message(), true)
        }
    }
}

/// Che cosa il canale comporta **oggi**, detto dove si sceglie.
///
/// # Perché la scelta si può fare adesso, e dichiara di non avere effetto
///
/// Finché manca il certificato di firma non esiste nulla di pubblicato su alcun
/// canale (HVQ-07), e un selettore che tacesse su questo non sarebbe decorativo:
/// sarebbe **bugiardo**, perché chi sceglie «Pilota» si aspetta di ricevere
/// prima. Nasconderlo però costa dopo: il giorno in cui il certificato
/// arriverà, nessuna postazione avrebbe una storia della propria scelta.
///
/// Si sceglie adesso, e accanto c'è scritta la verità (ADR-0066, decisione 4).
fn channel_note(channel: Channel, settable: bool) -> String {
    let mut nota = String::from(
        "Il canale non cambia nessuna verifica: firma, impronta e rifiuto di una \
         versione più vecchia sono gli stessi sui due canali. Cambia solo quando \
         questa postazione riceve.",
    );

    nota.push_str(
        "\n\nOggi non è pubblicato nulla su nessuno dei due canali, perché manca \
         il certificato di firma. La scelta resta scritta, e varrà quando ci sarà \
         qualcosa da ricevere.",
    );

    if !settable {
        nota.push_str(
            "\n\nIn modalità operatore la scelta si legge e non si cambia: vale \
             per la postazione, non per chi la usa.",
        );
    }

    nota.push_str(&format!(
        "\n\nCanale di questa postazione: {}.",
        channel.label()
    ));

    nota
}

/// Riporta nell'interfaccia ciò che si sa senza che nessuno prema nulla.
///
/// # Perché il servizio è facoltativo
///
/// Senza archivio il canale non si legge, e **non si inventa**: la schermata
/// resta con ciò che sa comunque — versione e Windows — invece di dichiarare un
/// canale che nessuno ha letto.
pub fn refresh(window: &AppWindow, update: Option<&SharedUpdate>) {
    let amministratore = persisted_mode_or_restricted() == OperatingMode::Administrator;
    window.set_update_channel_settable(amministratore);

    let Some(update) = update else {
        window.set_update_station(SharedString::from(station_text(Channel::default())));
        window.set_update_channel_note(SharedString::default());
        return;
    };

    let canale = match update.borrow().channel() {
        Ok(canale) => canale,
        Err(error) => {
            tracing::warn!(kind = error.kind(), "canale degli aggiornamenti non letto");
            window.set_update_station(SharedString::from(station_text(Channel::default())));
            window.set_update_channel_note(crate::lingua::schermo(error.operator_message()));
            return;
        }
    };

    window.set_update_station(SharedString::from(station_text(canale)));
    window.set_update_channel_index(i32::from(canale == Channel::Pilot));
    window.set_update_channel_note(SharedString::from(channel_note(canale, amministratore)));

    // UN ERRORE DI LETTURA NON DIVENTA «NON INDICATA».
    //
    // Sono due cose diverse: «nessuno l'ha indicata» è una scelta, «non si è
    // potuto leggere» è un guasto. Appiattirle mostrerebbe un campo vuoto che
    // invita a riscrivere un indirizzo che forse c'è già.
    let origine = match update.borrow().origin() {
        Ok(origine) => origine,
        Err(error) => {
            tracing::warn!(kind = error.kind(), "origine degli aggiornamenti non letta");
            window.set_update_origin(SharedString::default());
            window.set_update_origin_note(crate::lingua::schermo(error.operator_message()));
            return;
        }
    };

    window.set_update_origin(SharedString::from(origine.clone().unwrap_or_default()));
    window.set_update_signers(SharedString::from(match update.borrow().update_signers() {
        Ok(firmatari) => signers_text(&firmatari),
        Err(error) => error.operator_message(),
    }));
    window.set_update_origin_note(SharedString::from(origin_note(
        origine.is_some(),
        amministratore,
    )));

    // UNA CONSEGNA CHE NON HA PRODOTTO UN'INSTALLAZIONE (ADR-0073).
    //
    // Si legge il registro degli atti e la versione di questo binario: non si
    // tocca la rete e non si tocca il disco.
    let avviso = match update.borrow().delivery_outcome() {
        Ok(esito) => esito.sentence().unwrap_or_default(),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "esito dell'ultima consegna non letto");
            String::new()
        }
    };
    window.set_update_delivery_notice(SharedString::from(avviso));

    // DOVE SI E', E QUAL E' IL PASSO DOPO (ADR-0071).

    //
    // Lo stato non si conserva: si chiede al mondo ogni volta che la schermata
    // si aggiorna, e le due domande non escono dalla postazione.
    window.set_update_why_no_install(crate::lingua::schermo(
        lisi_services::update_review::PERCHE_NON_SI_INSTALLA,
    ));
    match update.borrow().step() {
        Ok(passo) => {
            window.set_update_step_sentence(crate::lingua::schermo(passo.sentence()));
            window.set_update_step_command(SharedString::from(passo.command().unwrap_or_default()));
            window.set_update_step_inaction(SharedString::from(passo.doing_nothing()));
            let c_e_un_file = passo == lisi_services::update_review::UpdateStep::VerifyWhatArrived;
            window.set_update_has_staged(c_e_un_file);
            // La nota compare SOLO dove il comando compare: una frase su un
            // comando che non c'e' e' rumore, e una frase che manca su un
            // comando che chiude il programma e' peggio.
            window.set_update_hand_off_note(SharedString::from(if c_e_un_file {
                lisi_services::update_review::COSA_SUCCEDE_CONSEGNANDO
            } else {
                ""
            }));
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "passo dell'aggiornamento non letto");
            window.set_update_step_sentence(crate::lingua::schermo(error.operator_message()));
            window.set_update_step_command(SharedString::default());
            window.set_update_step_inaction(SharedString::default());
            window.set_update_has_staged(false);
            window.set_update_hand_off_note(SharedString::default());
        }
    }
}

/// Che cosa l'origine comporta, detto dove si scrive.
///
/// # Perché l'assenza si spiega invece di essere un campo vuoto
///
/// Un campo vuoto sembra una dimenticanza. L'assenza dell'origine non lo è: è la
/// conseguenza del fatto che non c'è ancora nulla di pubblicato, e un indirizzo
/// predefinito scritto nel prodotto sarebbe un indirizzo che un giorno qualcuno
/// contatta senza averlo scelto.
/// I firmatari degli aggiornamenti, in righe da leggere (ADR-0183).
fn signers_text(firmatari: &[StoredUpdateSigner]) -> String {
    if !firmatari.iter().any(StoredUpdateSigner::is_admitted) {
        let mut testo = String::from(
            "Nessun firmatario degli aggiornamenti è ammesso: nessuna informazione sugli \
             aggiornamenti si accetta.",
        );
        if !firmatari.is_empty() {
            testo.push_str(" Quelli qui sotto sono ritirati.");
        }
        if firmatari.is_empty() {
            return testo;
        }
        return format!("{testo}\n{}", righe_dei_firmatari(firmatari));
    }
    format!(
        "Firmatari degli aggiornamenti:\n{}",
        righe_dei_firmatari(firmatari)
    )
}

fn righe_dei_firmatari(firmatari: &[StoredUpdateSigner]) -> String {
    firmatari
        .iter()
        .map(|firmatario| {
            let stato = match (&firmatario.retired_at, &firmatario.retired_by) {
                (Some(quando), Some(chi)) => {
                    format!("ritirato il {} da {chi}", quando.to_readable_local())
                }
                _ => format!(
                    "ammesso il {} da {}",
                    firmatario.added_at.to_readable_local(),
                    firmatario.added_by
                ),
            };
            format!(
                "«{}», {stato}. Impronta: {}.",
                firmatario.name, firmatario.sha256
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn origin_note(configurata: bool, amministratore: bool) -> String {
    let mut nota = String::from(
        "È l'unico indirizzo web che questo programma può raggiungere. Lo raggiunge \
         solo quando qualcuno lo chiede: non cerca da solo, non controlla in \
         automatico e non guarda all'avvio.",
    );

    if configurata {
        nota.push_str(
            "\n\nCiò che arriva da qui resta informazione non verificata, \
             esattamente come un file ricevuto a mano: viene esaminata, non \
             creduta.",
        );
    } else {
        nota.push_str(
            "\n\nNon è ancora indicata, e non è una dimenticanza: non c'è ancora \
             nulla di pubblicato. Finché resta vuota, il programma non contatta \
             nessuno.",
        );
    }

    if !amministratore {
        nota.push_str(
            "\n\nIn modalità operatore l'indirizzo si legge e non si cambia: \
             decide con chi la postazione parla.",
        );
    }

    nota
}

/// Collega i comandi della sezione al servizio.
pub fn wire(window: &AppWindow, update: &SharedUpdate) {
    let handle = window.as_weak();
    let esame = Rc::clone(update);
    window.on_review_update(move || {
        if crate::lock::refuse_while_locked("review_update") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        // Finestra chiusa senza scegliere: non e' un errore e non si annuncia
        // nulla. Un messaggio dopo un annullamento fa credere che sia successo
        // qualcosa.
        let esame = Rc::clone(&esame);
        crate::dialogs::ask(
            &window,
            manifest_dialog(),
            crate::dialogs::Pick::File,
            "review_update",
            move |window, percorso| {
                let (messaggio, attenzione) = run(&esame, &percorso);
                window.set_update_message(crate::lingua::schermo(messaggio));
                window.set_update_refused(attenzione);
            },
        );
    });

    let handle = window.as_weak();
    let servizio = Rc::clone(update);
    window.on_choose_update_channel(move |indice| {
        if crate::lock::refuse_while_locked("choose_update_channel") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        // LA MODALITA' VIENE DALLA CONFIGURAZIONE, NON DALLA SCHERMATA.
        //
        // Un comando disabilitato non e' un controllo: se la modalita' arrivasse
        // da una proprieta' dell'interfaccia, il controllo del servizio
        // verificherebbe cio' che l'interfaccia gli ha appena detto.
        let modalita = persisted_mode_or_restricted();
        let canale = if indice == 1 {
            Channel::Pilot
        } else {
            Channel::Stable
        };

        let esito = actor().and_then(|attore| {
            servizio
                .borrow()
                .choose_channel(canale, modalita, &attore, now())
        });

        if let Err(error) = esito {
            tracing::warn!(
                kind = error.kind(),
                "canale degli aggiornamenti non cambiato"
            );
            window.set_update_channel_note(crate::lingua::schermo(error.operator_message()));
        }

        // Si rilegge dall'archivio invece di fidarsi di cio' che si e' appena
        // scritto: se la scrittura e' stata rifiutata, la schermata deve tornare
        // a mostrare il canale VERO, non quello scelto.
        refresh(&window, Some(&servizio));
    });

    let handle = window.as_weak();
    let origine = Rc::clone(update);
    window.on_save_update_origin(move |indirizzo| {
        if crate::lock::refuse_while_locked("save_update_origin") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        // La modalita' viene dalla configurazione, non dalla schermata: vale
        // qui la stessa ragione del canale.
        let modalita = persisted_mode_or_restricted();
        let indirizzo = indirizzo.to_string();
        let scelta = indirizzo.trim();
        let scelta = if scelta.is_empty() {
            None
        } else {
            Some(scelta)
        };

        let esito = actor().and_then(|attore| {
            origine
                .borrow()
                .set_origin(scelta, modalita, &attore, now())
        });

        refresh(&window, Some(&origine));

        // L'esito si scrive DOPO l'aggiornamento della schermata (F-11): prima
        // stava sopra, e `refresh` lo sostituiva con la nota fissa, cosi' un
        // rifiuto non lo vedeva nessuno. Rifiutata, l'origine scritta resta nel
        // campo, da correggere.
        match esito {
            Ok(()) => window.set_update_origin_note(crate::lingua::schermo(format!(
                "{}\n\n{}",
                if scelta.is_some() {
                    "Origine salvata."
                } else {
                    "Origine svuotata: il programma non contatta nessuno."
                },
                window.get_update_origin_note()
            ))),
            Err(error) => {
                tracing::warn!(
                    kind = error.kind(),
                    "origine degli aggiornamenti non cambiata"
                );
                window.set_update_origin(SharedString::from(indirizzo.as_str()));
                window.set_update_origin_note(crate::lingua::schermo(error.operator_message()));
            }
        }
    });

    wire_signers(window, update);

    let handle = window.as_weak();
    let scarico = Rc::clone(update);
    window.on_fetch_update(move || {
        if crate::lock::refuse_while_locked("fetch_update") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        let esito = {
            let servizio = scarico.borrow();
            actor().and_then(|attore| servizio.fetch_and_review(&attore, now()))
        };

        let (messaggio, attenzione) = match esito {
            Ok((decisione, freschezza)) => {
                let attenzione = matches!(decisione, UpdateDecision::Refused(_));
                let mut messaggio = decisione.operator_message();
                if freschezza.worth_saying() {
                    messaggio.push_str("\n\n");
                    messaggio.push_str(&freschezza.as_sentence());
                }
                (messaggio, attenzione)
            }
            Err(error) => {
                // «Non e' arrivato» NON e' «e' stato rifiutato»: sono due fatti
                // diversi, e portano a due azioni diverse. Il servizio li tiene
                // separati, e qui non si rimescolano.
                tracing::warn!(
                    kind = error.kind(),
                    "informazione sull'aggiornamento non ottenuta"
                );
                (error.operator_message(), true)
            }
        };

        window.set_update_message(crate::lingua::schermo(messaggio));
        window.set_update_refused(attenzione);
    });

    let handle = window.as_weak();
    let artefatto = Rc::clone(update);
    window.on_download_artifact(move || {
        if crate::lock::refuse_while_locked("download_artifact") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        let esito = {
            let servizio = artefatto.borrow();
            actor().and_then(|attore| servizio.download_artifact(&attore, now()))
        };

        let (messaggio, attenzione) = match esito {
            Ok(sceso) => (
                format!(
                    "Il file è stato scaricato: {} byte.\n\nNon è stato verificato e non è \
                     stato installato. Il programma non lo apre e non lo esegue. Finché non \
                     è verificato, quel file è soltanto ciò che è arrivato dalla rete: per \
                     verificarlo, usare «Verifica il file».",
                    sceso.bytes
                ),
                false,
            ),
            Err(error) => {
                tracing::warn!(kind = error.kind(), "file dell'aggiornamento non scaricato");
                (error.operator_message(), true)
            }
        };

        window.set_update_message(crate::lingua::schermo(messaggio));
        window.set_update_refused(attenzione);
    });

    let handle = window.as_weak();
    let verifica = Rc::clone(update);
    window.on_verify_artifact(move || {
        if crate::lock::refuse_while_locked("verify_artifact") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        let esito = {
            let servizio = verifica.borrow();
            actor().and_then(|attore| servizio.verify_artifact(&attore, now()))
        };

        let (messaggio, attenzione) = match esito {
            Ok(verdetto) => {
                // UN VERDETTO NON E' UN ERRORE, e un anello rotto non e' un
                // guasto del programma: e' la risposta. L'ambra dice «guarda
                // questo», e su un verdetto positivo insegnerebbe a ignorarla.
                let attenzione = !matches!(
                    verdetto,
                    lisi_services::update_review::ArtifactVerdict::Verified { .. }
                );
                (verdetto.operator_message(), attenzione)
            }
            Err(error) => {
                tracing::warn!(kind = error.kind(), "verifica del file non eseguita");
                (error.operator_message(), true)
            }
        };

        window.set_update_message(crate::lingua::schermo(messaggio));
        window.set_update_refused(attenzione);
    });

    let handle = window.as_weak();
    let passo = Rc::clone(update);
    window.on_update_step_forward(move || {
        if crate::lock::refuse_while_locked("update_step_forward") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        // OGNI PASSO FA UNA COSA SOLA (ADR-0071).
        //
        // Incatenarne due sarebbe piu' comodo da premere e peggiore da capire:
        // quando qualcosa va storto non si saprebbe QUALE dei due, e le due
        // cause portano ad azioni diverse - una e' la rete, l'altra e' il file.
        let quale = passo.borrow().step();
        let esito = match quale {
            Ok(lisi_services::update_review::UpdateStep::AskTheOrigin) => {
                let servizio = passo.borrow();
                actor()
                    .and_then(|attore| servizio.fetch_and_review(&attore, now()))
                    .map(|(decisione, freschezza)| {
                        let attenzione = matches!(decisione, UpdateDecision::Refused(_));
                        let mut messaggio = decisione.operator_message();
                        if freschezza.worth_saying() {
                            messaggio.push_str("\n\n");
                            messaggio.push_str(&freschezza.as_sentence());
                        }
                        (messaggio, attenzione)
                    })
            }
            Ok(lisi_services::update_review::UpdateStep::VerifyWhatArrived) => {
                let servizio = passo.borrow();
                actor()
                    .and_then(|attore| servizio.verify_artifact(&attore, now()))
                    .map(|verdetto| {
                        let attenzione = !matches!(
                            verdetto,
                            lisi_services::update_review::ArtifactVerdict::Verified { .. }
                        );
                        (verdetto.operator_message(), attenzione)
                    })
            }
            // Senza origine non c'e' un comando, e la schermata non lo mostra.
            Ok(lisi_services::update_review::UpdateStep::OriginMissing) => return,
            Err(error) => Err(error),
        };

        let (messaggio, attenzione) = match esito {
            Ok(esito) => esito,
            Err(error) => {
                tracing::warn!(kind = error.kind(), "passo dell'aggiornamento non riuscito");
                (error.operator_message(), true)
            }
        };

        window.set_update_message(crate::lingua::schermo(messaggio));
        window.set_update_refused(attenzione);
        refresh(&window, Some(&passo));
    });

    let handle = window.as_weak();
    let consegna = Rc::clone(update);
    window.on_hand_off_update(move || {
        if crate::lock::refuse_while_locked("hand_off_update") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        let esito = {
            let servizio = consegna.borrow();
            actor().and_then(|attore| servizio.hand_off_to_installer(&attore, now()))
        };

        match esito {
            Ok(()) => {
                // CONSEGNATO: da qui in avanti l'installatore vive piu' a lungo
                // di questo processo, e questo processo si chiude.
                //
                // Non si riapre da solo: riaprirlo aprirebbe un programma
                // DIVERSO da quello che l'operatore ha chiuso, senza che
                // nessuno lo guardi partire (ADR-0072).
                tracing::info!("aggiornamento consegnato: il programma si chiude");
                window.set_update_message(crate::lingua::schermo(
                    "L'aggiornamento è stato consegnato all'installatore di Windows. \
                     Il programma si sta chiudendo: quando l'installazione sarà \
                     finita, riaprilo a mano.",
                ));
                window.set_update_refused(false);
                slint::quit_event_loop().ok();
            }
            Err(error) => {
                tracing::warn!(kind = error.kind(), "aggiornamento non consegnato");
                window.set_update_message(crate::lingua::schermo(error.operator_message()));
                window.set_update_refused(true);
                refresh(&window, Some(&consegna));
            }
        }
    });

    let handle = window.as_weak();
    let scarto = Rc::clone(update);
    window.on_discard_staged(move || {
        if crate::lock::refuse_while_locked("discard_staged") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        let esito = {
            let servizio = scarto.borrow();
            actor().and_then(|attore| servizio.discard_staged(&attore, now()))
        };

        let (messaggio, attenzione) = match esito {
            Ok(()) => (
                String::from(
                    "Il file scaricato è stato tolto dalla postazione. Non è stato \
                     installato nulla, e non resta niente da verificare.",
                ),
                false,
            ),
            Err(error) => {
                tracing::warn!(kind = error.kind(), "file scaricato non tolto");
                (error.operator_message(), true)
            }
        };

        window.set_update_message(crate::lingua::schermo(messaggio));
        window.set_update_refused(attenzione);
        refresh(&window, Some(&scarto));
    });
}

/// Collega «Ammetti il firmatario» e «Ritira il firmatario» (ADR-0183,
/// decisione 4). Chi può farlo lo decide il servizio: in modalità operatore i
/// pulsanti non ci sono, e se ci fossero il rifiuto verrebbe comunque da lì.
fn wire_signers(window: &AppWindow, update: &SharedUpdate) {
    {
        let handle = window.as_weak();
        let servizio = Rc::clone(update);
        window.on_admit_update_signer(move || {
            if crate::lock::refuse_while_locked("admit_update_signer") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let impronta = window.get_update_signer_fingerprint().to_string();
            let nome = window.get_update_signer_name().to_string();
            let esito = actor().and_then(|attore| {
                servizio.borrow_mut().admit_update_signer(
                    &impronta,
                    &nome,
                    persisted_mode_or_restricted(),
                    &attore,
                    now(),
                )
            });
            let frase = match esito {
                Ok(()) => {
                    window.set_update_signer_fingerprint(SharedString::default());
                    window.set_update_signer_name(SharedString::default());
                    String::from("Firmatario ammesso.")
                }
                Err(error) => error.operator_message(),
            };
            refresh(&window, Some(&servizio));
            window.set_update_signer_note(crate::lingua::schermo(frase));
        });
    }
    {
        let handle = window.as_weak();
        let servizio = Rc::clone(update);
        window.on_retire_update_signer(move || {
            if crate::lock::refuse_while_locked("retire_update_signer") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let impronta = window.get_update_signer_fingerprint().to_string();
            let esito = actor().and_then(|attore| {
                servizio.borrow_mut().retire_update_signer(
                    &impronta,
                    persisted_mode_or_restricted(),
                    &attore,
                    now(),
                )
            });
            let frase = match esito {
                Ok(()) => {
                    window.set_update_signer_fingerprint(SharedString::default());
                    String::from(
                        "Firmatario ritirato: resta nell'elenco, e una firma sua non si accetta più.",
                    )
                }
                Err(error) => error.operator_message(),
            };
            refresh(&window, Some(&servizio));
            window.set_update_signer_note(crate::lingua::schermo(frase));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{Channel, create_service, run, station_text};

    /// Il sorgente della schermata, letto a tempo di compilazione.
    pub(super) const SCHERMATA: &str = include_str!("../ui/app-window.slint");

    fn servizio() -> super::SharedUpdate {
        let Ok(database) = lisi_services::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let Some(condiviso) = create_service(database) else {
            panic!("il servizio deve potersi creare");
        };
        condiviso
    }

    fn scrivi(cartella: &std::path::Path, contenuto: &str) -> std::path::PathBuf {
        let percorso = cartella.join("manifesto.json");
        let Ok(()) = std::fs::write(&percorso, contenuto) else {
            panic!("il file di prova deve potersi scrivere");
        };
        percorso
    }

    /// **I firmatari si leggono, e un elenco senza ammessi dice la conseguenza**
    /// (ADR-0183): nessuna informazione si accetta; un ritirato resta e lo dice.
    #[test]
    fn i_firmatari_si_leggono_e_senza_ammessi_si_dice_la_conseguenza() {
        use lisi_core::Timestamp;
        use lisi_services::update_review::StoredUpdateSigner;

        assert!(super::signers_text(&[]).contains("nessuna informazione"));
        let ritirato = StoredUpdateSigner {
            sha256: "a".repeat(64),
            name: String::from("Produttore, chiave 2025"),
            added_at: Timestamp::from_millis(1_700_000_000_000),
            added_by: String::from("amministratore.prova"),
            retired_at: Some(Timestamp::from_millis(1_762_400_000_000)),
            retired_by: Some(String::from("amministratore.prova")),
        };
        let solo_ritirati = super::signers_text(std::slice::from_ref(&ritirato));
        assert!(solo_ritirati.contains("nessuna informazione"));
        assert!(solo_ritirati.contains("«Produttore, chiave 2025», ritirato il"));

        let ammesso = StoredUpdateSigner {
            sha256: "b".repeat(64),
            name: String::from("Produttore, chiave 2026"),
            retired_at: None,
            retired_by: None,
            ..ritirato
        };
        let testo = super::signers_text(&[ammesso]);
        assert!(testo.starts_with("Firmatari degli aggiornamenti:"));
        assert!(testo.contains("ammesso il"));
        assert!(testo.contains(&"b".repeat(64)));
    }

    /// **La postazione si descrive da se', non con valori scritti a mano.**
    #[test]
    fn la_riga_della_postazione_dice_versione_e_windows() {
        let testo = station_text(Channel::Stable);
        assert!(
            testo.contains("versione"),
            "la riga non dice la versione: «{testo}»"
        );
        if cfg!(windows) {
            assert!(
                testo.contains("Windows 10."),
                "la riga non dice la versione di Windows: «{testo}»"
            );
        }
    }

    /// **Un file inaccettabile si vede, e dice perche'.**
    ///
    /// Il caso che conta non e' il rifiuto: e' che l'esito NON assomigli a un
    /// successo. Un operatore che leggesse una frase neutra crederebbe di avere
    /// un aggiornamento disponibile.
    #[test]
    fn un_aggiornamento_rifiutato_si_vede_e_spiega() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = scrivi(cartella.path(), "questo non e' un file JSON");

        let (messaggio, attenzione) = run(&servizio(), &percorso);
        assert!(attenzione, "un rifiuto deve risultare tale");
        assert!(
            messaggio.contains("non accettato"),
            "l'esito non dichiara il rifiuto: «{messaggio}»"
        );
        assert!(
            !messaggio.contains("È disponibile"),
            "un rifiuto assomiglia a un'offerta: «{messaggio}»"
        );
    }

    /// **La schermata dichiara che il prodotto non scarica e non installa.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un pulsante che dice «Esamina un aggiornamento…» in una schermata muta
    /// lascia intendere che dietro ci sia un aggiornatore. Non c'e', ed e' una
    /// decisione (ADR-0037): un programma di monitoraggio che si sostituisse da
    /// solo cambierebbe, senza che nessuno lo abbia deciso, lo strumento con cui
    /// si stanno producendo atti.
    ///
    /// Togliere quelle frasi non romperebbe niente. Nessuna prova diventerebbe
    /// rossa, e la schermata comincerebbe a promettere cio' che non fa.
    #[test]
    fn la_schermata_dichiara_cio_che_il_prodotto_non_fa() {
        assert!(
            SCHERMATA.contains("AGGIORNAMENTI"),
            "la sezione degli aggiornamenti non c'e' piu': questa prova non sta \
             piu' guardando cio' che crede"
        );
        assert!(
            SCHERMATA.contains("non cerca aggiornamenti da solo"),
            "la schermata non dichiara piu' che il controllo automatico non \
             esiste: un pulsante in una schermata muta lascia intendere che \
             dietro ci sia un aggiornatore"
        );
        // LA FRASE SI E' SPOSTATA, NON E' SPARITA.
        //
        // Con UPDATE-06 non e' piu' scritta a mano nella schermata: viene dal
        // servizio, perche' il giorno in cui l'installazione esistera' dovra'
        // sparire INSIEME all'arrivo del comando, e una frase scritta in due
        // posti sparisce da uno solo. La prova la segue dove e' andata, invece
        // di essere tolta perche' e' diventata rossa.
        assert!(
            SCHERMATA.contains("root.update-why-no-install"),
            "la schermata non mostra piu' la frase che dichiara che il programma \
             non si sostituisce da se'"
        );
        assert!(
            lisi_services::update_review::PERCHE_NON_SI_INSTALLA
                .contains("non si sostituisce da sé"),
            "la frase non dichiara piu' che il programma non si installa da se'"
        );
        assert!(
            SCHERMATA.contains("root.review-update()"),
            "nessun comando invoca l'esame: il motore tornerebbe a non essere \
             raggiungibile da nessuno, che e' il difetto gia' chiuso tre volte"
        );
    }

    /// **La schermata non promette una connessione che non c'e'.**
    #[test]
    fn la_schermata_non_offre_un_controllo_automatico() {
        for proibito in [
            "Cerca aggiornamenti",
            "check-for-updates",
            "Controlla automaticamente",
            "Scarica l'aggiornamento",
        ] {
            assert!(
                !SCHERMATA.contains(proibito),
                "la schermata offre «{proibito}»: sarebbe una connessione uscente \
                 che nessun ufficio ha approvato, e il prodotto non la fa"
            );
        }
    }
}

#[cfg(test)]
mod canale {
    use super::tests::SCHERMATA;
    use super::{Channel, channel_note};

    /// Il sorgente di questo modulo, letto a tempo di compilazione.
    const QUESTO_MODULO: &str = include_str!("update.rs");

    /// **«Pilota» non si racconta come «prova».**
    ///
    /// E' la decisione 5 di ADR-0066, ed e' quella che si perde per strada: nel
    /// resto del mondo del software un canale «pilota» e' un canale dove le cose
    /// sono meno provate, e le parole che lo dicono arrivano da sole. Qui il
    /// pilota e' LO STESSO artefatto, firmato allo stesso modo, pubblicato
    /// prima: ognuna di quelle parole direbbe il falso.
    #[test]
    fn il_pilota_non_si_racconta_come_una_versione_di_prova() {
        let testo = format!(
            "{}{}{}",
            channel_note(Channel::Pilot, true),
            channel_note(Channel::Pilot, false),
            sezione_aggiornamenti()
        );
        let minuscolo = testo.to_lowercase();

        for parola in ["beta", "sperimental", "instabil", "anteprima", "collaud"] {
            assert!(
                !minuscolo.contains(parola),
                "«{parola}» dice «meno verificato», e il pilota non lo e': «{testo}»"
            );
        }
    }

    /// **Il canale dice QUANDO, e la schermata lo dice.**
    ///
    /// Non basta non dire il falso: chi legge deve trovare scritto che cosa
    /// cambia davvero, altrimenti lo deduce, e cio' che deduce e' «pilota =
    /// meno sicuro».
    #[test]
    fn la_nota_dice_che_il_canale_non_cambia_le_verifiche() {
        let nota = channel_note(Channel::Pilot, true);
        assert!(
            nota.contains("non cambia nessuna verifica"),
            "la nota non dice che le verifiche restano le stesse: «{nota}»"
        );
        assert!(
            nota.contains("quando questa postazione riceve"),
            "la nota non dice che cosa il canale cambia davvero: «{nota}»"
        );
    }

    /// **La scelta dichiara di non avere ancora effetto.**
    ///
    /// E' la decisione 4 di ADR-0066: un selettore che tacesse sul fatto che
    /// nulla e' pubblicato non sarebbe decorativo, sarebbe BUGIARDO — chi
    /// sceglie «Pilota» si aspetta di ricevere prima.
    #[test]
    fn la_nota_dichiara_che_non_c_e_ancora_nulla_da_ricevere() {
        for canale in [Channel::Stable, Channel::Pilot] {
            let nota = channel_note(canale, true);
            assert!(
                nota.contains("non è pubblicato nulla"),
                "la nota non dichiara che i canali sono vuoti: «{nota}»"
            );
            assert!(
                nota.contains("certificato di firma"),
                "la nota non dice PERCHE' sono vuoti: «{nota}»"
            );
        }
    }

    /// **In modalita' operatore la scelta si legge e non si cambia, e lo dice.**
    #[test]
    fn in_modalita_operatore_la_nota_spiega_perche_non_si_cambia() {
        let nota = channel_note(Channel::Stable, false);
        assert!(
            nota.contains("riservata") || nota.contains("non si cambia"),
            "la nota non dice che la scelta e' riservata: «{nota}»"
        );
        assert!(
            !channel_note(Channel::Stable, true).contains("non si cambia"),
            "in modalita' amministratore la nota non deve dire che non si cambia"
        );
    }

    /// **La modalita' non arriva dalla schermata.**
    ///
    /// Un comando disabilitato non e' un controllo. Se la modalita' venisse da
    /// una proprieta' dell'interfaccia, il servizio verificherebbe cio' che
    /// l'interfaccia gli ha appena detto, e chiunque sapesse scrivere in quella
    /// proprieta' avrebbe la modalita' amministratore.
    #[test]
    fn la_modalita_viene_dalla_configurazione_e_non_dalla_finestra() {
        let Some(comando) = QUESTO_MODULO.split("on_choose_update_channel").nth(1) else {
            panic!("il comando di scelta del canale non si trova in questo modulo");
        };
        let Some(corpo) = comando.split("\n    });").next() else {
            panic!("il corpo del comando non si delimita");
        };

        assert!(
            corpo.contains("persisted_mode_or_restricted()"),
            "la modalita' deve venire dalla configurazione della postazione"
        );
        assert!(
            !corpo.contains("get_update_channel_settable")
                && !corpo.contains("get_administrator_mode"),
            "la modalita' non deve essere letta da una proprieta' della finestra"
        );
    }

    /// La sezione «AGGIORNAMENTI» della schermata, per leggerne le parole.
    fn sezione_aggiornamenti() -> String {
        let Some(dopo) = SCHERMATA.split("\"AGGIORNAMENTI\"").nth(1) else {
            panic!("la sezione degli aggiornamenti non si trova nella schermata");
        };
        let Some(sezione) = dopo.split("// ----").next() else {
            panic!("la sezione degli aggiornamenti non si delimita");
        };
        String::from(sezione)
    }
}

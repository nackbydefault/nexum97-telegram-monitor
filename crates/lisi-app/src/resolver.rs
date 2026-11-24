//! La schermata della ricerca puntuale (PR-09, ADR-0125).
//!
//! # Che cosa fa
//!
//! Legge dalla schermata il genere, il dato e la ragione; costruisce la
//! richiesta **con l'autorità di acquisizione** della sessione dell'account; la
//! passa al servizio insieme al connettore dell'account; mostra l'esito e il
//! registro. **Nessuna logica di classificazione vive qui**: la tabella è quella
//! della matrice, nel servizio.
//!
//! # Che cosa non fa
//!
//! Non ripete una ricerca e non ne fa partire una da sola.
//!
//! # Il collegamento a un soggetto (PR-10, ADR-0126)
//!
//! Un «Trovato» di una persona si collega a un soggetto **solo a mano**: una
//! persona sceglie il soggetto fra quelli aperti, in ordine di nome, e scrive
//! perché è la stessa persona. Nessun soggetto è proposto, nessuno è ordinato
//! per somiglianza, e la ricerca stessa non collega nulla.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::identity_resolution::{ResolutionInputKind, ResolutionOutcome};
use lisi_core::model::reason::OperationalReason;
use lisi_core::{IdentityResolutionId, PersonId};
use lisi_services::Database;
use lisi_services::identity_link::IdentityLinkService;
use lisi_services::identity_resolver::{self, Attempt, ResolutionRequest};
use lisi_services::person::PersonService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, ResolutionRow};

/// Quante ricerche registrate si mostrano.
const SHOWN_ROWS: u32 = 30;

/// I generi di profilo che si collegano, gli stessi del servizio dei legami.
const LINKABLE_KINDS: [&str; 2] = ["persona", "account"];

/// La schermata: una connessione propria all'archivio per ciascun servizio.
pub struct ResolverScreen {
    archive: Database,
    links: IdentityLinkService,
    persons: PersonService,
    /// I soggetti offerti al collegamento in corso, nell'ordine mostrato.
    subjects: Vec<PersonId>,
}

/// Schermata condivisa fra i gestori.
pub type SharedResolver = Rc<RefCell<ResolverScreen>>;

/// Crea la schermata sulle connessioni indicate.
#[must_use]
pub fn create_service(archive: Database, links: Database, persons: Database) -> SharedResolver {
    Rc::new(RefCell::new(ResolverScreen {
        archive,
        links: IdentityLinkService::new(links),
        persons: PersonService::new(persons),
        subjects: Vec::new(),
    }))
}

/// I soggetti aperti, **in ordine di nome**: nessun altro ordine, perché un
/// ordine diverso sarebbe un suggerimento.
fn open_subjects(screen: &mut ResolverScreen) -> Result<Vec<String>, String> {
    let mut aperti: Vec<(String, PersonId)> = screen
        .persons
        .all()
        .map_err(|errore| errore.operator_message())?
        .into_iter()
        .filter(lisi_core::model::person::Person::is_open)
        .map(|soggetto| (soggetto.label.as_str().to_owned(), soggetto.id))
        .collect();
    aperti.sort();
    screen.subjects = aperti.iter().map(|(_, id)| *id).collect();
    Ok(aperti.into_iter().map(|(nome, _)| nome).collect())
}

/// Collega la ricerca scelta al soggetto scelto, con il motivo scritto.
///
/// `Ok` porta la frase del collegamento riuscito, `Err` quella del rifiuto.
/// La distinzione serve al modulo: dopo un rifiuto resta aperto con il testo
/// scritto, perché chi deve aggiungere tre parole non deve riscriverne venti
/// (CA02-05, GAP-18).
fn link(
    screen: &ResolverScreen,
    ricerca: i32,
    indice: i32,
    motivo: &str,
) -> Result<String, String> {
    let Some(soggetto) = usize::try_from(indice)
        .ok()
        .and_then(|indice| screen.subjects.get(indice).copied())
    else {
        return Err(String::from(
            "Scegliere il soggetto: nessun collegamento è stato registrato.",
        ));
    };
    let Ok(ragione) = OperationalReason::try_new(motivo) else {
        // La misura, non soltanto il rifiuto (OS-04): si sa quanto aggiungere.
        return Err(format!(
            "Scrivere un motivo fra {} e {} caratteri; quello scritto ne ha {}. Chi rilegge il \
             fascicolo deve sapere su che cosa si è deciso che è la stessa persona. Nessun \
             collegamento è stato registrato.",
            lisi_core::model::reason::MIN_REASON_CHARS,
            lisi_core::model::reason::MAX_REASON_CHARS,
            motivo.trim().chars().count(),
        ));
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        return Err(String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
    };
    match screen.links.link_from_resolution(
        soggetto,
        IdentityResolutionId::new(i64::from(ricerca)),
        &ragione,
        &operatore,
        crate::account::now(),
    ) {
        Ok(_) => Ok(String::from(
            "Collegato. Nella scheda del soggetto il legame dice chi l'ha deciso, quando, perché e \
             da quale ricerca.",
        )),
        Err(errore) => Err(errore.operator_message()),
    }
}

/// Che cosa fa il modulo dopo la conferma: si chiude solo se il collegamento è
/// riuscito, e altrimenti conserva soggetto e motivo (CA02-05, GAP-18).
const fn form_closes(esito: &Result<String, String>) -> bool {
    esito.is_ok()
}

/// Il genere scelto nella schermata.
fn kind_at(indice: i32) -> Option<ResolutionInputKind> {
    usize::try_from(indice)
        .ok()
        .and_then(|indice| ResolutionInputKind::ALL.get(indice).copied())
}

/// Esegue la ricerca chiesta dalla schermata. Restituisce l'esito, o la frase
/// del rifiuto prima di chiedere.
fn ask(
    screen: &SharedResolver,
    session: &SharedSession,
    indice: i32,
    dato: &str,
    motivo: &str,
) -> Result<ResolutionOutcome, String> {
    let Some(genere) = kind_at(indice) else {
        return Err(String::from(
            "Genere non riconosciuto: la ricerca non parte.",
        ));
    };
    let Ok(ragione) = OperationalReason::try_new(motivo) else {
        // La ragione c'era ma era corta: la frase dice la misura, non che
        // manca (OPERATOR-UX-REMEDIATION-01, OS-04).
        return Err(format!(
            "Scrivere una ragione operativa fra {} e {} caratteri; quella scritta ne ha {}. La \
             ricerca riguarda un soggetto, e chi la rilegge deve sapere perché.",
            lisi_core::model::reason::MIN_REASON_CHARS,
            lisi_core::model::reason::MAX_REASON_CHARS,
            motivo.trim().chars().count(),
        ));
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        return Err(String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione: la ricerca non parte.",
        ));
    };
    // L'autorità si prende e si lascia: la richiesta non la conserva, e il
    // connettore si chiede subito dopo, con un prestito diverso.
    let richiesta = {
        let sessione = session.borrow();
        let Some(autorita) = sessione.authority() else {
            return Err(sessione.refused("La ricerca puntuale"));
        };
        ResolutionRequest::new(autorita, genere, dato, operatore, ragione)
    };
    let mut sessione = session.borrow_mut();
    let Some(runtime) = sessione.runtime_mut() else {
        return Err(String::from(
            "L'account non è collegato: la ricerca non parte, e non è stata registrata.",
        ));
    };
    let mut screen = screen.borrow_mut();
    match identity_resolver::resolve(
        runtime.connector_mut(),
        &mut screen.archive,
        &richiesta,
        crate::account::now(),
    ) {
        Ok(Attempt::Recorded(esito)) => Ok(esito),
        Ok(Attempt::Refused(frase)) => Err(frase),
        Err(errore) => {
            tracing::warn!(kind = errore.kind(), "ricerca puntuale non registrata");
            Err(errore.operator_message())
        }
    }
}

/// L'ingresso di una ricerca come lo mostra il registro (ADR-0166, CA02-04):
/// un numero di telefono mascherato come gli altri numeri del prodotto, il
/// resto com'è stato scritto. L'archivio conserva ciò che è stato chiesto.
fn input_shown(genere: &str, valore: &str) -> String {
    let tipo = ResolutionInputKind::from_stored(genere);
    let etichetta = tipo.map_or("dato", ResolutionInputKind::label);
    if tipo == Some(ResolutionInputKind::PhoneNumber) {
        format!(
            "{etichetta}: {}",
            lisi_core::model::MaskedPhoneNumber::from_digits(valore).as_str()
        )
    } else {
        format!("{etichetta}: {valore}")
    }
}

/// Le ricerche registrate, per la schermata.
fn rows(screen: &ResolverScreen) -> Vec<ResolutionRow> {
    match identity_resolver::recent(&screen.archive, SHOWN_ROWS) {
        Ok(righe) => righe
            .iter()
            .map(|riga| {
                let ricerca = &riga.resolution;
                ResolutionRow {
                    when: SharedString::from(ricerca.requested_at.to_readable_local()),
                    operator: SharedString::from(ricerca.requested_by.as_str()),
                    input: SharedString::from(input_shown(
                        &ricerca.input_kind,
                        &ricerca.input_value,
                    )),
                    outcome: SharedString::from(outcome_label(&ricerca.outcome)),
                    found: ricerca
                        .found
                        .as_ref()
                        .map_or_else(SharedString::default, |profilo| {
                            SharedString::from(identity_resolver::found_in_words(profilo))
                        }),
                    sentence: SharedString::from(ricerca.outcome_reason.as_str()),
                    id: i32::try_from(riga.id).unwrap_or(-1),
                    // Un numero che non entra nella schermata non si collega:
                    // il comando porterebbe a un'altra ricerca.
                    linkable: i32::try_from(riga.id).is_ok()
                        && ricerca.outcome == "trovato"
                        && ricerca
                            .found
                            .as_ref()
                            .is_some_and(|profilo| LINKABLE_KINDS.contains(&profilo.kind.as_str())),
                }
            })
            .collect(),
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "registro delle ricerche non leggibile"
            );
            Vec::new()
        }
    }
}

/// La parola dell'esito, dal nome stabile.
fn outcome_label(stabile: &str) -> &'static str {
    match stabile {
        "trovato" => "Trovato",
        "dato_non_disponibile" => "Dato non disponibile",
        "richiesta_non_valida" => "Richiesta non valida",
        "errore_temporaneo" => "Errore temporaneo",
        "errore_operativo" => "Errore operativo",
        _ => "Esito non riconosciuto",
    }
}

/// Riporta il registro nella schermata.
pub fn refresh(window: &AppWindow, screen: &SharedResolver) {
    let righe = rows(&screen.borrow());
    window.set_resolver_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Collega i comandi del collegamento a un soggetto (PR-10).
fn wire_link(window: &AppWindow, screen: &SharedResolver) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_resolver_link_start(move |ricerca| {
            if crate::lock::refuse_while_locked("resolver_link_start") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            match open_subjects(&mut screen.borrow_mut()) {
                Ok(nomi) if nomi.is_empty() => {
                    window.set_resolver_link_message(crate::lingua::schermo(
                        "Nessun soggetto aperto: un fascicolo si apre dalla schermata Persone.",
                    ));
                }
                Ok(nomi) => {
                    let nomi: Vec<SharedString> =
                        nomi.into_iter().map(SharedString::from).collect();
                    window.set_resolver_subjects(ModelRc::from(Rc::new(VecModel::from(nomi))));
                    window.set_resolver_subject_index(0);
                    window.set_resolver_link_reason(SharedString::default());
                    window.set_resolver_link_message(SharedString::default());
                    window.set_resolver_linking(ricerca);
                }
                Err(frase) => window.set_resolver_link_message(crate::lingua::schermo(frase)),
            }
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_resolver_link_confirm(move || {
            if crate::lock::refuse_while_locked("resolver_link_confirm") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = link(
                &screen.borrow(),
                window.get_resolver_linking(),
                window.get_resolver_subject_index(),
                window.get_resolver_link_reason().as_str(),
            );
            if form_closes(&frase) {
                window.set_resolver_linking(-1);
                window.set_resolver_link_reason(SharedString::default());
            }
            let (Ok(testo) | Err(testo)) = frase;
            window.set_resolver_link_message(SharedString::from(testo));
            refresh(&window, &screen);
        });
    }
    {
        let handle = window.as_weak();
        window.on_resolver_link_cancel(move || {
            if crate::lock::refuse_while_locked("resolver_link_cancel") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_resolver_linking(-1);
            window.set_resolver_link_reason(SharedString::default());
            window.set_resolver_link_message(crate::lingua::schermo(
                "Nessun collegamento è stato registrato.",
            ));
        });
    }
}

/// Collega i comandi della schermata.
pub fn wire(window: &AppWindow, screen: &SharedResolver, session: &SharedSession) {
    wire_link(window, screen);
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_resolver_shown(move || {
            let Some(window) = handle.upgrade() else {
                return;
            };
            refresh(&window, &screen);
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        let session = Rc::clone(session);
        window.on_resolver_ask(move || {
            if crate::lock::refuse_while_locked("resolver_ask") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            match ask(
                &screen,
                &session,
                window.get_resolver_kind(),
                window.get_resolver_input().as_str(),
                window.get_resolver_reason().as_str(),
            ) {
                Ok(esito) => {
                    window.set_resolver_message(SharedString::default());
                    window.set_resolver_has_outcome(true);
                    window.set_resolver_outcome_label(crate::lingua::schermo(esito.label()));
                    window.set_resolver_outcome_sentence(crate::lingua::schermo(esito.sentence()));
                    window.set_resolver_outcome_todo(crate::lingua::schermo(esito.what_to_do()));
                }
                Err(frase) => {
                    window.set_resolver_has_outcome(false);
                    window.set_resolver_message(crate::lingua::schermo(frase));
                }
            }
            refresh(&window, &screen);
        });
    }
}

#[cfg(test)]
mod tests {
    const THIS_MODULE: &str = include_str!("resolver.rs");
    const MAIN: &str = include_str!("main.rs");
    const UI: &str = include_str!("../ui/app-window.slint");

    fn produzione() -> &'static str {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        produzione
    }

    /// **La schermata non classifica, non ripete, non collega a Persone.**
    #[test]
    fn la_schermata_non_classifica_ne_ripete() {
        let codice = produzione();
        for vietato in [
            "classify_refusal",
            "RESOLVER_TABLE",
            "loop {",
            "participants",
        ] {
            assert!(!codice.contains(vietato), "«{vietato}» nella schermata");
        }
        assert_eq!(codice.matches("identity_resolver::resolve(").count(), 1);
        assert!(!MAIN.contains("resolver::ask"), "nessun avvio la chiama");
    }

    /// **Un legame nasce soltanto dal gesto di una persona** (PR-10, controllo
    /// negativo 1): una sola chiamata al servizio dei legami, dentro la
    /// conferma; e nessun ordine dei soggetti diverso dal nome, perché un
    /// ordine diverso sarebbe un suggerimento (controllo negativo 2).
    #[test]
    fn un_legame_nasce_soltanto_da_un_gesto() {
        let codice = produzione();
        assert_eq!(codice.matches("link_from_resolution(").count(), 1);
        let Some(inizio) = codice.find("fn link(") else {
            panic!("la funzione del collegamento deve esistere");
        };
        let Some(dove) = codice.find("link_from_resolution(") else {
            panic!("il collegamento deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        assert!(
            dove > inizio && dove < inizio + fine,
            "soltanto dentro link"
        );
        assert_eq!(
            codice.matches("let frase = link(").count(),
            1,
            "chiamata dalla sola conferma"
        );
        let Some(conferma) = codice.find("on_resolver_link_confirm") else {
            panic!("la conferma deve esistere");
        };
        let Some(chiamata) = codice.find("let frase = link(") else {
            panic!("la chiamata deve esistere");
        };
        assert!(
            chiamata > conferma,
            "la chiamata sta nel gestore della conferma"
        );
        assert!(
            !MAIN.contains("link_from_resolution"),
            "nessun avvio collega"
        );
        assert_eq!(
            codice.matches(".sort").count(),
            1,
            "i soggetti si ordinano soltanto per nome"
        );
        assert!(codice.contains("aperti.sort();"));
        assert!(UI.contains(
            "Non è un giudizio sulla persona, e non dice nulla su condotte, appartenenze o opinioni."
        ));
    }

    /// **Senza dato e senza ragione il comando non si preme**, e la schermata
    /// dice il tetto e che cosa non si promette.
    #[test]
    fn la_schermata_dice_i_limiti() {
        assert!(
            UI.contains("enabled: root.resolver-input != \"\" && root.resolver-reason != \"\";")
        );
        assert!(crate::surface_text::assegna(
            UI,
            "text",
            lisi_services::identity_resolver::LIMITS_SENTENCE
        ));
        assert!(UI.contains("Da un nome utente non si ricava mai un numero"));
        assert!(UI.contains("Trovare un profilo non è un giudizio su una persona."));
    }

    /// **I generi della schermata sono quelli del dominio, nello stesso
    /// ordine.**
    #[test]
    fn i_generi_sono_quelli_del_dominio() {
        use lisi_core::model::identity_resolution::ResolutionInputKind;
        for (indice, genere) in ResolutionInputKind::ALL.iter().enumerate() {
            let Ok(indice) = i32::try_from(indice) else {
                panic!("indice piccolo");
            };
            assert_eq!(super::kind_at(indice), Some(*genere));
        }
        assert!(UI.contains(
            "model: [@tr(\"Nome utente\"), @tr(\"Numero di telefono\"), @tr(\"Identificativo Telegram\"), @tr(\"Collegamento\")];"
        ));
    }

    /// **Un rifiuto non svuota il modulo** (CA02-05, GAP-18): il modulo si
    /// chiude e il motivo si svuota soltanto dopo un collegamento riuscito.
    #[test]
    fn un_rifiuto_lascia_il_modulo_aperto_con_il_testo() {
        assert!(super::form_closes(&Ok(String::from("Collegato."))));
        assert!(!super::form_closes(&Err(String::from("motivo corto"))));

        let codice = include_str!("resolver.rs");
        let Some((produzione, _)) = codice.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some((_, gestore)) = produzione.split_once("window.on_resolver_link_confirm(") else {
            panic!("la conferma deve esistere");
        };
        let Some((gestore, _)) = gestore.split_once("window.on_resolver_link_cancel(") else {
            panic!("dopo la conferma viene l'annullamento");
        };
        let Some((prima, dentro)) = gestore.split_once("if form_closes(&frase) {") else {
            panic!("la chiusura deve dipendere dall'esito");
        };
        assert!(
            !prima.contains("set_resolver_link_reason(SharedString::default())"),
            "il motivo non si svuota prima di sapere se il collegamento è riuscito"
        );
        assert!(dentro.contains("set_resolver_link_reason(SharedString::default())"));
    }

    /// **Il registro mostra il numero di telefono mascherato, e il resto com'è
    /// stato scritto** (SUBJECT-02, CA02-04).
    #[test]
    fn il_registro_mostra_il_numero_mascherato() {
        use lisi_core::model::identity_resolution::ResolutionInputKind;
        let numero = super::input_shown(ResolutionInputKind::PhoneNumber.as_str(), "+390612345678");
        assert!(!numero.contains("0612345"), "{numero}");
        assert!(numero.ends_with("78"), "{numero}");
        assert!(numero.starts_with("numero di telefono: +"), "{numero}");
        let nome = super::input_shown(ResolutionInputKind::Username.as_str(), "@canale_cyber");
        assert!(nome.ends_with(": @canale_cyber"), "{nome}");
    }
}

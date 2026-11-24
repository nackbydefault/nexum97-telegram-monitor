//! I soggetti investigativi, nella schermata Persone (PERS-01).
//!
//! # Perché qui e non in una schermata propria
//!
//! Perché la confusione fra le due cose nascerebbe **esattamente qui**, davanti
//! a un elenco di nomi osservati con un comando accanto.
//!
//! L'elenco dei partecipanti è **derivato**: chi ha scritto durante un
//! monitoraggio. È un'osservazione, e non afferma niente su nessuno. Un soggetto
//! è qualcuno su cui l'ufficio ha deciso di aprire un fascicolo.
//!
//! Metterli nella stessa schermata, separati e con la differenza **scritta**, è
//! il posto dove quella frase serve. Una schermata separata avrebbe lasciato la
//! domanda senza risposta proprio dove qualcuno se la pone.
//!
//! # Nessun soggetto nasce da un'osservazione
//!
//! Non esiste un comando «apri un soggetto da questa riga». Sembrerebbe una
//! comodità — il nome ce l'abbiamo — e sarebbe esattamente ciò che il
//! congelamento vieta: «nessun profilo creato automaticamente per ogni utente
//! che compare in una fonte monitorata».
//!
//! Un soggetto si apre scrivendo **chi** e **perché**, in un campo vuoto.
//!
//! # La valutazione, da PERS-05
//!
//! Fino a PERS-04 questa intestazione diceva «nessuna valutazione», e prometteva
//! che sarebbe arrivata «con PERS-05: quattro stati con un nome, e un atto di un
//! operatore con motivo, istante e audit». **È arrivata così.**
//!
//! Ciò che non è cambiato, e non cambierà: **non c'è un punteggio, non c'è un
//! numero, e non c'è dove metterli**. La valutazione è una parola fra quattro,
//! la sceglie una persona, e porta il suo nome. La guardia che vieta i campi
//! numerici su una riga di soggetto è la stessa di PERS-01, ed è rimasta verde
//! attraverso questa milestone.
//!
//! # Valutare non riusa la ragione dell'apertura
//!
//! Sono due atti diversi, con due motivi diversi. Aprire dice «guardo questa
//! persona»; valutare dice «ho deciso che cosa penso». Riusare il primo farebbe
//! passare il secondo senza che nessuno l'abbia pensato.
//!
//! E **il motivo serve anche per ritirare**: una valutazione ritirata in
//! silenzio non dice se sia stata ritirata perché sbagliata o perché scomoda.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::assessment::{AssessedLevel, AssessmentAct};
use lisi_core::model::identity_link::LinkAct;
use lisi_core::model::person::NewPerson;
use lisi_core::model::reason::{MAX_REASON_CHARS, MIN_REASON_CHARS, OperationalReason};
use lisi_core::text::DisplayName;
use lisi_core::{PersonId, Timestamp};
use lisi_services::assessment::AssessmentService;
use lisi_services::association::AssociationService;
use lisi_services::identity_link::IdentityLinkService;
use lisi_services::person::PersonService;
use lisi_services::person_dossier::PersonDossierService;
use lisi_services::person_timeline::PersonTimelineService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, PersonRow, SubjectEntryRow};

/// I servizi della schermata: il fascicolo, il giudizio, i legami, e cio' che si
/// e' osservato delle identita' collegate.
///
/// # Perche' separati, e perche' NON si fondono
///
/// Perche' i primi tre sono **atti diversi**, con tre motivi diversi e tre
/// momenti diversi.
///
/// Aprire dice «guardo questa persona». Valutare dice «ho deciso che cosa
/// penso». Collegare dice «questa identita' osservata **e'** questa persona» —
/// ed e' la piu' concreta delle tre, quella che qualcuno dovra' saper ripetere.
///
/// Il congelamento chiede un motivo per ognuno, e sono tre motivi: chi ha
/// scritto perche' apriva non ha ancora scritto perche' valuta, e chi ha scritto
/// perche' valuta non ha ancora scritto perche' collega.
///
/// Il quarto (PERS-07) **non e' un atto**: raccoglie soltanto, e non scrive
/// niente. Ma raccoglie **solo cio' che un legame ha portato**, e ogni riga dice
/// da quale monitoraggio viene e chi l'ha collegato.
pub struct PersonScreens {
    subjects: PersonService,
    assessments: AssessmentService,
    links: IdentityLinkService,
    dossier: PersonDossierService,
    /// Note, riferimenti e nomi osservati (ADR-0153, DG-08): una connessione
    /// propria, perché scrive voci con il loro audit.
    records: lisi_services::Database,
}

/// Servizi dei soggetti, condivisi fra i gestori dei comandi.
pub type SharedPersons = Rc<RefCell<PersonScreens>>;

/// Costruisce i servizi sugli archivi indicati.
#[must_use]
pub fn create_service(
    subjects: lisi_services::Database,
    assessments: Option<lisi_services::Database>,
    links: Option<lisi_services::Database>,
    dossier: Option<[lisi_services::Database; 4]>,
    records: Option<lisi_services::Database>,
) -> Option<SharedPersons> {
    let [uno, due, tre, quattro] = dossier?;
    let records = records?;
    Some(Rc::new(RefCell::new(PersonScreens {
        subjects: PersonService::new(subjects),
        assessments: AssessmentService::new(assessments?),
        links: IdentityLinkService::new(links?),
        dossier: PersonDossierService::new(
            IdentityLinkService::new(uno),
            AssociationService::new(due),
            PersonTimelineService::new(tre),
            quattro,
        ),
        records,
    })))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Rilegge l'elenco dei soggetti.
pub fn refresh(window: &AppWindow, persons: &SharedPersons) {
    let Ok(elenco) = persons.borrow().subjects.all() else {
        window.set_person_message(crate::lingua::schermo(
            "I soggetti non sono leggibili in questo momento: quello qui sotto non dice che non ce \
             ne siano.",
        ));
        window.set_person_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    // I SOGGETTI CHIUSI RESTANO NELL'ELENCO: nasconderli direbbe che nessuno
    // ha mai aperto un fascicolo su quella persona.
    let righe: Vec<PersonRow> = elenco
        .iter()
        .map(|soggetto| {
            // LA VALUTAZIONE E LA SUA STORIA (PERS-05).
            //
            // Se non si leggono, la riga resta senza: mostrare NON VALUTATO
            // basandosi su una lettura fallita direbbe che nessuno si e'
            // espresso, che e' un'affermazione — e sarebbe falsa.
            let valutazione = persons
                .borrow()
                .assessments
                .current(soggetto.id)
                .map_err(|error| {
                    tracing::warn!(kind = error.kind(), "valutazione non leggibile");
                })
                .ok();
            let storia = persons
                .borrow()
                .assessments
                .history(soggetto.id)
                .unwrap_or_default();

            // I LEGAMI, E LA LORO STORIA (PERS-06).
            //
            // Se non si leggono, la riga resta senza: mostrare «nessuna
            // identita' collegata» basandosi su una lettura fallita direbbe che
            // nessuno ne ha collegate, che e' un'affermazione — e sarebbe falsa.
            let legami = persons
                .borrow()
                .links
                .current(soggetto.id)
                .map_err(|error| {
                    tracing::warn!(kind = error.kind(), "legami non leggibili");
                })
                .unwrap_or_default();
            let storia_legami = persons
                .borrow()
                .links
                .history(soggetto.id)
                .unwrap_or_default();

            // IL FASCICOLO MESSO INSIEME (PERS-07).
            //
            // Se non si compone, la sezione resta vuota e il registro lo dice:
            // un fascicolo che mostrasse meno di quello che c'e', senza dirlo,
            // sarebbe peggio di uno che non mostra niente.
            let fascicolo = comporre_il_fascicolo(persons, soggetto.id);

            PersonRow {
                id: i32::try_from(soggetto.id.get()).unwrap_or(i32::MAX),
                label: SharedString::from(soggetto.label.as_str()),
                // LA FRASE LA COMPONE IL MODELLO (DEC-252), e dice che un
                // fascicolo aperto non e' una valutazione.
                sentence: crate::lingua::schermo(soggetto.as_sentence()),
                reason: SharedString::from(soggetto.reason.as_str()),
                open: soggetto.is_open(),
                assessment_label: valutazione.as_ref().map_or_else(
                    || crate::lingua::schermo("NON LEGGIBILE"),
                    |v| crate::lingua::schermo(v.as_label()),
                ),
                assessment_sentence: valutazione.as_ref().map_or_else(
                    || {
                        crate::lingua::schermo(
                            "La valutazione non \u{e8} leggibile in questo momento. Questo non \
                             significa che il soggetto non sia valutato.",
                        )
                    },
                    |v| crate::lingua::schermo(v.as_sentence()),
                ),
                // LA STORIA COMPARE SOLO SE C'E' PIU' DI UN ATTO.
                //
                // Un atto solo lo dice gia' la frase sopra; ripeterlo sarebbe
                // rumore. Due o piu' raccontano come ci si e' arrivati, ed e'
                // esattamente cio' che chi rilegge deve poter vedere.
                assessment_history: ModelRc::from(Rc::new(VecModel::from(if storia.len() > 1 {
                    storia
                        .iter()
                        .map(|voce| crate::lingua::schermo(voce.as_sentence()))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                }))),
                // LE IDENTITA' COLLEGATE, E LA STORIA DEI LEGAMI (PERS-06).
                //
                // Ogni riga porta CHI ha collegato e QUANDO: un elenco di soli
                // identificativi si leggerebbe come un risultato del programma,
                // ed e' esattamente cio' che questi legami non sono.
                linked_identities: ModelRc::from(Rc::new(VecModel::from(
                    legami
                        .iter()
                        // L'ORIGINE PRIMA DELLA FRASE (PR-10): un legame e'
                        // la decisione di una persona, anche quando nasce da
                        // cio' che Telegram ha restituito a una ricerca.
                        .map(|legame| {
                            crate::lingua::schermo(format!(
                                "{} \u{2014} {}",
                                legame.origin().label(),
                                legame.as_sentence()
                            ))
                        })
                        .collect::<Vec<_>>(),
                ))),
                // LA STORIA DEI LEGAMI compare solo se qualcosa e' cambiato:
                // un legame mai sciolto lo dice gia' la riga sopra.
                link_history: ModelRc::from(Rc::new(VecModel::from(
                    if storia_legami.len() > legami.len() {
                        storia_legami
                            .iter()
                            .map(|voce| crate::lingua::schermo(voce.as_sentence()))
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    },
                ))),
                dossier: ModelRc::from(Rc::new(VecModel::from(fascicolo.clone()))),
                // NOTE E RIFERIMENTI (ADR-0153, DG-08): atti dell'operatore, con chi,
                // quando e perché, ritirati ma mai tolti.
                entries: ModelRc::from(Rc::new(VecModel::from(voci_della_scheda(
                    persons,
                    soggetto.id,
                )))),
                // NOMI OSSERVATI: dalle identità collegate, ricavati dai contenuti.
                // Sono osservazioni, mai identità, e la frase lo dice.
                observed_names: ModelRc::from(Rc::new(VecModel::from(nomi_osservati(
                    persons, &legami,
                )))),
            }
        })
        .collect();
    window.set_person_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Le voci della scheda, pronte per l'interfaccia (ADR-0153, DG-08).
///
/// Una lettura che non riesce non si nasconde: una riga lo dice, invece di
/// far credere che non ci siano note.
fn voci_della_scheda(persons: &SharedPersons, id: PersonId) -> Vec<SubjectEntryRow> {
    match lisi_services::subject_record::entries(&persons.borrow().records, id) {
        Ok(voci) => voci
            .iter()
            .map(|voce| SubjectEntryRow {
                id: i32::try_from(voce.stored.id).unwrap_or(-1),
                // LA FRASE LA COMPONE IL SERVIZIO (DEC-252).
                sentence: crate::lingua::schermo(voce.as_sentence()),
                withdrawn: voce.is_withdrawn(),
                content_id: voce
                    .content_target()
                    .and_then(|numero| i32::try_from(numero).ok())
                    .unwrap_or(-1),
            })
            .collect(),
        Err(errore) => {
            tracing::warn!(kind = errore.kind(), "voci del soggetto non leggibili");
            vec![SubjectEntryRow {
                id: -1,
                sentence: crate::lingua::schermo(
                    "Le note e i riferimenti non sono leggibili in questo momento: l'elenco non \
                     dice che non ce ne siano.",
                ),
                withdrawn: true,
                content_id: -1,
            }]
        }
    }
}

/// I nomi osservati delle identità collegate (ADR-0153, decisione 8).
fn nomi_osservati(
    persons: &SharedPersons,
    legami: &[lisi_core::model::identity_link::LinkedIdentity],
) -> Vec<SharedString> {
    let mut righe = Vec::new();
    for legame in legami {
        match lisi_services::subject_record::observed_names(
            &persons.borrow().records,
            &legame.identifier,
        ) {
            Ok(nomi) if nomi.is_empty() => righe.push(crate::lingua::schermo(format!(
                "Identit\u{e0} {}: nessun contenuto archiviato la mostra.",
                legame.identifier
            ))),
            Ok(nomi) => {
                for nome in nomi {
                    righe.push(crate::lingua::schermo(format!(
                        "Identit\u{e0} {}: {}",
                        legame.identifier,
                        nome.as_sentence()
                    )));
                }
            }
            Err(errore) => {
                righe.push(crate::lingua::schermo(errore.operator_message()));
                break;
            }
        }
    }
    righe
}

/// Scrive una nota sul soggetto.
fn write_note(window: &AppWindow, persons: &SharedPersons, id: i32, testo: &str) {
    let Ok(operatore) = crate::operator::audit_actor() else {
        window.set_person_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione: la nota non si scrive.",
        ));
        return;
    };
    let esito = lisi_services::subject_record::write_note(
        &mut persons.borrow_mut().records,
        PersonId::new(i64::from(id)),
        testo,
        &operatore,
        now(),
    );
    match esito {
        Ok(_) => {
            window.set_person_note_draft(SharedString::default());
            window.set_person_message(crate::lingua::schermo(
                "Nota scritta. Resta sulla scheda con chi l'ha scritta e quando; si ritira, non \
                 si cancella.",
            ));
        }
        Err(errore) => window.set_person_message(crate::lingua::schermo(errore.operator_message())),
    }
    refresh(window, persons);
}

/// Aggiunge un riferimento: il genere da un elenco chiuso, il bersaglio scritto.
fn add_reference(
    window: &AppWindow,
    persons: &SharedPersons,
    id: i32,
    genere: i32,
    bersaglio: &str,
    motivo: &str,
) {
    // UN NUMERO CHE NON SI LEGGE NON SI INDOVINA: la traduzione della scelta la
    // fa il servizio, in un posto solo.
    let Some(target) = lisi_services::subject_record::target_from_choice(genere, bersaglio) else {
        window.set_person_message(crate::lingua::schermo(
            "Scrivere il numero dell'archivio, che si legge accanto a ogni riga; per un \
             documento esterno, la sua indicazione.",
        ));
        return;
    };
    let Ok(ragione) = OperationalReason::try_new(motivo) else {
        window.set_person_message(crate::lingua::schermo(format!(
            "Scrivere perch\u{e9} si riferisce questa cosa al soggetto, fra {MIN_REASON_CHARS} e \
             {MAX_REASON_CHARS} caratteri; ne sono stati scritti {}.",
            motivo.trim().chars().count()
        )));
        return;
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        window.set_person_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione: il riferimento non si \
             aggiunge.",
        ));
        return;
    };
    let esito = lisi_services::subject_record::add_reference(
        &mut persons.borrow_mut().records,
        PersonId::new(i64::from(id)),
        target,
        &ragione,
        &operatore,
        now(),
    );
    match esito {
        Ok(_) => {
            window.set_person_ref_target(SharedString::default());
            window.set_person_ref_reason(SharedString::default());
            window.set_person_message(crate::lingua::schermo(
                "Riferimento aggiunto, con il suo perch\u{e9}.",
            ));
        }
        Err(errore) => window.set_person_message(crate::lingua::schermo(errore.operator_message())),
    }
    refresh(window, persons);
}

/// Ritira una voce, con il suo perché.
fn withdraw_entry(window: &AppWindow, persons: &SharedPersons, voce: i32, motivo: &str) {
    let Ok(ragione) = OperationalReason::try_new(motivo) else {
        window.set_person_message(crate::lingua::schermo(format!(
            "Scrivere perch\u{e9} si ritira, fra {MIN_REASON_CHARS} e {MAX_REASON_CHARS} \
             caratteri: un ritiro senza perch\u{e9} non dice se la voce era sbagliata o scomoda."
        )));
        return;
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        window.set_person_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione: nulla si ritira.",
        ));
        return;
    };
    let esito = lisi_services::subject_record::withdraw(
        &mut persons.borrow_mut().records,
        i64::from(voce),
        &ragione,
        &operatore,
        now(),
    );
    match esito {
        Ok(()) => {
            window.set_person_withdraw_reason(SharedString::default());
            window.set_person_message(crate::lingua::schermo(
                "Voce ritirata: resta sulla scheda, con chi l'ha ritirata, quando e perch\u{e9}.",
            ));
        }
        Err(errore) => window.set_person_message(crate::lingua::schermo(errore.operator_message())),
    }
    refresh(window, persons);
}

/// Compone le righe del fascicolo, pronte per l'interfaccia (PERS-07).
///
/// # Perché ogni riga porta il monitoraggio
///
/// Perché PERS-02, PERS-03 e PERS-04 hanno rifiutato tre volte di unire
/// monitoraggi diversi, e la ragione era la **tracciabilità**: «chi lo consegna
/// non potrebbe più dire a quale dei due si riferisce».
///
/// Qui l'unione è lecita **soltanto** perché ogni riga lo dice.
///
/// # Perché le avvertenze viaggiano con i dati
///
/// Perché se restassero nella schermata d'origine, chi legge il fascicolo
/// vedrebbe una cronologia senza sapere che è piena di buchi per costruzione, e
/// un elenco di collegamenti senza sapere che non sono un giudizio.
fn comporre_il_fascicolo(persons: &SharedPersons, id: PersonId) -> Vec<SharedString> {
    let Ok(identita) = persons.borrow().dossier.for_person(id) else {
        tracing::warn!("fascicolo non componibile: le osservazioni non sono leggibili");
        return Vec::new();
    };

    let mut righe: Vec<SharedString> = Vec::new();
    for voce in &identita {
        // PERCHE' QUESTA IDENTITA' E' QUI. Sempre, e per prima.
        righe.push(SharedString::from(voce.why_here()));

        if voce.nothing_observed() {
            // COLLEGATA MA MAI INCONTRATA: e' la situazione ordinaria, e dirlo
            // impedisce di leggere l'assenza come «non ha scritto».
            righe.push(crate::lingua::schermo(
                "Nessun monitoraggio ha incontrato questa identit\u{e0}. Non significa che non \
                 abbia scritto: significa che non l'abbiamo vista.",
            ));
            continue;
        }

        for osservato in &voce.observed {
            righe.push(crate::lingua::schermo(format!(
                "\u{2014} Monitoraggio \u{ab}{}\u{bb}:",
                osservato.session_label
            )));

            for gruppo in lisi_services::association::group_by_kind(&osservato.associations) {
                let (etichetta, elementi) = gruppo;
                righe.push(crate::lingua::schermo(format!(
                    "   {etichetta}: {} \u{2014} osservati in questo monitoraggio.",
                    elementi.len()
                )));
            }

            if let Some(cronologia) = osservato.timeline.as_ref() {
                righe.push(crate::lingua::schermo(format!(
                    "   Cronologia: {} righe osservate.",
                    cronologia.entries().len()
                )));
                // L'AVVERTENZA VIAGGIA CON I DATI.
                righe.push(crate::lingua::schermo(format!(
                    "   {}",
                    cronologia.caveat()
                )));
            }
        }
    }
    righe
}

/// Traduce la scelta dell'interfaccia in un atto del dominio.
///
/// # Perché un indice e non un testo
///
/// Perché l'interfaccia offre **quattro voci in un elenco chiuso**, e un testo
/// libero permetterebbe di inventarne una quinta: il congelamento ne prevede
/// quattro, e l'unico modo di non averne cinque è non poterle scrivere.
///
/// # Perché restituisce un'opzione
///
/// Perché lo zero è **NON VALUTATO**, che non è un livello: è il ritiro. Le
/// due cose sono atti diversi, e il tipo del dominio le tiene separate.
const fn atto_dalla_scelta(scelta: i32) -> Option<AssessmentAct> {
    match scelta {
        0 => Some(AssessmentAct::Withdraw),
        1 => Some(AssessmentAct::Assess(AssessedLevel::ToInvestigate)),
        2 => Some(AssessmentAct::Assess(AssessedLevel::OfInterest)),
        3 => Some(AssessmentAct::Assess(AssessedLevel::HighPriority)),
        // NESSUN ALTRO VALORE E' UN ATTO.
        //
        // Un indice fuori intervallo verrebbe da un errore, e trattarlo come
        // un livello scriverebbe un giudizio che nessuno ha scelto.
        _ => None,
    }
}

/// La frase che spiega perché una ragione non è stata accettata.
///
/// # Perché una frase sola per i due casi
///
/// Perché il gesto è lo stesso: scrivere di più. Dire «troppo corta» e «troppo
/// lunga» con due frasi diverse non aiuta chi deve rimediare, e la seconda non
/// capita quasi mai.
fn ragione_rifiutata(che_cosa: &str) -> SharedString {
    crate::lingua::schermo(format!(
        "{che_cosa} ha bisogno di una ragione scritta, di almeno {MIN_REASON_CHARS} caratteri e \
         non pi\u{f9} di {MAX_REASON_CHARS}. Non \u{e8} una formalit\u{e0}: chi apre un fascicolo \
         su una persona risponde di averlo aperto, e «il programma lo permetteva» non \u{e8} una \
         risposta. La soglia non rende buona una ragione \u{2014} rende visibile chi non ne sta \
         scrivendo una."
    ))
}

/// Apre un soggetto.
fn open(window: &AppWindow, persons: &SharedPersons, label: &str, reason: &str) {
    let Ok(nome) = DisplayName::try_new(label) else {
        window.set_person_message(crate::lingua::schermo(
            "Un soggetto ha bisogno di un nome: \u{e8} quello con cui l'ufficio lo chiama, e non \
             deve essere il nome che Telegram mostra.",
        ));
        return;
    };

    // LA RAGIONE E' UN TIPO, e non una stringa da controllare qui.
    //
    // Se non si costruisce, non c'e' modo di chiamare l'apertura: non e' una
    // convalida che qualcuno puo' dimenticare in un secondo punto.
    let Ok(ragione) = OperationalReason::try_new(reason) else {
        window.set_person_message(ragione_rifiutata("Aprire un soggetto"));
        return;
    };

    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_person_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    match persons
        .borrow()
        .subjects
        .open(&NewPerson::open(nome, ragione), &attore, now())
    {
        Ok(_) => {
            window.set_person_new_label(SharedString::default());
            window.set_person_new_reason(SharedString::default());
            window.set_person_message(crate::lingua::schermo(
                "Soggetto aperto. Un fascicolo aperto non \u{e8} una valutazione: dice che \
                 qualcuno ha deciso di raccogliere, e perch\u{e9}. La ragione resta scritta e non \
                 si modifica.",
            ));
        }
        Err(errore) => {
            window.set_person_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, persons);
}

/// Chiude un soggetto.
fn close(window: &AppWindow, persons: &SharedPersons, id: i32, reason: &str) {
    if id <= 0 {
        return;
    }

    let Ok(ragione) = OperationalReason::try_new(reason) else {
        window.set_person_message(ragione_rifiutata("Chiudere un soggetto"));
        return;
    };

    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_person_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    match persons
        .borrow()
        .subjects
        .close(PersonId::new(i64::from(id)), &attore, &ragione, now())
    {
        Ok(()) => {
            window.set_person_closing(0);
            window.set_person_closing_reason(SharedString::default());
            window.set_person_message(crate::lingua::schermo(
                "Soggetto chiuso. Resta leggibile: dice chi lo aveva aperto, perch\u{e9}, chi \
                 lo ha chiuso e perch\u{e9}. Non si riapre \u{2014} se il lavoro riprende, se ne \
                 apre uno nuovo.",
            ));
        }
        Err(errore) => {
            window.set_person_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, persons);
}

/// Registra un atto di valutazione su un soggetto.
///
/// # Perché la ragione non è quella dell'apertura
///
/// Perché sono due atti diversi. Chi ha scritto **perché apriva** non ha ancora
/// scritto **perché valuta**, e riusare la prima farebbe passare la seconda
/// senza che nessuno l'abbia pensata.
fn assess(window: &AppWindow, persons: &SharedPersons, id: i32, scelta: i32, reason: &str) {
    if id <= 0 {
        return;
    }

    let Some(atto) = atto_dalla_scelta(scelta) else {
        window.set_person_message(crate::lingua::schermo(
            "Quella scelta non corrisponde a nessuno dei quattro stati previsti, e non \u{e8} \
             stato registrato nulla.",
        ));
        return;
    };

    // LA RAGIONE E' UN TIPO, e serve ANCHE per ritirare.
    //
    // Una valutazione ritirata in silenzio non dice se sia stata ritirata
    // perche' sbagliata o perche' scomoda, e sono due cose molto diverse.
    let Ok(ragione) = OperationalReason::try_new(reason) else {
        window.set_person_message(ragione_valutazione_rifiutata(atto));
        return;
    };

    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_person_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    match persons.borrow().assessments.record(
        PersonId::new(i64::from(id)),
        atto,
        &ragione,
        &attore,
        now(),
    ) {
        Ok(_) => {
            window.set_person_assessing(0);
            window.set_person_assessment_reason(SharedString::default());
            window.set_person_message(SharedString::from(match atto {
                AssessmentAct::Withdraw => {
                    "Valutazione ritirata: il soggetto torna a NON VALUTATO. L'atto precedente \
                     resta scritto, con chi lo aveva espresso e perch\u{e9}."
                }
                AssessmentAct::Assess(_) => {
                    "Valutazione registrata. \u{c8} il giudizio di una persona, non un calcolo \
                     del programma: porta il tuo nome, l'istante e il motivo, e non si modifica. Se \
                     cambia, se ne registra una nuova."
                }
            }));
        }
        Err(errore) => {
            window.set_person_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, persons);
}

/// La frase che spiega perché una ragione di valutazione non è stata accettata.
///
/// # Perché una frase diversa da quella dell'apertura
///
/// Perché la posta è diversa, e la frase deve dirlo. Aprire un fascicolo è una
/// decisione di lavoro; **valutare è un giudizio su una persona**, e chi lo
/// scrive ne risponde in un modo che aprire non comporta.
fn ragione_valutazione_rifiutata(atto: AssessmentAct) -> SharedString {
    let che_cosa = match atto {
        AssessmentAct::Withdraw => "Ritirare una valutazione",
        AssessmentAct::Assess(_) => "Valutare un soggetto",
    };
    let perche = match atto {
        AssessmentAct::Withdraw => {
            "una valutazione ritirata in silenzio non dice se sia stata ritirata perch\u{e9} \
             sbagliata o perch\u{e9} scomoda, e sono due cose molto diverse per chi rilegge"
        }
        AssessmentAct::Assess(_) => {
            "un giudizio su una persona resta scritto con il tuo nome, e «il programma lo \
             permetteva» non \u{e8} una risposta"
        }
    };
    crate::lingua::schermo(format!(
        "{che_cosa} ha bisogno di un motivo scritto, di almeno {MIN_REASON_CHARS} caratteri e non \
         pi\u{f9} di {MAX_REASON_CHARS}: {perche}. La soglia non rende buono un motivo \u{2014} \
         rende visibile chi non ne sta scrivendo uno."
    ))
}

/// Registra un atto su un legame fra un'identità osservata e un soggetto.
///
/// # Perché il gesto parte dal fascicolo, e non da una riga osservata
///
/// Perché un comando «collega questa riga» accanto a un elenco di persone
/// osservate sarebbe **lo stesso difetto** che PERS-01 ha evitato non mettendo
/// un «apri un soggetto da questa riga»: sembrerebbe una comodità — l'identità
/// ce l'abbiamo — e trasformerebbe un'osservazione in un atto con un clic.
///
/// Qui si parte da un fascicolo che qualcuno ha aperto, e **si scrive**
/// l'identificativo: lo stesso gesto con cui si scrive il nome di un soggetto.
fn link(
    window: &AppWindow,
    persons: &SharedPersons,
    id: i32,
    identifier: &str,
    sciogli: bool,
    reason: &str,
) {
    if id <= 0 {
        return;
    }

    let atto = if sciogli {
        LinkAct::Unlink
    } else {
        LinkAct::Link
    };

    // IL MOTIVO E' UN TIPO, e serve ANCHE per sciogliere.
    //
    // Un legame sciolto in silenzio non dice se sia stato sciolto perche' era
    // sbagliato o perche' e' diventato scomodo.
    let Ok(ragione) = OperationalReason::try_new(reason) else {
        window.set_person_message(ragione_legame_rifiutata(atto));
        return;
    };

    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_person_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    match persons.borrow().links.record(
        PersonId::new(i64::from(id)),
        identifier,
        atto,
        &ragione,
        &attore,
        now(),
    ) {
        Ok(_) => {
            window.set_person_linking(0);
            window.set_person_link_identifier(SharedString::default());
            window.set_person_link_reason(SharedString::default());
            window.set_person_message(SharedString::from(match atto {
                LinkAct::Unlink => {
                    "Legame sciolto. Resta scritto che era esistito, con chi lo aveva fatto e \
                     perch\u{e9}. Se qualcuno ha lavorato su questo fascicolo mentre \
                     l'identit\u{e0} era collegata, quel lavoro resta leggibile."
                }
                LinkAct::Link => {
                    "Identit\u{e0} collegata. \u{c8} la decisione di una persona, non un \
                     risultato del programma: porta il tuo nome, l'istante e il motivo. Si pu\u{f2} \
                     sciogliere, e anche sciogliere chiede un motivo."
                }
            }));
        }
        Err(errore) => {
            window.set_person_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, persons);
}

/// La frase che spiega perché un motivo di collegamento non è stato accettato.
///
/// # Perché una frase propria, la terza
///
/// Perché la posta è ancora diversa. Aprire è una decisione di lavoro; valutare
/// è un giudizio; **collegare è un'affermazione di fatto**: dice che quella
/// identità osservata è quella persona. Se è sbagliata, tutto ciò che il
/// fascicolo raccoglie riguarda qualcun altro.
fn ragione_legame_rifiutata(atto: LinkAct) -> SharedString {
    let che_cosa = match atto {
        LinkAct::Unlink => "Sciogliere un legame",
        LinkAct::Link => "Collegare un'identit\u{e0} a un soggetto",
    };
    let perche = match atto {
        LinkAct::Unlink => {
            "un legame sciolto in silenzio non dice se sia stato sciolto perch\u{e9} era sbagliato \
             o perch\u{e9} \u{e8} diventato scomodo"
        }
        LinkAct::Link => {
            "\u{e8} un'affermazione di fatto \u{2014} che quell'identit\u{e0} \u{e8} quella persona \
             \u{2014} e se \u{e8} sbagliata tutto ci\u{f2} che il fascicolo raccoglie riguarda \
             qualcun altro"
        }
    };
    crate::lingua::schermo(format!(
        "{che_cosa} ha bisogno di un motivo scritto, di almeno {MIN_REASON_CHARS} caratteri e non \
         pi\u{f9} di {MAX_REASON_CHARS}: {perche}. La soglia non rende buono un motivo \u{2014} \
         rende visibile chi non ne sta scrivendo uno."
    ))
}

/// Collega i comandi.
pub fn wire(window: &AppWindow, persons: &SharedPersons) {
    // APRIRE PERSONE RICOMPONE I FASCICOLI (CA02-01).
    //
    // Si ricalcolavano all'avvio e dopo i quattro atti sulla scheda: non
    // aprendo la pagina, non dopo nuove acquisizioni, non dopo un collegamento
    // fatto dalla Ricerca puntuale. La scheda poteva affermare «nessun
    // monitoraggio ha incontrato questa identità» con due contenuti in
    // archivio: un falso negativo su una persona.
    {
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_persons_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &persons);
            }
        });
    }

    {
        // NOTE, RIFERIMENTI E RITIRI SULLA SCHEDA (ADR-0153, DG-08).
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_person_write_note(move |id, testo| {
            if crate::lock::refuse_while_locked("person_write_note") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                write_note(&window, &persons, id, testo.as_str());
            }
        });
    }

    {
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_person_add_reference(move |id, genere, bersaglio, motivo| {
            if crate::lock::refuse_while_locked("person_add_reference") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                add_reference(
                    &window,
                    &persons,
                    id,
                    genere,
                    bersaglio.as_str(),
                    motivo.as_str(),
                );
            }
        });
    }

    {
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_person_withdraw_entry(move |voce, motivo| {
            if crate::lock::refuse_while_locked("person_withdraw_entry") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                withdraw_entry(&window, &persons, voce, motivo.as_str());
            }
        });
    }

    {
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_link_identity(move |id, identifier, sciogli, reason| {
            if crate::lock::refuse_while_locked("link_identity") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                link(
                    &window,
                    &persons,
                    id,
                    identifier.as_str(),
                    sciogli,
                    reason.as_str(),
                );
            }
        });
    }

    {
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_assess_person(move |id, scelta, reason| {
            if crate::lock::refuse_while_locked("assess_person") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                assess(&window, &persons, id, scelta, reason.as_str());
            }
        });
    }

    {
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_open_person(move |label, reason| {
            if crate::lock::refuse_while_locked("open_person") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                open(&window, &persons, label.as_str(), reason.as_str());
            }
        });
    }

    {
        let handle = window.as_weak();
        let persons = Rc::clone(persons);
        window.on_close_person(move |id, reason| {
            if crate::lock::refuse_while_locked("close_person") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close(&window, &persons, id, reason.as_str());
            }
        });
    }
}

/// Quante righe l'elenco mostra: serve alle prove.
#[cfg(test)]
fn conta_soggetti(window: &AppWindow) -> usize {
    use slint::Model as _;
    window.get_person_rows().iter().count()
}

#[cfg(test)]
mod tests {
    use lisi_core::model::assessment::{AssessedLevel, AssessmentAct};
    use lisi_core::model::identity_link::LinkAct;

    use super::conta_soggetti;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("person.rs");

    /// Il file dell'interfaccia.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco della schermata Persone, e nient'altro.
    ///
    /// # Perché finisce alla pagina successiva
    ///
    /// Perché un confine scritto a mano smette di valere quando qualcuno
    /// inserisce una pagina in mezzo, e la guardia si mette a leggere due
    /// schermate senza dirlo. È successo con SEARCH-01.
    fn schermata_delle_persone() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(14)
    }

    /// **Non esiste un comando che apre un soggetto da un'osservazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Quello che la Fase 6 nomina nella propria intestazione: «non si crea un
    /// profilo per ogni utente Telegram solo perché compare in una fonte
    /// monitorata».
    ///
    /// Un comando «apri un soggetto da questa riga», accanto all'elenco dei
    /// partecipanti, sembrerebbe la cosa più naturale del mondo — il nome ce
    /// l'abbiamo — e trasformerebbe ogni persona osservata in un candidato a
    /// un clic di distanza.
    #[test]
    fn non_esiste_un_comando_che_apre_da_una_osservazione() {
        let schermata = schermata_delle_persone();
        // Il comando che apre non compare DENTRO l'elenco dei partecipanti.
        let Some(elenco) = schermata.find("for person in root.participants:") else {
            panic!("l'elenco dei partecipanti deve esistere");
        };
        let Some(fine_elenco) = schermata[elenco..].find("\n                            }") else {
            panic!("l'elenco deve chiudersi");
        };
        assert!(
            !schermata[elenco..elenco + fine_elenco].contains("open-person"),
            "un comando che apre un soggetto dentro l'elenco delle persone osservate \
             trasformerebbe ogni riga in un candidato a un clic di distanza"
        );

        // E il modulo non sa nemmeno che cosa sia un partecipante.
        let codice = codice_senza_commenti();
        for osservazione in ["Participant", "participants", "Content", "author"] {
            assert!(
                !codice.contains(osservazione),
                "il modulo nomina «{osservazione}»: un soggetto si apre perche' qualcuno lo \
                 decide"
            );
        }
    }

    /// **La schermata dice la differenza fra un'osservazione e un soggetto.**
    ///
    /// # Perché conta
    ///
    /// Perché è la sola cosa che impedisce a chi guarda di leggere le due liste
    /// come la stessa. E va detta **lì**, dove le due liste si vedono insieme:
    /// una spiegazione in un manuale non la legge nessuno.
    #[test]
    fn la_schermata_dice_la_differenza() {
        let schermata = schermata_delle_persone();
        assert!(
            schermata.contains("Un soggetto non è una persona dell'elenco qui sopra"),
            "la differenza va detta dove le due liste si vedono insieme"
        );
        assert!(
            schermata.contains("Nessuno diventa un soggetto per aver scritto in un gruppo"),
            "e va detta come divieto, non come sfumatura"
        );
    }

    /// **Aprire e chiudere vogliono entrambi una ragione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una chiusura senza motivo. Non direbbe se il fascicolo sia stato chiuso
    /// perché non c'era niente o perché nessuno se ne occupava più, e sono due
    /// esiti diversi.
    #[test]
    fn aprire_e_chiudere_vogliono_una_ragione() {
        let schermata = schermata_delle_persone();
        assert!(
            crate::surface_text::assegna(&schermata, "label", "Ragione operativa, obbligatoria"),
            "aprire vuole una ragione"
        );
        assert!(
            crate::surface_text::assegna(
                &schermata,
                "label",
                "Ragione della chiusura, obbligatoria"
            ),
            "e chiuderlo anche"
        );

        // IL CONTEGGIO DEI COMANDI STA IN UNA PROVA SOLA.
        //
        // Fino a PERS-05 stava qui, e diceva «due» e poi «tre». Da PERS-06 il
        // numero e' quattro e vive in `quattro_comandi_quattro_motivi`: due
        // prove che contano la stessa cosa con due numeri diversi si
        // contraddicono, e la prima che qualcuno aggiorna vince senza che
        // nessuno se ne accorga.
        //
        // Il conteggio NON e' stato tolto: e' stato spostato, e il numero e'
        // salito.
    }

    /// **Valutare vuole un motivo proprio, diverso da quello dell'apertura.**
    ///
    /// # Il difetto che questa prova impedisce (PERS-05)
    ///
    /// Che il motivo scritto **aprendo** valga anche per **valutare**. Sono due
    /// atti diversi: aprire dice «guardo questa persona», valutare dice «ho
    /// deciso che cosa penso». Riusare il primo farebbe passare il secondo senza
    /// che nessuno l'abbia pensato.
    #[test]
    fn valutare_vuole_un_motivo_proprio() {
        let schermata = schermata_delle_persone();
        assert!(
            schermata.contains("root.person-assessment-reason"),
            "il campo del motivo della valutazione deve esistere nella schermata"
        );
        assert!(
            !schermata.contains("root.assess-person(soggetto.id, root.person-assessment-choice, root.person-new-reason)"),
            "valutare non deve riusare la ragione dell'apertura"
        );

        let codice = codice_senza_commenti();
        assert!(
            codice.contains("fn ragione_valutazione_rifiutata"),
            "il rifiuto di un motivo di valutazione ha una frase propria: la posta e' diversa"
        );
    }

    /// **Il motivo serve anche per ritirare una valutazione.**
    ///
    /// # Perché conta
    ///
    /// Perché una valutazione ritirata in silenzio non dice se sia stata
    /// ritirata **perché sbagliata** o **perché scomoda**, e sono due cose molto
    /// diverse per chi rilegge un fascicolo.
    #[test]
    fn ritirare_vuole_un_motivo_come_valutare() {
        let frase = super::ragione_valutazione_rifiutata(AssessmentAct::Withdraw).to_string();
        assert!(frase.starts_with("Ritirare una valutazione"), "{frase}");
        assert!(
            frase.contains("perch\u{e9} sbagliata o perch\u{e9} scomoda"),
            "la frase deve dire perche' serve: {frase}"
        );
    }

    /// **Collegare parte dal fascicolo, non da una riga osservata (PERS-06).**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un comando «collega questa riga» accanto all'elenco delle persone
    /// osservate. Sarebbe **lo stesso difetto** che PERS-01 ha evitato non
    /// mettendo un «apri un soggetto da questa riga»: sembrerebbe una comodità —
    /// l'identità ce l'abbiamo — e trasformerebbe un'osservazione in un atto con
    /// un clic.
    ///
    /// La schermata dei partecipanti non deve nominare il comando, e
    /// l'identificativo deve **scriversi**.
    #[test]
    fn collegare_parte_dal_fascicolo_non_da_una_riga_osservata() {
        // NELLA SEZIONE DEI SOGGETTI il comando c'e', e l'identificativo si
        // scrive in un campo vuoto.
        assert!(
            UI.contains("root.person-link-identifier"),
            "l'identificativo si scrive"
        );
        assert!(
            UI.contains("root.link-identity("),
            "il comando esiste, e parte dal fascicolo"
        );

        // E NON C'E' UN ELENCO DA CUI SCEGLIERLO.
        //
        // Un elenco di identita' osservate accanto al comando sarebbe la
        // proposta che il congelamento vieta, anche senza calcolare nulla:
        // basterebbe che qualcuno la scorresse cercando un nome somigliante.
        for proposta in [
            "person-link-candidates",
            "person-link-suggestions",
            "link-candidates",
        ] {
            assert!(
                !UI.contains(proposta),
                "«{proposta}»: un elenco da cui scegliere e' una proposta, e le proposte sono \
                 vietate"
            );
        }
    }

    /// **Ogni riga del fascicolo dice da quale monitoraggio viene (PERS-07).**
    ///
    /// # Perché è la guardia di questa milestone
    ///
    /// Perché PERS-02, PERS-03 e PERS-04 hanno rifiutato **tre volte** di unire
    /// monitoraggi diversi, e la ragione era la **tracciabilità**: «chi lo
    /// consegna non potrebbe più dire a quale dei due si riferisce».
    ///
    /// Qui l'unione è lecita **soltanto** perché ogni riga lo dice. Se la
    /// composizione smettesse di nominare il monitoraggio, la deroga
    /// diventerebbe una scorciatoia.
    #[test]
    fn ogni_riga_del_fascicolo_dice_da_quale_monitoraggio_viene() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("Monitoraggio \\u{ab}{}\\u{bb}")
                || codice.contains("osservato.session_label"),
            "la composizione deve nominare il monitoraggio di ogni blocco"
        );
        assert!(
            codice.contains("voce.why_here()"),
            "e ogni identita' deve dire perche' e' sul fascicolo"
        );
    }

    /// **Un'identità collegata ma mai incontrata lo dichiara.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un'identità collegata senza righe sotto, che si legge come «non ha
    /// scritto». È la situazione **ordinaria** — nessun monitoraggio l'ha
    /// incontrata — ed è la stessa distinzione di PERS-04 fra un vuoto e un
    /// silenzio.
    #[test]
    fn un_identita_collegata_ma_mai_incontrata_lo_dichiara() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("Non significa che non \\u{e0}")
                || codice.contains("non l'abbiamo vista"),
            "l'assenza di osservazioni va dichiarata, non lasciata leggere come un'assenza di atti"
        );
    }

    /// **La scheda del soggetto dice dove si guarda il grafo.**
    ///
    /// # Perché questa prova ha cambiato verso
    ///
    /// Fino a PR-01 pretendeva che la scheda dicesse «il grafo non ha ancora una
    /// schermata: arriverà con GRAPH-02». GRAPH-02 l'ha costruita, e la prova
    /// continuava a esigere una frase **diventata falsa**: una guardia che
    /// difende un'affermazione superata è peggio di nessuna guardia, perché la
    /// fa sembrare vera. Il censimento del linguaggio l'ha trovata (ADR-0117).
    ///
    /// Ora la scheda rimanda alla schermata per nome, e non nomina più una
    /// milestone: un codice di lavoro non è un'informazione per chi legge.
    #[test]
    fn la_scheda_rimanda_alla_schermata_del_grafo() {
        assert!(
            UI.contains("Il grafo delle prove ha una sua schermata, «Grafo»"),
            "la scheda deve dire dove si guarda il grafo"
        );
        assert!(
            !UI.contains("arriverà con GRAPH-02"),
            "la scheda non deve promettere una schermata che esiste già"
        );
    }

    /// **Sciogliere chiede un motivo come collegare.**
    #[test]
    fn sciogliere_chiede_un_motivo_come_collegare() {
        let frase = super::ragione_legame_rifiutata(LinkAct::Unlink).to_string();
        assert!(frase.starts_with("Sciogliere un legame"), "{frase}");
        assert!(
            frase.contains("perch\u{e9} era sbagliato o perch\u{e9} \u{e8} diventato scomodo"),
            "la frase deve dire perche' serve: {frase}"
        );

        let collegare = super::ragione_legame_rifiutata(LinkAct::Link).to_string();
        assert!(
            collegare.contains("affermazione di fatto"),
            "collegare ha la sua ragione, ed e' diversa: {collegare}"
        );
    }

    /// **Quattro comandi, quattro motivi.**
    ///
    /// # Perché il numero sale, e perché è un rafforzamento
    ///
    /// Perché ogni milestone che aggiunge un atto su una persona aggiunge anche
    /// il suo motivo. Erano due fino a PERS-04, tre con PERS-05, quattro con
    /// PERS-06. **Se un giorno scendesse, uno degli atti avrebbe smesso di
    /// chiedere il motivo.**
    #[test]
    fn quattro_comandi_quattro_motivi() {
        let codice = codice_senza_commenti();
        assert_eq!(
            codice.matches("OperationalReason::try_new(reason)").count(),
            4,
            "i quattro comandi che scrivono su una persona \u{2014} aprire, chiudere, valutare, \
             collegare \u{2014} costruiscono il motivo, e senza non proseguono"
        );
    }

    /// **Lo zero della scelta è il ritiro, non un livello.**
    ///
    /// # Perché conta
    ///
    /// Perché «NON VALUTATO» non è un giudizio: è l'assenza di un giudizio.
    /// Trattarlo come il livello più basso di una scala lo renderebbe un
    /// giudizio, e sarebbe quello dato a chi non è stato giudicato.
    #[test]
    fn lo_zero_e_il_ritiro_non_un_livello() {
        assert_eq!(
            super::atto_dalla_scelta(0),
            Some(AssessmentAct::Withdraw),
            "lo zero ritira, non valuta"
        );
        for (scelta, livello) in [
            (1, AssessedLevel::ToInvestigate),
            (2, AssessedLevel::OfInterest),
            (3, AssessedLevel::HighPriority),
        ] {
            assert_eq!(
                super::atto_dalla_scelta(scelta),
                Some(AssessmentAct::Assess(livello))
            );
        }

        // FUORI INTERVALLO NON E' UN ATTO.
        //
        // Trattarlo come un livello scriverebbe un giudizio che nessuno ha
        // scelto, ed e' il genere di difetto che nasce da un elenco riordinato.
        for fuori in [-1, 4, 99] {
            assert_eq!(
                super::atto_dalla_scelta(fuori),
                None,
                "«{fuori}» non corrisponde a nessuno dei quattro stati"
            );
        }
    }

    /// **La schermata non mostra una valutazione, e non ha dove prenderla.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il congelamento lo nomina tre volte: mai una percentuale di
    /// pericolosità, nessuna attribuzione automatica di responsabilità, nessuna
    /// classificazione automatica di una persona.
    #[test]
    fn la_schermata_non_mostra_una_valutazione() {
        let Some(inizio) = UI.find("export struct PersonRow {") else {
            panic!("la struttura deve esistere");
        };
        let Some(fine) = UI[inizio..].find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        let campi = &UI[inizio..inizio + fine];
        for numerico in [": int", ": float", ": percent"] {
            // L'identificativo e' l'unico intero ammesso, e non e' una misura.
            let quanti = campi.matches(numerico).count();
            if numerico == ": int" {
                assert_eq!(
                    quanti, 1,
                    "il solo intero ammesso e' l'identificativo: ogni altro numero su una \
                     persona diventa una misura"
                );
            } else {
                assert_eq!(quanti, 0, "«{numerico}» non ha posto su una persona");
            }
        }

        let codice = codice_senza_commenti().to_lowercase();
        for valutazione in ["score", "punteggio", "rischio", "pericolosit", "probabilit"] {
            assert!(
                !codice.contains(valutazione),
                "il modulo nomina «{valutazione}»: la valutazione e' un atto umano, arriva con \
                 PERS-05, e non e' un numero"
            );
        }
    }

    /// **La frase che rifiuta una ragione dice perché, non «non valido».**
    ///
    /// # Perché guarda la frase e non il sorgente
    ///
    /// Perché il sorgente la spezza dove `cargo fmt` decide, e una guardia che
    /// cercasse la frase intera fra le righe diventerebbe rossa alla prima
    /// riformattazione — senza che nulla sia peggiorato. Qui si costruisce la
    /// frase e si guarda **quella**, che è ciò che l'operatore legge.
    #[test]
    fn la_frase_che_rifiuta_dice_perche() {
        let frase = super::ragione_rifiutata("Aprire un soggetto").to_string();

        assert!(frase.starts_with("Aprire un soggetto"), "{frase}");
        assert!(
            frase.contains("rende visibile chi non ne sta scrivendo una"),
            "la frase deve dire che cosa la soglia fa e che cosa non fa \u{2014} {frase}"
        );
        assert!(
            frase.contains(&lisi_core::model::reason::MIN_REASON_CHARS.to_string()),
            "e deve dire quanti caratteri servono \u{2014} {frase}"
        );

        // I NUMERI VENGONO DALLA REGOLA CONDIVISA, non riscritti a mano: due
        // soglie divergono il giorno in cui una si muove.
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("MIN_REASON_CHARS") && codice.contains("MAX_REASON_CHARS"),
            "la frase deve leggere le soglie da dove sono decise"
        );
    }

    /// **La schermata non conosce l'archivio.**
    #[test]
    fn la_schermata_non_conosce_l_archivio() {
        assert!(
            !codice_senza_commenti().contains("lisi_storage"),
            "l'interfaccia dipende soltanto dai servizi applicativi (ADR-0010)"
        );
    }

    /// **L'elenco parte vuoto.**
    #[test]
    fn l_elenco_parte_vuoto() {
        // L'event loop di winit si crea una volta sola per processo (NOTE-01).
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        assert_eq!(conta_soggetti(&window), 0);
    }
}

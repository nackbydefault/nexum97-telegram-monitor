//! Collegamento fra la schermata Persone e il servizio che compone l'elenco.
//!
//! # Perché la schermata mostra una cosa sola per volta
//!
//! O la richiesta della ragione, o l'elenco. Mai entrambi: un elenco mostrato
//! accanto alla richiesta di motivarlo suggerirebbe che la richiesta sia
//! facoltativa, e sarebbe il modo più efficace di svuotarla senza toglierla.
//!
//! Le scelte sono in `docs/adr/ADR-0024-PARTICIPANTS.md`.

use std::rc::Rc;

use lisi_services::association::AssociationService;
use lisi_services::observed_identity::ObservedIdentityService;
use lisi_services::participants::ParticipantService;
use lisi_services::person_timeline::PersonTimelineService;
use lisi_services::{ServiceError, ServiceResult};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, ParticipantEntry};

/// I quattro servizi della schermata: chi ha scritto, come si e' chiamato, a che
/// cosa risulta collegato, e quando lo si e' visto.
///
/// # Perche' quattro, e non uno
///
/// Perche' sono quattro domande diverse. «Chi ha scritto» e' un elenco di
/// persone; «come si e' chiamato nel tempo» e' la storia di una di esse
/// (PERS-02); «a che cosa risulta collegato» sono le associazioni con la loro
/// provenienza (PERS-03); «quando lo si e' visto» e' la cronologia, con le
/// finestre in cui si stava guardando (PERS-04).
///
/// Vogliono tutti e quattro la **stessa ragione registrata**, e nessuno la
/// scrive: la scrive il comando dedicato, e ne basta una. Quattro
/// autorizzazioni dove ce n'e' una bloccherebbero una funzione senza che chi la
/// usa capisca quale frase manchi.
pub struct ParticipantScreens {
    participants: ParticipantService,
    identities: ObservedIdentityService,
    associations: AssociationService,
    timelines: PersonTimelineService,
}

/// Servizi della schermata, condivisi fra i gestori dei comandi.
pub type SharedParticipants = Rc<ParticipantScreens>;

/// Crea i servizi sugli archivi indicati.
#[must_use]
pub fn create_service(
    participants: Option<lisi_services::Database>,
    identities: Option<lisi_services::Database>,
    associations: Option<lisi_services::Database>,
    timelines: Option<lisi_services::Database>,
) -> Option<SharedParticipants> {
    Some(Rc::new(ParticipantScreens {
        participants: ParticipantService::new(participants?),
        identities: ObservedIdentityService::new(identities?),
        associations: AssociationService::new(associations?),
        timelines: PersonTimelineService::new(timelines?),
    }))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// La storia degli alias di un'identità, pronta per l'interfaccia (PERS-02).
///
/// # Perché due valori e non uno
///
/// Perché l'elenco dei nomi e **l'avvertenza su che cosa gli istanti non
/// dicono** hanno due destini diversi: l'elenco compare riga per riga,
/// l'avvertenza una volta e in ambra. Metterla in coda all'elenco la
/// renderebbe una riga come le altre, e chi scorre non la leggerebbe.
#[derive(Clone)]
struct StoriaDegliAlias {
    righe: Vec<SharedString>,
    avvertenza: SharedString,
}

impl StoriaDegliAlias {
    /// Nessuna storia: chi ha portato lo stesso nome non ne ha una.
    fn nessuna() -> Self {
        Self {
            righe: Vec::new(),
            avvertenza: SharedString::default(),
        }
    }

    /// La storia di un'identità osservata, se c'è qualcosa da raccontare.
    fn di(identita: &lisi_core::model::observed_identity::ObservedIdentity) -> Self {
        // SOLO SE QUALCOSA E' CAMBIATO.
        //
        // Mostrare «si e' sempre chiamato cosi'» sotto ogni riga sarebbe
        // rumore, e il rumore fa smettere di leggere anche cio' che conta.
        if !identita.has_any_history() {
            return Self::nessuna();
        }
        Self {
            righe: identita
                .aliases
                .iter()
                .map(|alias| crate::lingua::schermo(alias.as_sentence()))
                .collect(),
            avvertenza: crate::lingua::schermo(identita.as_sentence()),
        }
    }
}

/// Le associazioni di un'identità, pronte per l'interfaccia (PERS-03).
///
/// # Perché due valori, come per gli alias
///
/// Perché l'elenco di ciò che risulta collegato e **la frase che dice che cosa
/// quei collegamenti non significano** hanno due destini diversi. La seconda
/// compare una volta e in ambra: in coda all'elenco sarebbe una riga come le
/// altre, e chi scorre non la leggerebbe.
#[derive(Clone)]
struct Associazioni {
    righe: Vec<SharedString>,
    avvertenza: SharedString,
}

impl Associazioni {
    /// Nessuna: chi non ha scritto non risulta collegato a niente.
    fn nessuna() -> Self {
        Self {
            righe: Vec::new(),
            avvertenza: SharedString::default(),
        }
    }

    /// Le associazioni di un'identità, raggruppate per genere.
    fn di(associazioni: &[lisi_core::model::association::PersonAssociation]) -> Self {
        let gruppi = lisi_services::association::group_by_kind(associazioni);
        // SOLO IL FATTO PRIMO NON BASTA.
        //
        // Ogni persona che ha scritto ha almeno un contenuto e una fonte:
        // mostrarli come «associazioni» sotto ognuna sarebbe ripetere l'elenco
        // dei partecipanti con altre parole, ed e' rumore. La sezione compare
        // quando c'e' qualcosa che l'elenco non diceva gia': un alert, un
        // indicatore, un workspace.
        let qualcosa_da_dire = gruppi
            .iter()
            .any(|(etichetta, _)| matches!(*etichetta, "Alert" | "Indicatore" | "Raccoglitore"));
        if !qualcosa_da_dire {
            return Self::nessuna();
        }

        let mut righe: Vec<SharedString> = Vec::new();
        for (etichetta, elementi) in &gruppi {
            // I contenuti e le fonti restano fuori: li dice gia' la riga della
            // persona, con il conteggio dei messaggi e delle fonti.
            if matches!(*etichetta, "Contenuto" | "Fonte") {
                continue;
            }
            for associazione in elementi {
                righe.push(crate::lingua::schermo(format!(
                    "{} \u{2014} {}",
                    lisi_services::association::target_label(associazione.target()),
                    associazione.provenance().as_sentence()
                )));
            }
        }

        Self {
            righe,
            avvertenza: crate::lingua::schermo(
                "Questi collegamenti dicono che la persona ha scritto un contenuto, e che quel \
                 contenuto ha una certa propriet\u{e0}. Non dicono che la persona sia o abbia \
                 fatto altro, e non sono una valutazione: quella la scrive una persona, con un \
                 motivo.",
            ),
        }
    }
}

/// La cronologia di un'identità, pronta per l'interfaccia (PERS-04).
///
/// # Perché tre valori e non uno
///
/// Perché le righe, **le finestre in cui si stava guardando** e l'avvertenza
/// hanno tre destini diversi. Le finestre non sono un contorno: sono l'unica
/// cosa che rende leggibile un vuoto, e senza di esse un periodo senza righe si
/// legge come «non ha fatto niente».
#[derive(Clone)]
struct Cronologia {
    righe: Vec<SharedString>,
    finestre: Vec<SharedString>,
    avvertenza: SharedString,
}

impl Cronologia {
    /// Nessuna: chi non ha scritto non ha una cronologia.
    fn nessuna() -> Self {
        Self {
            righe: Vec::new(),
            finestre: Vec::new(),
            avvertenza: SharedString::default(),
        }
    }

    /// La cronologia di un'identità osservata.
    fn di(cronologia: &lisi_core::model::person_timeline::PersonTimeline) -> Self {
        // UNA SOLA RIGA NON E' UNA CRONOLOGIA.
        //
        // Chi ha scritto una volta sola ha gia' tutto nella riga della persona:
        // una «cronologia» di un elemento sarebbe rumore, ed e' la lezione di
        // PERS-02 e PERS-03.
        if cronologia.entries().len() < 2 {
            return Self::nessuna();
        }

        Self {
            righe: cronologia
                .entries()
                .iter()
                .map(|riga| {
                    crate::lingua::schermo(format!(
                        "{} \u{2014} {}",
                        riga.at.to_readable_local(),
                        riga.event.as_sentence()
                    ))
                })
                .collect(),
            finestre: cronologia
                .windows()
                .iter()
                .map(|finestra| crate::lingua::schermo(finestra.as_sentence()))
                .collect(),
            avvertenza: SharedString::from(cronologia.caveat()),
        }
    }
}

/// Traduce una persona in una riga dell'interfaccia.
fn row(
    person: &lisi_services::participants::Participant,
    storia: &StoriaDegliAlias,
    associazioni: &Associazioni,
    cronologia: &Cronologia,
) -> ParticipantEntry {
    ParticipantEntry {
        identifier: SharedString::from(person.identifier.as_str()),
        display_name: person
            .display_name
            .as_deref()
            .map_or_else(SharedString::default, SharedString::from),
        username: person
            .username
            .as_deref()
            .map_or_else(SharedString::default, |username| {
                crate::lingua::schermo(format!("@{username}"))
            }),
        messages: SharedString::from(if person.messages == 1 {
            String::from("1 messaggio")
        } else {
            format!("{} messaggi", person.messages)
        }),
        sources: SharedString::from(if person.sources.len() == 1 {
            String::from("1 fonte")
        } else {
            format!("{} fonti", person.sources.len())
        }),
        first_seen: SharedString::from(person.first_seen.to_readable_local()),
        last_seen: SharedString::from(person.last_seen.to_readable_local()),
        alias_history: ModelRc::from(Rc::new(VecModel::from(storia.righe.clone()))),
        alias_caveat: storia.avvertenza.clone(),
        associations: ModelRc::from(Rc::new(VecModel::from(associazioni.righe.clone()))),
        associations_caveat: associazioni.avvertenza.clone(),
        timeline: ModelRc::from(Rc::new(VecModel::from(cronologia.righe.clone()))),
        timeline_windows: ModelRc::from(Rc::new(VecModel::from(cronologia.finestre.clone()))),
        timeline_caveat: cronologia.avvertenza.clone(),
    }
}

/// Riporta nell'interfaccia lo stato della schermata.
pub fn refresh(window: &AppWindow, service: &SharedParticipants, message: Option<&str>) {
    if let Some(text) = message {
        window.set_participants_message(SharedString::from(text));
    }

    let recorded = service
        .participants
        .basis_recorded()
        .unwrap_or_else(|error| {
            tracing::warn!(kind = error.kind(), "audit non leggibile");
            // Non leggibile non è «registrata»: mostrare l'elenco basandosi su una
            // lettura fallita significherebbe produrlo senza sapere se una ragione
            // esiste, che è precisamente ciò che il controllo impedisce.
            false
        });
    window.set_participants_basis_recorded(recorded);

    if !recorded {
        window.set_participants(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_participants_session_id(0);
        window.set_participants_sessions(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    }

    // Il selettore dei monitoraggi. La più recente per prima: è quella che si
    // guarda quasi sempre, e metterla in fondo costringerebbe a scorrere ogni
    // volta un elenco che cresce.
    //
    // Non c'è una voce «tutti i monitoraggi», e la differenza con lo Storico è
    // voluta: un elenco di persone che unisce monitoraggi diversi mette insieme
    // atti diversi, e chi lo consegna non potrebbe più dire a quale dei due si
    // riferisce.
    let sessions = readable_sessions(service);
    // L'etichetta porta anche l'istante: due monitoraggi possono chiamarsi
    // allo stesso modo, e sceglierne uno per nome vorrebbe dire sceglierne uno
    // a caso.
    let labels: Vec<SharedString> = sessions
        .iter()
        .map(|session| {
            crate::lingua::schermo(format!(
                "{} \u{2014} {}",
                session.label.as_str(),
                session.created_at.to_readable_local()
            ))
        })
        .collect();

    // Un indice rimasto oltre la fine — perché l'elenco si è accorciato —
    // punterebbe a un monitoraggio diverso da quello scelto.
    let chosen = window.get_participants_session_index();
    let chosen = if usize::try_from(chosen).is_ok_and(|value| value < labels.len()) {
        chosen
    } else {
        0
    };
    window.set_participants_session_index(chosen);
    window.set_participants_sessions(ModelRc::from(Rc::new(VecModel::from(labels))));

    let scelta = usize::try_from(chosen)
        .ok()
        .and_then(|position| sessions.get(position));
    // Il monitoraggio scelto, per la scheda «Foto, biografia e stato»
    // (PERSON-MEDIA-01): la richiesta vale per un autore di QUESTO monitoraggio.
    window.set_participants_session_id(
        scelta.map_or(0, |session| i32::try_from(session.id.get()).unwrap_or(0)),
    );

    let list = scelta
        .and_then(|session| {
            service
                .participants
                .list(session.id)
                .map_err(|error| {
                    tracing::warn!(kind = error.kind(), "elenco delle persone non composto");
                })
                .ok()
        })
        .unwrap_or_default();

    // LA STORIA DEGLI ALIAS, PER IDENTIFICATIVO (PERS-02).
    //
    // Si ricava una volta per il monitoraggio scelto, e si accosta alle righe
    // per identificativo — mai per nome, che e' il modo in cui due omonimi
    // finirebbero per scambiarsi la storia.
    //
    // Se non si ricava, le righe restano senza storia: una schermata senza la
    // storia degli alias e' incompleta, una che ne mostrasse una sbagliata
    // sarebbe peggio.
    let storie: std::collections::BTreeMap<String, StoriaDegliAlias> = scelta
        .and_then(|session| {
            service
                .identities
                .for_session(session.id)
                .map_err(|error| {
                    tracing::warn!(kind = error.kind(), "storia degli alias non composta");
                })
                .ok()
        })
        .unwrap_or_default()
        .iter()
        .map(|identita| (identita.identifier.clone(), StoriaDegliAlias::di(identita)))
        .collect();

    // LE ASSOCIAZIONI, PER IDENTIFICATIVO (PERS-03).
    //
    // Si ricavano una volta per il monitoraggio scelto e si accostano alle
    // righe per identificativo, come la storia degli alias e per la stessa
    // ragione: accostarle per nome scambierebbe fra loro i collegamenti di due
    // omonimi, che qui sarebbe l'errore piu' grave possibile.
    //
    // Se non si ricavano, le righe restano senza associazioni: una schermata
    // incompleta e' meglio di una che mostra collegamenti sbagliati.
    let collegamenti: std::collections::BTreeMap<String, Associazioni> = scelta
        .and_then(|session| {
            service
                .associations
                .for_session(session.id)
                .map_err(|error| {
                    tracing::warn!(kind = error.kind(), "associazioni non composte");
                })
                .ok()
        })
        .unwrap_or_default()
        .into_iter()
        .fold(
            std::collections::BTreeMap::<String, Vec<_>>::new(),
            |mut raccolte, associazione| {
                raccolte
                    .entry(associazione.identifier().to_owned())
                    .or_default()
                    .push(associazione);
                raccolte
            },
        )
        .into_iter()
        .map(|(identificativo, righe)| (identificativo, Associazioni::di(&righe)))
        .collect();

    // LA CRONOLOGIA, PER IDENTIFICATIVO (PERS-04).
    //
    // Come la storia degli alias e le associazioni, e per la stessa ragione:
    // accostarla per nome darebbe a due omonimi la cronologia l'uno dell'altro.
    //
    // Se non si ricava, le righe restano senza cronologia: una schermata
    // incompleta e' meglio di una che mostra una cronologia sbagliata.
    let cronologie: std::collections::BTreeMap<String, Cronologia> = scelta
        .and_then(|session| {
            service
                .timelines
                .for_session(session.id)
                .map_err(|error| {
                    tracing::warn!(kind = error.kind(), "cronologie non composte");
                })
                .ok()
        })
        .unwrap_or_default()
        .iter()
        .map(|cronologia| {
            (
                cronologia.identifier().to_owned(),
                Cronologia::di(cronologia),
            )
        })
        .collect();

    let rows: Vec<ParticipantEntry> = list
        .participants
        .iter()
        .map(|person| {
            let storia = storie
                .get(&person.identifier)
                .map_or_else(StoriaDegliAlias::nessuna, StoriaDegliAlias::clone);
            let associazioni = collegamenti
                .get(&person.identifier)
                .map_or_else(Associazioni::nessuna, Associazioni::clone);
            let cronologia = cronologie
                .get(&person.identifier)
                .map_or_else(Cronologia::nessuna, Cronologia::clone);
            row(person, &storia, &associazioni, &cronologia)
        })
        .collect();
    window.set_participants(ModelRc::from(Rc::new(VecModel::from(rows))));
    if message.is_none() {
        window.set_participants_message(crate::lingua::schermo(list.operator_message()));
    }
}

/// Monitoraggi condotti, dal più recente al più vecchio.
///
/// Un archivio non leggibile produce un elenco vuoto e una riga nel registro:
/// la schermata mostrerà zero persone, che è la verità disponibile, invece di
/// un elenco composto su una lettura fallita.
fn readable_sessions(service: &SharedParticipants) -> Vec<lisi_core::model::Session> {
    let mut sessions = service
        .participants
        .database()
        .sessions()
        .map_err(|error| {
            tracing::warn!(errore = %error, "sessioni non leggibili");
        })
        .unwrap_or_default();
    sessions.reverse();
    sessions
}

/// Registra la ragione scritta dall'operatore.
fn record(window: &AppWindow, service: &SharedParticipants) -> String {
    let basis = window.get_participants_basis().to_string();
    let outcome =
        actor().and_then(|actor| service.participants.record_basis(&basis, &actor, now()));

    match outcome {
        Ok(()) => {
            // Il campo si svuota: la ragione vive nell'audit, e lasciarla
            // scritta nella schermata suggerirebbe che si possa riscrivere.
            window.set_participants_basis(SharedString::default());
            String::from(
                "Ragione scritta nel registro delle operazioni. L'elenco delle persone è ora disponibile.",
            )
        }
        Err(error) => describe(&error),
    }
}

/// Traduce un errore del servizio in un messaggio per l'operatore.
fn describe(error: &ServiceError) -> String {
    tracing::warn!(kind = error.kind(), "elenco delle persone non disponibile");
    error.operator_message()
}

/// Collega i comandi della schermata.
pub fn wire(window: &AppWindow, service: &SharedParticipants) {
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_participants_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service, None);
            }
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_participants_session_chosen(move |_| {
            if crate::lock::refuse_while_locked("participants_session_chosen") {
                return;
            }
            // L'indice l'ha già scritto il selettore: qui si ricompone
            // l'elenco su quella scelta. Nessun messaggio, perché la scelta è
            // il comando e il suo esito è l'elenco stesso.
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service, None);
            }
        });
    }

    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_record_participants_basis(move || {
            if crate::lock::refuse_while_locked("record_participants_basis") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let message = record(&window, &service);
            refresh(&window, &service, Some(&message));
        });
    }
}

#[cfg(test)]
mod tests {
    /// Interfaccia, letta a tempo di compilazione.
    const UI: &str = include_str!("../ui/app-window.slint");

    #[test]
    fn the_page_index_matches_the_interface() {
        // L'indice è condiviso con il file `.slint`: se cambia in un posto
        // solo, la voce di menu aprirebbe una pagina diversa da quella che
        // popola, e la schermata risulterebbe vuota senza alcun errore.
        assert!(UI.contains("root.open-page(14);"));
        assert!(UI.contains("if root.current-page == 14:"));
    }

    #[test]
    fn the_list_and_the_reason_are_never_shown_together() {
        // Un elenco mostrato accanto alla richiesta di motivarlo suggerirebbe
        // che la richiesta sia facoltativa, ed e' il modo piu' efficace di
        // svuotarla senza toglierla.
        assert!(UI.contains("if !root.participants-basis-recorded:"));
        // Dal 2026-10-07 l'elenco sta dentro lo scorrimento unico della schermata
        // (FINAL-REVIEW-01, FR-031): la condizione resta la stessa.
        assert!(UI.contains("if root.participants-basis-recorded: Rectangle"));
    }

    /// **L'avvertenza sulle associazioni compare in ambra e una volta sola.**
    ///
    /// # Perché conta (PERS-03)
    ///
    /// Perché un elenco di collegamenti sotto il nome di una persona è
    /// esattamente il materiale con cui si scrive, in una relazione, una frase
    /// che nessun fatto sostiene. La riga che dice **che cosa quei collegamenti
    /// non significano** deve distinguersi: in coda all'elenco, dello stesso
    /// colore, sarebbe una riga come le altre e nessuno la leggerebbe.
    #[test]
    fn l_avvertenza_sulle_associazioni_e_in_ambra_e_una_volta_sola() {
        assert!(
            UI.contains("text: person.associations-caveat;"),
            "l'avvertenza deve comparire nella schermata"
        );
        assert_eq!(
            UI.matches("text: person.associations-caveat;").count(),
            1,
            "una volta sola: ripeterla la renderebbe rumore"
        );

        // IN AMBRA, come l'avvertenza degli alias: e' il colore con cui questo
        // prodotto dice «attenzione a come leggi questo».
        let Some(posizione) = UI.find("text: person.associations-caveat;") else {
            panic!("l'avvertenza deve esserci");
        };
        let dopo = &UI[posizione..];
        let Some(fine) = dopo.find('}') else {
            panic!("il blocco deve chiudersi");
        };
        assert!(
            dopo[..fine].contains("Palette.amber"),
            "l'avvertenza deve distinguersi dal resto"
        );
    }

    /// **La cronologia non compare mai senza le sue finestre (PERS-04).**
    ///
    /// # Perché è la guardia di questa milestone
    ///
    /// Perché una cronologia senza le finestre in cui si stava guardando **mente
    /// per omissione**: un periodo senza righe si legge come «non ha fatto
    /// niente», e nessuno se ne accorge guardandola.
    ///
    /// Le due sezioni sono rette dalla **stessa** condizione, e questa prova lo
    /// verifica: se un giorno qualcuno ne condizionasse una soltanto, la
    /// cronologia potrebbe comparire da sola.
    #[test]
    fn la_cronologia_non_compare_mai_senza_le_sue_finestre() {
        assert!(
            UI.contains("for finestra in person.timeline-windows: Text {"),
            "le finestre devono comparire nella schermata"
        );
        assert!(
            UI.contains("for momento in person.timeline: Text {"),
            "e le righe della cronologia anche"
        );

        // TRE CONDIZIONI, LA STESSA: intestazione della cronologia,
        // intestazione delle finestre, avvertenza. Se una si staccasse dalle
        // altre, una delle tre parti potrebbe comparire da sola.
        assert_eq!(
            UI.matches("if person.timeline-caveat != \"\"").count(),
            3,
            "le tre parti della cronologia sono rette dalla stessa condizione"
        );
    }

    /// **L'avvertenza della cronologia è in ambra e una volta sola.**
    #[test]
    fn l_avvertenza_della_cronologia_e_in_ambra_e_una_volta_sola() {
        assert_eq!(
            UI.matches("text: person.timeline-caveat;").count(),
            1,
            "una volta sola: ripeterla la renderebbe rumore"
        );

        let Some(posizione) = UI.find("text: person.timeline-caveat;") else {
            panic!("l'avvertenza deve esserci");
        };
        let dopo = &UI[posizione..];
        let Some(fine) = dopo.find('}') else {
            panic!("il blocco deve chiudersi");
        };
        assert!(
            dopo[..fine].contains("Palette.amber"),
            "l'avvertenza deve distinguersi dal resto"
        );
    }

    /// **Le associazioni non compaiono quando non c'è nulla da dire.**
    ///
    /// # Perché conta
    ///
    /// Perché ogni persona che ha scritto ha almeno un contenuto e una fonte:
    /// mostrarli come «associazioni» sotto ognuna sarebbe ripetere l'elenco dei
    /// partecipanti con altre parole. È la lezione di PERS-02 sul rumore, e la
    /// sezione è retta dalla stessa condizione dell'avvertenza.
    #[test]
    fn le_associazioni_non_compaiono_quando_non_c_e_nulla_da_dire() {
        assert!(
            UI.contains("if person.associations-caveat != \"\": Text {"),
            "la sezione deve essere condizionata"
        );
        assert_eq!(
            UI.matches("if person.associations-caveat != \"\"").count(),
            2,
            "due condizioni sole: l'intestazione e l'avvertenza"
        );
    }
}

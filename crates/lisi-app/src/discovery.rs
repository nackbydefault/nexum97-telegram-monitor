//! Collegamento fra la schermata della scoperta pubblica e l'archivio delle
//! scoperte (PD-UI-01).
//!
//! # Che cosa questa schermata non fa, e non deve fare
//!
//! **Cercare.**
//!
//! Non c'è un comando che lo chieda, non c'è una funzione che lo faccia, e il
//! servizio che sta sotto non ne ha il modo. Non è prudenza: una ricerca
//! pubblica richiede una politica validata, che si ottiene solo da limiti
//! osservati, che nessuno ha ancora misurato (ADR-0074, HVQ-03).
//!
//! Un pulsante «Cerca» che si preme e non fa nulla sarebbe la promessa che
//! UPDATE-06 ha già rifiutato: *un comando che non fa ciò che dice è una
//! promessa* (ADR-0071). Quindi il pulsante **non esiste**, e la ragione sta
//! scritta sulla pagina.
//!
//! # Perché ciò che non è stato chiesto sta accanto e non dietro
//!
//! PD-STORAGE-01 conserva le omissioni perché la dichiarazione del pianificatore
//! non muoia con la schermata. Se poi la schermata le nascondesse dietro un
//! pannello da aprire, il silenzio tornerebbe al suo posto — e **conservare e
//! non mostrare è come non conservare** (ADR-0079).
//!
//! # Perché il nome pubblico non è un collegamento
//!
//! Arriva da fuori. Qui si mostra e non si interpreta: non si apre, non si
//! aggiunge, non si ignora. Quelle sono azioni, e le azioni hanno un operatore,
//! un motivo, un istante e una riga d'audit: sono **SRC-DISC-01**.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::acquisition_authority::StationAuthorityService;
use lisi_services::candidate_decision::{
    COSA_SI_DICHIARA_AGGIUNGENDO, COSA_SUCCEDE_IGNORANDO, CandidateDecisionService,
};
use lisi_services::discovery::{
    DiscoveryReviewService, NESSUNA_SCOPERTA_ESEGUITA, PERCHE_NON_SI_CERCA, candidate_sentence,
};
use lisi_services::discovery_gate::PERCHE_NON_CERCA_CHI_SEGUE;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, DiscoveryCandidateEntry, DiscoveryRunEntry, DiscoveryTermEntry};

/// Perché, quando si cercherà, non cercherà questa postazione.
///
/// Restituisce `None` su una postazione che acquisisce: lì la seconda ragione
/// non esiste, e una frase che dichiara una condizione che non c'è è rumore.
///
/// La frase viene dal servizio e non da qui: la porta è una sola, e la ragione
/// per cui non si apre deve restare una sola (ADR-0103).
fn la_ricerca_e_dell_hub() -> Option<&'static str> {
    let radice = crate::account::data_root()?;
    if StationAuthorityService::in_directory(&radice)
        .role()
        .may_acquire()
    {
        return None;
    }
    Some(PERCHE_NON_CERCA_CHI_SEGUE)
}

/// Il servizio di rilettura, condiviso fra i gestori della schermata.
pub type SharedDiscovery = Rc<RefCell<DiscoveryReviewService>>;

/// Il servizio che **scrive** le decisioni, condiviso fra i gestori.
///
/// È un archivio diverso da quello che rilegge: rileggere non scrive, e la
/// guardia che lo verifica resta intatta (ADR-0079, ADR-0080).
pub type SharedDecisions = Rc<RefCell<CandidateDecisionService>>;

/// Che cosa la schermata sta guardando adesso.
///
/// Serve a sapere **su quale riga** una decisione viene presa: la posizione che
/// l'interfaccia restituisce indica una riga di ciò che questo programma ha
/// appena composto, non un identificativo che arriva da fuori.
type CurrentCandidates = Rc<RefCell<Vec<i64>>>;

/// Crea il servizio di rilettura attorno all'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> SharedDiscovery {
    Rc::new(RefCell::new(DiscoveryReviewService::new(database)))
}

/// Crea il servizio che registra le decisioni.
#[must_use]
pub fn create_decision_service(database: lisi_services::Database) -> SharedDecisions {
    Rc::new(RefCell::new(CandidateDecisionService::new(database)))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Collega i comandi della schermata al servizio.
pub fn wire(window: &AppWindow, discovery: &SharedDiscovery, decisions: &SharedDecisions) {
    let candidati: CurrentCandidates = Rc::new(RefCell::new(Vec::new()));

    // Le due frasi che dichiarano lo stato vengono dal servizio e non dalla
    // schermata: due composizioni della stessa frase divergono alla prima
    // modifica, e la ragione per cui non si cerca deve restare una sola.
    window.set_discovery_closed_door(crate::lingua::schermo(PERCHE_NON_SI_CERCA));
    window.set_discovery_never_run(crate::lingua::schermo(NESSUNA_SCOPERTA_ESEGUITA));
    // CHE COSA SI DICHIARA AGGIUNGENDO si legge PRIMA di firmare, non dopo.
    window.set_discovery_add_declaration(crate::lingua::schermo(COSA_SI_DICHIARA_AGGIUNGENDO));
    window.set_discovery_ignore_note(crate::lingua::schermo(COSA_SUCCEDE_IGNORANDO));
    // E, su una postazione che segue un Hub, la seconda ragione.
    window.set_discovery_follows_hub(SharedString::from(
        la_ricerca_e_dell_hub().unwrap_or_default(),
    ));

    {
        let handle = window.as_weak();
        let discovery = Rc::clone(discovery);
        window.on_discovery_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &discovery);
            }
        });
    }

    {
        let handle = window.as_weak();
        let discovery = Rc::clone(discovery);
        let candidati = Rc::clone(&candidati);
        window.on_discovery_run_chosen(move |position| {
            if crate::lock::refuse_while_locked("discovery_run_chosen") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                show_detail(&window, &discovery, position, &candidati);
            }
        });
    }

    {
        let handle = window.as_weak();
        window.on_discovery_candidate_chosen(move |_| {
            if crate::lock::refuse_while_locked("discovery_candidate_chosen") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                // SCEGLIERE NON DECIDE NIENTE. Si azzera il motivo, perche' un
                // motivo scritto per un candidato non vale per un altro: e'
                // esattamente il travaso che renderebbe la decisione un gesto.
                window.set_discovery_decision_reason(SharedString::new());
                window.set_discovery_decision_message(SharedString::new());
            }
        });
    }

    decide(
        window,
        decisions,
        &candidati,
        Decisione::Apri,
        |window, decisions, result_id, reason, actor| {
            decisions
                .borrow_mut()
                .open(result_id, reason, actor, now())
                .map(|esito| {
                    // IL SERVIZIO NON APRE: restituisce l'indirizzo, e
                    // l'apertura passa da dove passano tutte le aperture di
                    // questo prodotto (ADR-0018).
                    if let Some(indirizzo) = esito.open.as_deref() {
                        window.invoke_open_url(SharedString::from(indirizzo));
                    }
                    String::from(
                        "Aperta per guardarla. Aprire non aggiunge: la chat non è \
                         diventata una fonte.",
                    )
                })
        },
    );

    decide(
        window,
        decisions,
        &candidati,
        Decisione::Aggiungi,
        |_, decisions, result_id, reason, actor| {
            decisions
                .borrow_mut()
                .add_as_source(result_id, reason, actor, now())
                .map(|_| {
                    String::from(
                        "Aggiunta come fonte, con la tua dichiarazione e il motivo. \
                         Nasce inattiva: per sorvegliarla va scelta in un \
                         monitoraggio.",
                    )
                })
        },
    );

    decide(
        window,
        decisions,
        &candidati,
        Decisione::Ignora,
        |_, decisions, result_id, reason, actor| {
            decisions
                .borrow_mut()
                .ignore(result_id, reason, actor, now())
                .map(|_| {
                    String::from(
                        "Registrato che è stata esaminata e scartata, con il motivo. \
                         Non è stata cancellata.",
                    )
                })
        },
    );
}

/// Quale delle tre decisioni si sta collegando.
#[derive(Debug, Clone, Copy)]
enum Decisione {
    Apri,
    Aggiungi,
    Ignora,
}

/// Collega uno dei tre comandi di decisione.
///
/// # Perché uno per volta
///
/// Non esiste un gestore che agisca su più di un candidato: una decisione presa
/// su dieci cose insieme non è dieci decisioni, è **un gesto**, ed è ciò che
/// «mai adesione automatica» vieta (ADR-0080).
fn decide<F>(
    window: &AppWindow,
    decisions: &SharedDecisions,
    candidati: &CurrentCandidates,
    quale: Decisione,
    azione: F,
) where
    F: Fn(
            &AppWindow,
            &SharedDecisions,
            i64,
            &str,
            &lisi_core::text::Actor,
        ) -> lisi_services::ServiceResult<String>
        + 'static,
{
    let handle = window.as_weak();
    let decisions = Rc::clone(decisions);
    let candidati = Rc::clone(candidati);

    let gestore = move || {
        if crate::lock::refuse_while_locked("discovery_decision") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let Some(result_id) = candidato_scelto(&window, &candidati) else {
            return;
        };
        let motivo = window.get_discovery_decision_reason().to_string();
        let esito = crate::operator::audit_actor()
            .and_then(|actor| azione(&window, &decisions, result_id, motivo.trim(), &actor));

        match esito {
            Ok(messaggio) => {
                window.set_discovery_decision_message(crate::lingua::schermo(messaggio));
                window.set_discovery_decision_reason(SharedString::new());
            }
            Err(errore) => {
                // IL MESSAGGIO E' QUELLO DELL'ERRORE, non uno inventato qui: due
                // composizioni della stessa frase divergono alla prima modifica.
                window.set_discovery_decision_message(crate::lingua::schermo(
                    errore.operator_message(),
                ));
            }
        }
    };

    match quale {
        Decisione::Apri => window.on_discovery_open_candidate(gestore),
        Decisione::Aggiungi => window.on_discovery_add_candidate(gestore),
        Decisione::Ignora => window.on_discovery_ignore_candidate(gestore),
    }
}

/// Su quale riga si sta decidendo.
fn candidato_scelto(window: &AppWindow, candidati: &CurrentCandidates) -> Option<i64> {
    let posizione = window.get_discovery_candidate_selected();
    let indice = usize::try_from(posizione).ok()?;
    candidati.borrow().get(indice).copied()
}

/// Ricarica l'elenco delle scoperte registrate.
pub fn refresh(window: &AppWindow, discovery: &SharedDiscovery) {
    let servizio = discovery.borrow();
    let Ok(scoperte) = servizio.runs() else {
        // L'archivio non risponde: l'elenco resta vuoto, e il vuoto dice gia'
        // che nessuna scoperta e' visibile. Fingerne una sarebbe peggio.
        tracing::warn!("elenco delle scoperte pubbliche non disponibile");
        window.set_discovery_runs(ModelRc::new(VecModel::from(Vec::new())));
        window.set_discovery_selected(-1);
        return;
    };

    let righe: Vec<DiscoveryRunEntry> = scoperte
        .iter()
        .map(|scoperta| DiscoveryRunEntry {
            when: SharedString::from(scoperta.started_at.to_readable_local()),
            scope: crate::lingua::schermo(scoperta.scope.label()),
            summary: crate::lingua::schermo(format!(
                "{} domande poste, {} termini non chiesti, {} risultati, {} candidati",
                scoperta.asked, scoperta.omitted, scoperta.results, scoperta.candidates
            )),
        })
        .collect();

    window.set_discovery_runs(ModelRc::new(VecModel::from(righe)));
    window.set_discovery_selected(-1);
    svuota_il_dettaglio(window);
}

/// Mostra per intero la scoperta scelta.
fn show_detail(
    window: &AppWindow,
    discovery: &SharedDiscovery,
    position: i32,
    candidati: &CurrentCandidates,
) {
    let servizio = discovery.borrow();
    let Ok(scoperte) = servizio.runs() else {
        svuota_il_dettaglio(window);
        candidati.borrow_mut().clear();
        return;
    };
    let Ok(indice) = usize::try_from(position) else {
        svuota_il_dettaglio(window);
        candidati.borrow_mut().clear();
        return;
    };
    let Some(scoperta) = scoperte.get(indice) else {
        svuota_il_dettaglio(window);
        candidati.borrow_mut().clear();
        return;
    };
    let Ok(Some(dettaglio)) = servizio.run_detail(scoperta.id) else {
        svuota_il_dettaglio(window);
        candidati.borrow_mut().clear();
        return;
    };

    window.set_discovery_summary(crate::lingua::schermo(dettaglio.sentence()));

    // LA MISURA CON LA SUA PROVENIENZA. Un numero senza provenienza non si
    // distingue da uno inventato, e la data dice se valga ancora qualcosa.
    window.set_discovery_limits(crate::lingua::schermo(format!(
        "Limiti osservati: {} interrogazioni gratuite al giorno, {} ancora disponibili. \
         Misurati il {}, da: {}.",
        dettaglio.limits.free_per_day,
        dettaglio.limits.remaining_free,
        dettaglio.limits.observed_at.to_readable_local(),
        dettaglio.limits.origin
    )));

    let domande: Vec<SharedString> = dettaglio
        .asked
        .iter()
        .map(|domanda| SharedString::from(domanda.as_str()))
        .collect();
    window.set_discovery_asked(ModelRc::new(VecModel::from(domande)));

    let omessi: Vec<DiscoveryTermEntry> = dettaglio
        .omitted
        .iter()
        .map(|omesso| DiscoveryTermEntry {
            term: SharedString::from(omesso.term.as_str()),
            reason: SharedString::from(omesso.reason.as_str()),
            consequence: SharedString::from(omesso.consequence.as_str()),
        })
        .collect();
    window.set_discovery_omitted(ModelRc::new(VecModel::from(omessi)));

    // LE RIGHE D'ARCHIVIO SEGUONO I CANDIDATI, nello stesso ordine in cui la
    // schermata li mostra: una decisione si prende su una riga, e la posizione
    // che l'interfaccia restituisce indica una riga di questo elenco.
    candidati.borrow_mut().clear();
    candidati
        .borrow_mut()
        .extend(dettaglio.candidates.iter().map(|(riga, _)| *riga));

    let righe: Vec<DiscoveryCandidateEntry> = dettaglio
        .candidates
        .iter()
        .map(|(_, candidato)| DiscoveryCandidateEntry {
            name: SharedString::from(candidato.candidate.result.public_name.as_str()),
            scope: crate::lingua::schermo(candidato.candidate.result.scope.label()),
            why: SharedString::from(candidate_sentence(candidato)),
            // UNO PER RIGA: e' l'unico modo per cui si possano contestare uno
            // per uno, che e' la proprieta' per cui contare non e' valutare.
            reasons: SharedString::from(
                candidato
                    .candidate
                    .reasons()
                    .iter()
                    .map(|motivo| format!("— {}", motivo.as_str()))
                    .collect::<Vec<String>>()
                    .join("\n"),
            ),
            // L'INDIRIZZO SI MOSTRA, NON SI APRE DA SOLO. Vuoto quando non c'e':
            // senza, non c'e' niente da aprire e niente da sorvegliare.
            address: SharedString::from(
                candidato
                    .candidate
                    .result
                    .public_address
                    .as_ref()
                    .map_or_else(String::new, |indirizzo| indirizzo.as_str().to_owned()),
            ),
        })
        .collect();
    window.set_discovery_candidates(ModelRc::new(VecModel::from(righe)));
    window.set_discovery_candidate_selected(-1);
    window.set_discovery_decision_reason(SharedString::new());
    window.set_discovery_decision_message(SharedString::new());

    window.set_discovery_results_note(SharedString::from(nota_sui_risultati(
        dettaglio.results_without_reasons,
    )));
}

/// Che cosa dire dei risultati che non sono candidati.
///
/// Non sono un residuo: sono risultati **senza un motivo scritto**, e tacerli
/// farebbe credere che la ricerca ne abbia restituiti meno di quanti ne ha
/// restituiti davvero.
fn nota_sui_risultati(senza_motivi: usize) -> String {
    if senza_motivi == 0 {
        return String::from("Ogni risultato di questa ricerca porta almeno un motivo.");
    }
    let parola = if senza_motivi == 1 {
        "risultato è tornato"
    } else {
        "risultati sono tornati"
    };
    format!(
        "{senza_motivi} {parola} senza alcun motivo: restano risultati, non diventano \
         candidati, e non spariscono dal conto."
    )
}

/// Riporta il dettaglio a «niente scelto».
fn svuota_il_dettaglio(window: &AppWindow) {
    window.set_discovery_candidate_selected(-1);
    window.set_discovery_decision_reason(SharedString::new());
    window.set_discovery_decision_message(SharedString::new());

    window.set_discovery_summary(SharedString::new());
    window.set_discovery_limits(SharedString::new());
    window.set_discovery_results_note(SharedString::new());
    window.set_discovery_asked(ModelRc::new(VecModel::from(Vec::<SharedString>::new())));
    window.set_discovery_omitted(ModelRc::new(VecModel::from(
        Vec::<DiscoveryTermEntry>::new(),
    )));
    window.set_discovery_candidates(ModelRc::new(VecModel::from(
        Vec::<DiscoveryCandidateEntry>::new(),
    )));
}

#[cfg(test)]
mod tests {
    use super::nota_sui_risultati;

    /// Interfaccia principale, per le guardie strutturali di questo modulo.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il corpo della pagina della scoperta.
    fn pagina_della_scoperta() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(26)
    }

    /// **I comandi di questa pagina sono questi, e per averne un altro bisogna
    /// dirlo qui.**
    ///
    /// # Perche' questa guardia ha sostituito quella di PD-UI-01
    ///
    /// PD-UI-01 verificava che la pagina non avesse ALCUN comando, ed era vero:
    /// non si poteva fare niente. SRC-DISC-01 aggiunge le tre decisioni del
    /// piano, e quella guardia sarebbe diventata semplicemente falsa.
    ///
    /// Cancellarla avrebbe tolto la difesa insieme alla sua ragione. Al suo
    /// posto c'e' un'affermazione che regge ancora: l'elenco dei comandi
    /// ammessi. Un comando nuovo - per esempio uno che cerchi - fa fallire
    /// questa prova finche' qualcuno non scrive qui che cosa ci fa.
    ///
    /// E cio' che PD-UI-01 difendeva resta difeso: fra i comandi ammessi non ce
    /// n'e' nessuno che esegua una ricerca, e la porta chiusa e' ancora
    /// dichiarata sulla pagina.
    #[test]
    fn i_comandi_della_pagina_della_scoperta_sono_solo_questi() {
        const AMMESSI: [&str; 6] = [
            // Apre la pagina e ricarica l'elenco.
            "discovery-shown",
            // Sceglie una ricerca registrata da rileggere.
            "discovery-run-chosen",
            // Sceglie un candidato. NON decide niente.
            "discovery-candidate-chosen",
            // Le tre decisioni del piano, una per candidato.
            "discovery-open-candidate",
            "discovery-add-candidate",
            "discovery-ignore-candidate",
        ];

        let pagina = pagina_della_scoperta();
        let codice: String = pagina
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        let mut trovati: Vec<String> = Vec::new();
        let mut resto = codice.as_str();
        while let Some(posizione) = resto.find("root.discovery-") {
            let coda = &resto[posizione + "root.".len()..];
            let nome: String = coda
                .chars()
                .take_while(|carattere| carattere.is_ascii_alphanumeric() || *carattere == '-')
                .collect();
            if coda[nome.len()..].starts_with('(') {
                trovati.push(nome);
            }
            resto = &resto[posizione + "root.discovery-".len()..];
        }

        assert!(
            !trovati.is_empty(),
            "nessun comando trovato: se la pagina e' stata riscritta, questa \
             guardia va aggiornata insieme a lei"
        );
        for comando in &trovati {
            assert!(
                AMMESSI.contains(&comando.as_str()),
                "«{comando}» non e' fra i comandi ammessi su questa pagina: se \
                 deve esistere, va scritto qui che cosa fa (ADR-0079, ADR-0080)"
            );
        }

        // CIO' CHE LA GUARDIA DI PD-UI-01 DIFENDEVA, E CHE RESTA VERO.
        assert!(
            pagina.contains("root.discovery-closed-door"),
            "la porta chiusa resta dichiarata sulla pagina: da qui non si cerca"
        );
        assert!(
            pagina.contains("StateKind.planned"),
            "e si dichiara come capacita' che questa versione non ha, non come \
             «ancora nessun dato»"
        );
    }

    /// **La pagina dice perche' non cerchera' questa postazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Su una postazione che segue un Hub la pagina resta senza comando di
    /// ricerca, esattamente come su un Hub. Le due assenze si somigliano e
    /// hanno ragioni diverse: sull'Hub manca la misura, qui manca la misura
    /// **e** il compito. Un'assenza non spiegata si legge come una mancanza, e
    /// chi la nota chiede di colmarla (ADR-0079, ADR-0103).
    ///
    /// La prova verifica che il blocco esista e che dipenda dalla proprieta'
    /// che resta vuota su un Hub: una frase sempre visibile direbbe il falso
    /// meta' delle volte.
    #[test]
    fn la_pagina_dice_perche_non_cerchera_questa_postazione() {
        let pagina = pagina_della_scoperta();

        assert!(
            pagina.contains("root.discovery-follows-hub != \"\": StateBlock"),
            "la seconda ragione si mostra sempre, anche su un Hub, dove non e' \
             vera"
        );
        assert!(
            pagina.contains("message: root.discovery-follows-hub;"),
            "il blocco non porta la frase che lo giustifica"
        );

        let frase = lisi_services::discovery_gate::PERCHE_NON_CERCA_CHI_SEGUE;
        for atteso in ["dell'Hub", "una volta sola", "account"] {
            assert!(
                frase.contains(atteso),
                "la frase non dice «{atteso}»: senza quello non spiega perche' \
                 cercare da qui costerebbe all'ufficio intero"
            );
        }
        assert!(
            !frase.contains("vietat") && !frase.contains("permess"),
            "un'impossibilita' non si traveste da divieto: «{frase}»"
        );
    }

    /// **Nessuna delle tre decisioni si preme senza un motivo scritto.**
    ///
    /// Un motivo per candidato e' la difesa piu' semplice contro il gesto: non
    /// si scrive un motivo dieci volte per distrazione, ed e' cosi' che «mai
    /// adesione automatica» resta vero anche quando a premere e' una persona.
    #[test]
    fn nessuna_decisione_si_preme_senza_un_motivo() {
        let pagina = pagina_della_scoperta();

        for comando in [
            "root.discovery-open-candidate()",
            "root.discovery-add-candidate()",
            "root.discovery-ignore-candidate()",
        ] {
            let Some(posizione) = pagina.find(comando) else {
                panic!("«{comando}» non si trova sulla pagina");
            };
            // Il blocco del pulsante che lo invoca: la condizione precede
            // sempre il gestore, perche' e' una proprieta' del componente.
            let inizio = pagina[..posizione].rfind("HudButton {").unwrap_or(0);
            let blocco = &pagina[inizio..posizione];
            assert!(
                blocco.contains("enabled: root.discovery-decision-reason != \"\""),
                "«{comando}» si puo' premere senza un motivo scritto (ADR-0080)"
            );
        }
    }

    /// **Cio' che non e' stato chiesto sta sulla pagina, non dietro un
    /// pannello.**
    ///
    /// Conservarlo e non mostrarlo riporterebbe il silenzio al suo posto:
    /// l'archivio le ha, nessuno le vede.
    #[test]
    fn i_termini_non_chiesti_stanno_sulla_pagina() {
        let pagina = pagina_della_scoperta();

        assert!(
            pagina.contains("root.discovery-omitted"),
            "i termini non chiesti si mostrano"
        );
        assert!(
            pagina.contains("Termini non chiesti"),
            "e hanno un titolo che dice che cosa sono"
        );
        assert!(
            pagina.contains("omesso.consequence"),
            "di ogni termine non chiesto si dice che cosa ne segue"
        );
    }

    /// **Scegliere un candidato non decide niente.**
    ///
    /// # Perche' questa guardia ha ristretto quella di PD-UI-01
    ///
    /// PD-UI-01 verificava che su un candidato non si potesse premere nulla,
    /// perche' le azioni non esistevano ancora. Ora esistono, e la riga si
    /// sceglie: la guardia non e' piu' vera com'era scritta.
    ///
    /// Cio' che resta vero, e che e' la cosa che conta, e' che **scegliere non
    /// e' decidere**: dalla riga non parte nessuna delle tre decisioni, e il
    /// nome pubblico non e' un collegamento. Una decisione presa cliccando su
    /// una riga sarebbe una decisione presa senza un motivo scritto, cioe' un
    /// gesto (ADR-0080).
    #[test]
    fn scegliere_un_candidato_non_decide_niente() {
        let Some(inizio) = UI.find("for candidato[indice] in root.discovery-candidates:") else {
            panic!("l'elenco dei candidati non si trova");
        };
        let Some(lunghezza) = UI[inizio..].find("if root.discovery-candidate-selected >= 0:")
        else {
            panic!("la fine dell'elenco dei candidati non si delimita");
        };
        let elenco = &UI[inizio..inizio + lunghezza];

        for vietato in [
            "discovery-open-candidate",
            "discovery-add-candidate",
            "discovery-ignore-candidate",
            "open-url",
        ] {
            assert!(
                !elenco.contains(vietato),
                "«{vietato}» dentro la riga di un candidato: scegliere non e' \
                 decidere, e il nome pubblico non e' un collegamento (ADR-0080)"
            );
        }

        assert!(
            elenco.contains("root.discovery-candidate-chosen(indice)"),
            "la riga si sceglie, e la scelta dice soltanto quale riga e'"
        );
    }

    /// **I risultati senza motivo si contano, e non spariscono.**
    #[test]
    fn i_risultati_senza_motivo_restano_nel_conto() {
        let nessuno = nota_sui_risultati(0);
        assert!(nessuno.contains("almeno un motivo"));

        let uno = nota_sui_risultati(1);
        assert!(uno.contains("1 risultato è tornato"), "«{uno}»");
        assert!(uno.contains("non spariscono dal conto"), "«{uno}»");

        let molti = nota_sui_risultati(4);
        assert!(molti.contains("4 risultati sono tornati"), "«{molti}»");
    }
}

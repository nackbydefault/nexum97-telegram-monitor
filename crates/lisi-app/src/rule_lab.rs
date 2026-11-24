//! Collegamento fra la schermata «Rule Lab» e il confronto che la alimenta.
//!
//! # Che cosa questo modulo fa, e che cosa non può fare
//!
//! Legge i contenuti di una sessione, risolve due configurazioni — la versione
//! pubblicata e la bozza dello stesso dizionario — e chiama il confronto.
//!
//! **Il confronto non può scrivere**, e non perché questo modulo stia attento:
//! `lisi-services::rule_lab` non conosce l'archivio, e non ha nulla con cui
//! scrivere (LAB-01, DEC-258). Questo modulo gli passa contenuti già letti e ne
//! mostra l'esito.
//!
//! # Che cosa la schermata dice prima di eseguire
//!
//! Quale versione pubblicata, quale bozza, su quanti contenuti. Chi lo scopre
//! dopo lo scopre aspettando, e il confronto costa quanto l'analisi
//! moltiplicata per due configurazioni e per il numero di contenuti.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::SessionId;
use lisi_services::dictionaries::{DictionaryService, LabCandidate};
use lisi_services::review::ReviewService;
use lisi_services::rule_lab::{
    LabComparison, LabContent, LevelShift, TermChange, TermDifferences, compare,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, FeedbackRow, LabRow, LabTermRow};

/// Quanti contenuti al massimo entrano in un confronto.
///
/// # Perché un limite, e perché questo
///
/// Perché il confronto è sincrono e tiene ferma l'interfaccia: su una sessione
/// da centomila contenuti la finestra resterebbe bloccata senza dire nulla.
///
/// **Duemila** è il numero di contenuti che il confronto attraversa restando
/// sotto il secondo sulla macchina di sviluppo. Non è una verità: è una misura
/// presa una volta, e la schermata **dichiara** quando il limite ha tagliato —
/// un confronto su una parte che si spacciasse per un confronto su tutto
/// farebbe approvare una modifica guardando un decimo dei contenuti.
const MAX_CONTENTS: u32 = 2_000;

/// Quante righe del riscontro compaiono al massimo.
///
/// # Perché un limite, e perché non è un ordinamento per gravità
///
/// Perché una sessione può aver riscontrato centinaia di termini distinti, e
/// una pagina di centinaia di righe non si legge.
///
/// Le righe restano nell'ordine dell'aggregazione — dizionario, regola,
/// categoria — e **non** in quello dei conteggi. Ordinarle per numero di
/// smentite comporrebbe una classifica delle regole peggiori, che è un
/// punteggio scritto con l'ordine invece che con una cifra. Il taglio si
/// **dichiara**, come quello del confronto.
const MAX_FEEDBACK_ROWS: usize = 60;

/// Servizio dei dizionari e archivio, per il laboratorio.
pub struct LabServices {
    /// Da cui si risolvono le due configurazioni.
    pub dictionaries: DictionaryService,
    /// Da cui si leggono i contenuti e le sessioni.
    pub database: lisi_services::Database,
    /// Da cui si legge che cosa le persone hanno deciso.
    ///
    /// L'aggregazione vera non lo riceve: `lisi-services::feedback` non
    /// conosce l'archivio, ed è la ragione per cui non può modificare un
    /// dizionario (FEEDBACK-01, DEC-262).
    pub review: ReviewService,
}

/// Servizi del laboratorio, condivisi fra i gestori dei comandi.
pub type SharedLab = Rc<RefCell<LabServices>>;

/// Crea i servizi del laboratorio.
#[must_use]
pub fn create_service(
    dictionaries: lisi_services::Database,
    contents: lisi_services::Database,
    reviews: lisi_services::Database,
) -> Option<SharedLab> {
    Some(Rc::new(RefCell::new(LabServices {
        dictionaries: DictionaryService::new(dictionaries),
        database: contents,
        review: ReviewService::new(reviews),
    })))
}

/// Le bozze aperte, ciascuna con la versione con cui si confronta
/// (OPERATOR-E2E-REMEDIATION-01, F-07).
///
/// Fino a questa correzione l'elenco conteneva solo i dizionari con **entrambe**
/// le versioni, e nessun comando apriva una bozza su un dizionario pubblicato:
/// l'elenco era sempre vuoto. Ora le bozze vengono tutte, con il loro
/// riferimento — la pubblicata, o l'originale di un duplicato — o con la
/// dichiarazione che non ne hanno uno. La regola sta nel servizio
/// (`DictionaryService::lab_candidates`), dove è provata.
fn comparable(services: &LabServices) -> Vec<LabCandidate> {
    services
        .dictionaries
        .lab_candidates()
        .unwrap_or_else(|errore| {
            tracing::warn!(errore = %errore, "bozze del laboratorio non leggibili");
            Vec::new()
        })
}

/// Le righe delle differenze dei termini, come l'interfaccia le mostra.
fn term_rows(differenze: &TermDifferences) -> Vec<LabTermRow> {
    differenze
        .changes
        .iter()
        .map(|cambio| LabTermRow {
            sign: SharedString::from(cambio.sign()),
            sentence: crate::lingua::schermo(cambio.as_sentence()),
            removed: matches!(cambio, TermChange::Removed(_)),
        })
        .collect()
}

/// Le sessioni, dalla più recente.
fn sessions(services: &LabServices) -> Vec<(SessionId, String)> {
    services.database.sessions().map_or_else(
        |_| Vec::new(),
        |sessioni| {
            let mut elenco: Vec<(SessionId, String)> = sessioni
                .into_iter()
                .map(|sessione| (sessione.id, sessione.label.as_str().to_owned()))
                .collect();
            elenco.reverse();
            elenco
        },
    )
}

/// Riporta nell'interfaccia le scelte disponibili e l'anteprima.
pub fn refresh(window: &AppWindow, lab: &SharedLab) {
    let services = lab.borrow();
    let dizionari = comparable(&services);
    let sessioni = sessions(&services);

    // «PROVA NEL LABORATORIO» DA DIZIONARI: si sceglie la bozza chiesta, una
    // volta, e la richiesta si consuma.
    let richiesta = window.get_lab_requested_dictionary();
    if richiesta > 0 {
        if let Some(posizione) = dizionari
            .iter()
            .position(|c| c.dictionary.id.get() == i64::from(richiesta))
        {
            window.set_lab_dictionary_index(i32::try_from(posizione).unwrap_or(0));
            window.set_lab_summary(SharedString::default());
            window.set_lab_findings(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        }
        window.set_lab_requested_dictionary(0);
    }

    window.set_lab_has_candidates(!dizionari.is_empty());
    window.set_lab_dictionaries(ModelRc::from(Rc::new(VecModel::from(
        dizionari
            .iter()
            .map(|candidato| crate::lingua::schermo(candidato.label()))
            .collect::<Vec<_>>(),
    ))));
    window.set_lab_sessions(ModelRc::from(Rc::new(VecModel::from(
        sessioni
            .iter()
            .map(|(_, etichetta)| SharedString::from(etichetta.as_str()))
            .collect::<Vec<_>>(),
    ))));

    let dizionario = scelta(&dizionari, window.get_lab_dictionary_index());
    let sessione = scelta(&sessioni, window.get_lab_session_index());

    // CHE COSA LA BOZZA CAMBIA NEL DIZIONARIO: si legge subito, senza contenuti.
    window.set_lab_draft_dictionary(
        dizionario.map_or(0, |c| i32::try_from(c.dictionary.id.get()).unwrap_or(0)),
    );
    let (frase_termini, righe_termini) = match dizionario {
        None => (String::new(), Vec::new()),
        Some(candidato) => match services.dictionaries.lab_term_differences(candidato) {
            Ok(Some(differenze)) => (differenze.as_sentence(), term_rows(&differenze)),
            Ok(None) => (
                String::from(
                    "Questa bozza non ha una versione pubblicata con cui confrontarsi, né un \
                     dizionario da cui è stata duplicata: è la prima versione. Pubblicata, \
                     diventa il riferimento delle versioni successive.",
                ),
                Vec::new(),
            ),
            Err(errore) => {
                tracing::warn!(errore = %errore, "termini del laboratorio non leggibili");
                (
                    String::from("I termini delle due versioni non si sono potuti leggere."),
                    Vec::new(),
                )
            }
        },
    };
    window.set_lab_term_summary(SharedString::from(frase_termini));
    window.set_lab_term_rows(ModelRc::from(Rc::new(VecModel::from(righe_termini))));

    let (anteprima, eseguibile) = match (dizionario, sessione) {
        (None, _) if dizionari.is_empty() => (
            String::from(
                "Il Laboratorio confronta la bozza di un dizionario con la sua versione \
                 pubblicata, e nessun dizionario ha una bozza aperta. Per aprirne una: in \
                 Dizionari, su un dizionario pubblicato che non sia di sistema, «Nuova \
                 versione»; oppure «Duplica» un dizionario di sistema. La bozza compare qui.",
            ),
            false,
        ),
        (Some(candidato), _) if candidato.baseline.is_none() => (
            String::from(
                "Senza una versione di riferimento non c'è un effetto da misurare sui \
                 contenuti: il confronto parte dalla seconda versione.",
            ),
            false,
        ),
        (_, None) if sessioni.is_empty() => (
            String::from(
                "Per vedere l'effetto sui contenuti serve un monitoraggio con contenuti già \
                 archiviati, e su questa postazione non ce n'è ancora uno. Le differenze dei \
                 termini, qui sopra, non ne hanno bisogno.",
            ),
            false,
        ),
        (Some(candidato), Some((session_id, etichetta))) => {
            let quanti = services
                .database
                .session_bodies(*session_id, MAX_CONTENTS)
                .map_or(0, |righe| righe.len());
            let riferimento = candidato
                .baseline
                .as_ref()
                .map_or(0, |b| b.version().number);
            if quanti == 0 {
                (
                    format!(
                        "Il monitoraggio «{etichetta}» non ha contenuti archiviati: un confronto \
                         su zero contenuti non direbbe nulla del candidato."
                    ),
                    false,
                )
            } else {
                (
                    format!(
                        "Si confronteranno la versione di riferimento v{riferimento} e la bozza \
                         v{} di «{}» su {quanti} contenuti del monitoraggio «{etichetta}». Il \
                         confronto non scrive nulla; su molti contenuti può richiedere qualche \
                         istante.",
                        candidato.draft.number,
                        candidato.dictionary.name.as_str()
                    ),
                    true,
                )
            }
        }
        _ => (String::new(), false),
    };

    window.set_lab_preview(SharedString::from(anteprima));
    window.set_lab_can_run(eseguibile);
}

/// L'elemento scelto, quando l'indice è dentro l'elenco.
fn scelta<T>(elenco: &[T], index: i32) -> Option<&T> {
    usize::try_from(index).ok().and_then(|i| elenco.get(i))
}

/// Esegue il confronto e ne mostra l'esito.
fn run(window: &AppWindow, lab: &SharedLab) {
    let services = lab.borrow();
    let dizionari = comparable(&services);
    let sessioni = sessions(&services);

    let (Some(candidato), Some((session_id, _))) = (
        scelta(&dizionari, window.get_lab_dictionary_index()),
        scelta(&sessioni, window.get_lab_session_index()),
    ) else {
        return;
    };
    // Il riferimento può essere la versione di un altro dizionario: quello da
    // cui la bozza è stata duplicata (ADR-0141).
    let (Some(riferimento), Some(dizionario_riferimento)) = (
        candidato.baseline.as_ref(),
        candidato.baseline_dictionary_id(),
    ) else {
        return;
    };

    let (Ok(configurazione_pubblicata), Ok(configurazione_candidata)) = (
        services
            .dictionaries
            .configuration_of_version(dizionario_riferimento, riferimento.version()),
        services
            .dictionaries
            .configuration_of_version(candidato.dictionary.id, &candidato.draft),
    ) else {
        window.set_lab_summary(crate::lingua::schermo(
            "Non è stato possibile risolvere le due versioni del dizionario.",
        ));
        return;
    };

    let Ok(righe) = services.database.session_bodies(*session_id, MAX_CONTENTS) else {
        window.set_lab_summary(crate::lingua::schermo(
            "Non è stato possibile leggere i contenuti della sessione.",
        ));
        return;
    };
    let troncato = righe.len() == MAX_CONTENTS as usize;
    let contenuti = LabContent::from_rows(righe);

    let esito = compare(
        &contenuti,
        &configurazione_pubblicata,
        &configurazione_candidata,
    );

    mostra(window, &esito, troncato);
}

/// Riporta l'esito nell'interfaccia.
///
/// # Perché il troncamento si dichiara
///
/// Perché un confronto su una parte che si spacciasse per un confronto su tutto
/// farebbe approvare una modifica guardando un decimo dei contenuti.
fn mostra(window: &AppWindow, esito: &LabComparison, troncato: bool) {
    let righe: Vec<LabRow> = esito
        .findings
        .iter()
        .map(|finding| LabRow {
            content: crate::lingua::schermo(format!("Contenuto {}", finding.content_id.get())),
            reason: SharedString::from(finding.reason()),
            raised: finding.shift == LevelShift::Raised,
            lowered: finding.shift == LevelShift::Lowered,
            not_reproducing: !finding.reproduces_archive(),
        })
        .collect();

    let mut riepilogo = esito.as_sentence();
    if troncato {
        riepilogo.push_str(&format!(
            " ATTENZIONE: sono stati esaminati i primi {MAX_CONTENTS} contenuti della \
             sessione, non tutti. Ciò che questo confronto dice vale per quelli."
        ));
    }

    window.set_lab_summary(crate::lingua::schermo(riepilogo));
    window.set_lab_findings(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Chiude il riscontro sui dizionari e ne toglie le righe.
///
/// # Perché si chiude cambiando sessione
///
/// Perché il riscontro è **di quella sessione**: lasciarlo sotto gli occhi
/// dopo averne scelta un'altra lo farebbe leggere come il riscontro della
/// nuova. È la stessa ragione per cui l'esito del confronto sparisce.
fn chiudi_riscontro(window: &AppWindow) {
    window.set_feedback_open(false);
    window.set_feedback_summary(SharedString::default());
    window.set_feedback_rules(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
}

/// Legge che cosa la revisione umana dice delle regole della sessione scelta.
///
/// # Che cosa questa funzione non fa
///
/// Non tocca alcun dizionario, e non potrebbe: l'aggregazione sta in
/// `lisi-services::feedback`, che non conosce l'archivio, e il suggerimento che
/// ne esce **non contiene un valore nuovo**. Non c'è nulla da applicare.
fn apri_riscontro(window: &AppWindow, lab: &SharedLab) {
    let services = lab.borrow();
    let sessioni = sessions(&services);

    let Some((session_id, etichetta)) = scelta(&sessioni, window.get_lab_session_index()) else {
        window.set_feedback_open(true);
        window.set_feedback_summary(crate::lingua::schermo(
            "Nessuna sessione scelta: il riscontro si legge sui contenuti di una sessione.",
        ));
        window.set_feedback_rules(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let esito = match services.review.dictionary_feedback(*session_id) {
        Ok(Some(esito)) => esito,
        // Senza la fotografia dei termini non si sa da quale dizionario, e in
        // quale versione, una regola venisse allora. L'unica alternativa
        // sarebbe attribuire le decisioni di ieri ai dizionari di oggi.
        Ok(None) => {
            window.set_feedback_open(true);
            window.set_feedback_summary(crate::lingua::schermo(format!(
                "La sessione «{etichetta}» non conserva l'elenco dei termini con cui i \
                 contenuti furono analizzati. Senza, le decisioni delle persone non sono \
                 attribuibili ad alcun dizionario: attribuirle a quelli di oggi \
                 accuserebbe una versione di ciò che aveva fatto un'altra."
            )));
            window.set_feedback_rules(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
            return;
        }
        Err(errore) => {
            tracing::warn!(errore = %errore, "riscontro sui dizionari non leggibile");
            window.set_feedback_open(true);
            window.set_feedback_summary(crate::lingua::schermo(
                "Non è stato possibile leggere le decisioni di questa sessione.",
            ));
            window.set_feedback_rules(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
            return;
        }
    };

    let troncato = esito.rules.len() > MAX_FEEDBACK_ROWS;
    let righe: Vec<FeedbackRow> = esito
        .rules
        .iter()
        .take(MAX_FEEDBACK_ROWS)
        .map(|regola| {
            let invito = regola.suggestion();
            FeedbackRow {
                // La schermata RICEVE le due frasi già composte e non le
                // ricompone: la riga e il servizio non devono poter dire due
                // cose diverse (DEC-252, quinta superficie).
                rule: SharedString::from(regola.identity()),
                counts: crate::lingua::schermo(regola.counts_sentence()),
                suggested: invito.is_some(),
                suggestion: SharedString::from(
                    invito
                        .map(|invito| invito.as_sentence())
                        .unwrap_or_default(),
                ),
            }
        })
        .collect();

    let mut riepilogo = esito.as_sentence();
    if troncato {
        riepilogo.push_str(&format!(
            " Sono mostrate le prime {MAX_FEEDBACK_ROWS} righe in ordine alfabetico, non \
             tutte: l'ordine non è una classifica."
        ));
    }

    window.set_feedback_open(true);
    window.set_feedback_summary(crate::lingua::schermo(riepilogo));
    window.set_feedback_rules(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Registra i gestori dei comandi della schermata.
pub fn wire(window: &AppWindow, lab: &SharedLab) {
    for registra in [0_u8, 1, 2] {
        let weak = window.as_weak();
        let lab = Rc::clone(lab);
        match registra {
            0 => window.on_lab_shown(move || {
                let Some(window) = weak.upgrade() else { return };
                refresh(&window, &lab);
            }),
            1 => window.on_lab_dictionary_chosen(move |_| {
                if crate::lock::refuse_while_locked("lab_dictionary_chosen") {
                    return;
                }
                let Some(window) = weak.upgrade() else { return };
                // Cambiando dizionario l'esito precedente non vale piu': era il
                // confronto di un'altra coppia di versioni, e lasciarlo sotto
                // gli occhi lo farebbe leggere come quello nuovo.
                window.set_lab_summary(SharedString::default());
                window.set_lab_findings(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
                refresh(&window, &lab);
            }),
            _ => window.on_lab_session_chosen(move |_| {
                if crate::lock::refuse_while_locked("lab_session_chosen") {
                    return;
                }
                let Some(window) = weak.upgrade() else { return };
                window.set_lab_summary(SharedString::default());
                window.set_lab_findings(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
                // Il riscontro e' di QUELLA sessione: lasciarlo sotto gli occhi
                // dopo averne scelta un'altra lo farebbe leggere come il
                // riscontro della nuova.
                chiudi_riscontro(&window);
                refresh(&window, &lab);
            }),
        }
    }

    {
        let weak = window.as_weak();
        let lab = Rc::clone(lab);
        window.on_run_lab(move || {
            if crate::lock::refuse_while_locked("run_lab") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            run(&window, &lab);
        });
    }

    {
        let weak = window.as_weak();
        let lab = Rc::clone(lab);
        window.on_open_feedback(move || {
            if crate::lock::refuse_while_locked("open_feedback") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            apri_riscontro(&window, &lab);
        });
    }

    {
        let weak = window.as_weak();
        window.on_close_feedback(move || {
            if crate::lock::refuse_while_locked("close_feedback") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            chiudi_riscontro(&window);
        });
    }
}

#[cfg(test)]
mod guardie {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("rule_lab.rs");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod guardie {") else {
            panic!("il modulo deve avere un blocco di guardie riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Il laboratorio non pubblica e non scrive.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un pulsante «Pubblica» qui accanto sembrerebbe comodo: si è appena visto
    /// che cosa cambia, e pubblicare è il gesto successivo. Ma una schermata di
    /// valutazione che pubblica è una schermata in cui si pubblica **per
    /// inerzia**, subito dopo aver letto un esito che sembrava buono, senza il
    /// passaggio deliberato che la pubblicazione merita.
    #[test]
    fn il_laboratorio_non_pubblica_e_non_scrive() {
        let codice = codice_senza_commenti();

        for scrittura in [
            "publish(",
            "add_terms(",
            "remove_term(",
            "insert_",
            "append_audit",
            "set_status(",
        ] {
            assert!(
                !codice.contains(scrittura),
                "la schermata del Rule Lab chiama «{scrittura}»: il confronto è a vuoto, \
                 e la pubblicazione è un gesto deliberato che si compie altrove"
            );
        }

        // Solo il blocco della pagina del laboratorio.
        //
        // # Perché non tutto il file
        //
        // Perché «Pubblica la bozza» **esiste e deve esistere**: è il comando
        // della schermata Dizionari, ed è lì che la pubblicazione si compie.
        // Cercarlo nell'intero file farebbe diventare rossa questa prova per il
        // pulsante giusto al posto giusto — e una prova che si accende su ciò
        // che è corretto non verifica quello che dichiara di verificare.
        for riga in pagina_del_laboratorio()
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("label:") || riga.starts_with("text:"))
        {
            for vietato in ["Pubblica", "Applica", "Salva"] {
                assert!(
                    !riga.contains(vietato),
                    "la pagina del laboratorio offre «{vietato}»: il confronto è a vuoto, \
                     e la pubblicazione è un gesto deliberato che si compie in Dizionari \
                     — «{riga}»"
                );
            }
        }
    }

    /// Il blocco dell'interfaccia che disegna la pagina del laboratorio.
    fn pagina_del_laboratorio() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(19)
    }

    /// La schermata dice che cosa confronterà **prima** di confrontare.
    ///
    /// Il confronto costa quanto l'analisi, per due configurazioni e per il
    /// numero di contenuti. Chi lo scopre dopo lo scopre aspettando.
    #[test]
    fn la_schermata_dice_che_cosa_confrontera_prima_di_farlo() {
        let Some(anteprima) = UI.find("text: root.lab-preview;") else {
            panic!("l'anteprima deve esistere");
        };
        let Some(comando) = UI.find("root.run-lab();") else {
            panic!("il comando deve esistere");
        };
        assert!(
            anteprima < comando,
            "che cosa si sta per confrontare va detto prima del pulsante"
        );
        assert!(
            UI.contains("può richiedere") || THIS_MODULE.contains("può richiedere"),
            "il costo va dichiarato prima di essere pagato"
        );
    }

    /// Senza le due versioni o senza contenuti il comando è spento.
    ///
    /// Un confronto su zero contenuti produrrebbe «nessuna differenza», che è
    /// la frase più pericolosa che il laboratorio possa dire.
    #[test]
    fn senza_qualcosa_da_confrontare_il_comando_e_spento() {
        assert!(
            UI.contains("enabled: root.lab-can-run;"),
            "il comando deve spegnersi quando non c'è nulla da confrontare"
        );

        let codice = codice_senza_commenti();
        assert!(
            codice.contains("if quanti == 0"),
            "una sessione senza contenuti deve spegnere il comando, non produrre un esito"
        );
    }

    /// Il blocco dell'interfaccia che disegna il riscontro sui dizionari.
    fn blocco_del_riscontro() -> &'static str {
        let Some(inizio) = UI.find("if root.feedback-open: Rectangle {") else {
            panic!("il riscontro sui dizionari deve esistere nella pagina del laboratorio");
        };
        let Some(fine) = UI[inizio..].find("text: root.lab-preview;") else {
            panic!("il riscontro deve stare prima dell'anteprima del confronto");
        };
        &UI[inizio..inizio + fine]
    }

    /// **Il riscontro non offre alcun modo di cambiare una regola.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un comando «Applica» accanto a «nove decisioni la smentiscono»
    /// sembrerebbe la conclusione naturale della frase. Sarebbe una modifica
    /// del dizionario compiuta **per inerzia**, sulla base di un conteggio che
    /// nessuno ha discusso — e NEXUM non modifica mai un dizionario.
    ///
    /// La garanzia vera è altrove: il suggerimento non contiene un valore
    /// nuovo, quindi non c'è nulla da applicare. Questa guardia impedisce che
    /// qualcuno apra la strada mettendo il pulsante prima del campo.
    #[test]
    fn il_riscontro_non_offre_alcun_modo_di_cambiare_una_regola() {
        for riga in blocco_del_riscontro()
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("label:") || riga.starts_with("text: \""))
        {
            for vietato in [
                "Applica", "Correggi", "Rimuovi", "Abbassa", "Alza", "Modifica", "Pubblica",
                "Accetta",
            ] {
                assert!(
                    !riga.contains(vietato),
                    "il riscontro offre «{vietato}»: NEXUM suggerisce, e un dizionario lo \
                     cambia una persona — «{riga}»"
                );
            }
        }

        let codice = codice_senza_commenti();
        for scrittura in ["update_term", "set_level", "publish_version", "save_draft"] {
            assert!(
                !codice.contains(scrittura),
                "la schermata chiama «{scrittura}»: il riscontro conta e nient'altro"
            );
        }
    }

    /// Il riscontro **non compare se nessuno lo chiede**.
    ///
    /// Costa una lettura di tutta la sessione; e un'aggregazione che si aprisse
    /// da sola verrebbe letta come un giudizio del programma sui dizionari, che
    /// non è.
    #[test]
    fn il_riscontro_non_compare_se_nessuno_lo_chiede() {
        assert!(
            UI.contains("in property <bool> feedback-open: false;"),
            "il riscontro deve partire chiuso"
        );
        assert!(
            UI.contains("if !root.feedback-open: Rectangle {"),
            "deve esserci un comando che lo chiede"
        );
        assert!(
            UI.contains("root.open-feedback();"),
            "il comando deve chiamare l'apertura"
        );
    }

    /// Cambiare sessione chiude il riscontro.
    ///
    /// Il riscontro è **di quella sessione**: lasciarlo sotto gli occhi dopo
    /// averne scelta un'altra lo farebbe leggere come il riscontro della nuova.
    #[test]
    fn cambiare_sessione_chiude_il_riscontro() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("window.on_lab_session_chosen(move |_| {") else {
            panic!("il gestore del cambio di sessione deve esistere");
        };
        let resto = &codice[inizio..];
        let Some(fine) = resto.find("\n            }),") else {
            panic!("il gestore deve chiudersi");
        };
        assert!(
            resto[..fine].contains("chiudi_riscontro(&window)"),
            "cambiando sessione il riscontro precedente deve sparire"
        );
    }

    /// Un riscontro troncato lo dichiara, e dice che l'ordine non è una
    /// classifica.
    ///
    /// Ordinare per numero di smentite comporrebbe una classifica delle regole
    /// peggiori: un punteggio scritto con l'ordine invece che con una cifra.
    #[test]
    fn un_riscontro_troncato_lo_dichiara_e_nega_di_essere_una_classifica() {
        let codice = codice_senza_commenti();

        assert!(
            codice.contains("let troncato = esito.rules.len() > MAX_FEEDBACK_ROWS;"),
            "il troncamento va rilevato, non supposto"
        );
        assert!(
            codice.contains("non è una classifica"),
            "l'ordine alfabetico va dichiarato per non essere scambiato per una graduatoria"
        );
        assert!(
            !codice.contains("sort_by_key") && !codice.contains("sort_by("),
            "le righe restano nell'ordine dell'aggregazione"
        );
    }

    /// **Il ciclo intero sulla finestra vera** (OPERATOR-E2E-REMEDIATION-01,
    /// F-07): dizionario pubblicato → «Nuova versione» → un termine aggiunto
    /// alla bozza → il Laboratorio la mostra e dice che cosa cambia → torna
    /// alla bozza → pubblicata con la conferma → la nuova versione è in
    /// elenco, e la vecchia non è cambiata.
    #[test]
    fn bozza_modifica_confronto_e_pubblicazione() {
        use lisi_core::model::dictionary::{
            DictionaryScope, DictionaryVisibility, MatchMode, NewDictionaryTerm, SuggestedLevel,
        };
        use lisi_core::text::{
            DictionaryDescription, DictionaryName, LanguageTag, TermCategory, TermNote, TermText,
        };
        use slint::{Model as _, SharedString};

        i_slint_backend_testing::init_no_event_loop();
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("prova.sqlite");
        let apri = || {
            let Ok(archivio) = lisi_services::Database::open(&percorso) else {
                panic!("l'archivio di prova deve aprirsi");
            };
            archivio
        };

        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        let Some(dizionari) = crate::dictionaries::create_service(apri()) else {
            panic!("la libreria deve aprirsi");
        };

        // Un dizionario personale pubblicato, con un termine.
        let (Ok(nome), Ok(descrizione), Ok(attore)) = (
            DictionaryName::try_new("Incendi di prova"),
            DictionaryDescription::try_new("prova"),
            crate::operator::audit_actor(),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let istante = lisi_core::Timestamp::from_millis(1_700_000_000_000);
        let Ok((id, v1)) = dizionari.borrow().create(
            &lisi_services::dictionaries::DictionaryProposal {
                name: nome,
                description: descrizione,
                scope: DictionaryScope::Thematic,
                visibility: DictionaryVisibility::Personal,
            },
            &attore,
            istante,
        ) else {
            panic!("il dizionario deve potersi creare");
        };
        let (Ok(text), Ok(category), Ok(language), Ok(suggested_level), Ok(note)) = (
            TermText::try_new("incendio"),
            TermCategory::try_new("azione"),
            LanguageTag::try_new("it"),
            SuggestedLevel::try_new(3),
            TermNote::try_new(""),
        ) else {
            panic!("il termine di prova deve essere valido");
        };
        let termine = NewDictionaryTerm {
            version_id: v1,
            text,
            category,
            language,
            match_mode: MatchMode::NormalizedWord,
            suggested_level,
            note,
        };
        let Ok(_) = dizionari
            .borrow_mut()
            .add_terms(v1, &[termine], &attore, istante)
        else {
            panic!("il termine deve potersi aggiungere");
        };
        let Ok(()) = dizionari.borrow().publish(v1, &attore, istante) else {
            panic!("la prima versione deve potersi pubblicare");
        };

        crate::dictionaries::wire(&window, &dizionari);
        let Some(laboratorio) = super::create_service(apri(), apri(), apri()) else {
            panic!("il laboratorio deve aprirsi");
        };
        super::wire(&window, &laboratorio);
        let id_ui = i32::try_from(id.get()).unwrap_or(0);

        // Il Laboratorio, senza bozze, dice come aprirne una.
        super::refresh(&window, &laboratorio);
        assert!(!window.get_lab_has_candidates());
        assert!(window.get_lab_preview().contains("Nuova versione"));

        // NUOVA VERSIONE dalla schermata Dizionari: il pulsante sceglie il
        // dizionario e poi chiede la versione, come qui.
        window.set_selected_dictionary(id_ui);
        window.invoke_start_new_version(id_ui);
        assert!(
            window.get_draft_open(),
            "la bozza si apre: {}",
            window.get_dictionaries_message()
        );
        assert!(window.get_draft_title().contains("v2"));

        // MODIFICA: un termine nuovo; lo stesso una seconda volta è un doppione.
        window.set_draft_term_input(SharedString::from("rogo"));
        window.set_draft_category_input(SharedString::from("azione"));
        window.invoke_add_draft_term();
        assert!(window.get_dictionaries_message().contains("aggiunto"));
        window.set_draft_term_input(SharedString::from("Rogo"));
        window.invoke_add_draft_term();
        assert!(
            window
                .get_dictionaries_message()
                .contains("c'è già nella bozza"),
            "un doppione non è un guasto tecnico: {}",
            window.get_dictionaries_message()
        );

        // CONFRONTA: «Prova nel Laboratorio» apre su quella bozza.
        window.set_lab_requested_dictionary(id_ui);
        super::refresh(&window, &laboratorio);
        assert!(window.get_lab_has_candidates());
        assert_eq!(
            window.get_lab_requested_dictionary(),
            0,
            "la richiesta si consuma"
        );
        assert_eq!(window.get_lab_draft_dictionary(), id_ui);
        assert_eq!(
            window.get_lab_term_rows().row_count(),
            1,
            "un termine aggiunto"
        );
        assert!(
            window.get_lab_term_summary().contains("aggiunge 1"),
            "{}",
            window.get_lab_term_summary()
        );
        let Some(riga) = window.get_lab_term_rows().row_data(0) else {
            panic!("la riga del termine deve esserci");
        };
        assert!(riga.sentence.contains("«rogo»"));
        assert!(
            !window.get_lab_can_run(),
            "senza monitoraggi non c'è un effetto da misurare"
        );

        // PUBBLICA: la versione 2 nasce, la 1 resta com'era.
        window.set_selected_dictionary(id_ui);
        window.invoke_publish_draft();
        assert!(
            window
                .get_dictionaries_message()
                .contains("versione 2 pubblicata"),
            "{}",
            window.get_dictionaries_message()
        );
        let Ok(vecchi) = dizionari.borrow().terms(v1) else {
            panic!("la versione 1 deve rileggersi");
        };
        assert_eq!(vecchi.len(), 1, "la versione pubblicata non si tocca");
        let riga_dizionario = window
            .get_dictionaries()
            .iter()
            .find(|d| d.dictionary_id == id_ui);
        assert_eq!(riga_dizionario.map(|d| d.published_version), Some(2));

        // Pubblicata, la bozza non c'è più, e il Laboratorio torna a dirlo.
        super::refresh(&window, &laboratorio);
        assert!(!window.get_lab_has_candidates());
    }

    /// Un confronto troncato lo dichiara.
    #[test]
    fn un_confronto_troncato_lo_dichiara() {
        let codice = codice_senza_commenti();

        assert!(
            codice.contains("non tutti"),
            "un confronto su una parte deve dire di essere su una parte"
        );
        assert!(
            codice.contains("let troncato = righe.len() == MAX_CONTENTS as usize;"),
            "il troncamento va rilevato, non supposto"
        );
    }
}

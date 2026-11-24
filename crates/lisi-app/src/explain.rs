//! «Perché vedo questo?»: il pannello unico (PR-02, ADR-0119).
//!
//! # Tre strade, un pannello
//!
//! - **`explain-this`** — gli elementi la cui risposta si compone da ciò che
//!   la schermata sta già mostrando: una tendenza, un gruppo di segnali, un
//!   vicino del grafo, una voce della coda di lavoro. Chi chiede il perché ha
//!   la cosa davanti, e la sua frase è già sullo schermo (PROV-02).
//! - **`history-explain`** — ciò che si spiega da un contenuto dello Storico:
//!   la riga, il livello, l'avviso, il riscontro. I fatti si leggono
//!   dall'archivio, perché la versione del motore è quella **registrata** con
//!   il contenuto, e la schermata non la conosce (`crate::history`).
//! - **`team-explain`** — la voce della coda dell'ufficio, con
//!   l'identificativo soltanto: la risposta si compone dalla riga che l'Hub ha
//!   consegnato, e una riga che l'Hub non ha mostrato non si spiega
//!   (`crate::team_review`).
//!
//! Tutte e tre finiscono in [`show`], che scrive le tre parti sempre negli
//! stessi campi. Nessuna legge l'orologio.
//!
//! # La porta
//!
//! «Provenienza, note e contesto» apre il Provenance Explorer che già esiste: il
//! percorso del contenuto (PROV-01) o il pannello di PROV-02. Dove l'Explorer
//! non copre l'elemento, la porta non compare.

use lisi_core::model::explanation::{Explained, Explanation};
use lisi_core::model::origin::Origin;
use slint::{ComponentHandle, SharedString};

use crate::why_subject::kind as soggetto;
use crate::{AppWindow, Origine, Spiegabile};

/// Dove porta «Provenienza, note e contesto».
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Door {
    /// Il percorso di un contenuto, nello Storico o negli Avvisi (PROV-01).
    ContentPath(i32),
    /// Il pannello di PROV-02, con il genere del soggetto e la sua chiave.
    SubjectPanel {
        /// Il genere, come lo conosce `crate::why_subject`.
        genere: i32,
        /// La chiave del soggetto.
        chiave: String,
    },
    /// L'Explorer non copre l'elemento, oppure ci si trova già dentro.
    Nowhere,
}

/// Il genere del dominio, dal genere che la schermata indica.
///
/// Il `match` è esaustivo: un genere nuovo nella schermata senza traduzione
/// non compila.
#[must_use]
pub const fn explained_of(genere: Spiegabile) -> Explained {
    match genere {
        Spiegabile::Contenuto => Explained::Content,
        Spiegabile::Avviso => Explained::Alert,
        Spiegabile::Livello => Explained::Level,
        Spiegabile::Riscontro | Spiegabile::RiscontroRetroattivo => Explained::Match,
        Spiegabile::GruppoDiSegnali => Explained::CyberEvent,
        Spiegabile::RigaCronologiaOsservata => Explained::CyberWatchRow { by_a_person: false },
        Spiegabile::RigaCronologiaDiUnaPersona => Explained::CyberWatchRow { by_a_person: true },
        Spiegabile::SuggerimentoDiFonte => Explained::SourceSuggestion,
        Spiegabile::RicercaPubblica => Explained::DiscoveryResult,
        Spiegabile::VoceDellaCoda => Explained::WorkQueueItem,
        Spiegabile::VicinoOsservato => Explained::GraphNode { by_a_person: false },
        Spiegabile::VicinoDeciso => Explained::GraphNode { by_a_person: true },
        Spiegabile::Tendenza => Explained::Trend,
        Spiegabile::Aumento => Explained::Spike,
        Spiegabile::Somiglianza => Explained::Resemblance,
        Spiegabile::Associazione => Explained::PersonAssociation,
        Spiegabile::PeriodoPrioritario => Explained::CoverageGap,
    }
}

/// La risposta su un elemento i cui fatti sono quelli della schermata, con la
/// porta che gli spetta.
///
/// Restituisce `None` per i generi che si spiegano **dall'archivio** — la
/// riga dello Storico, il livello, il riscontro nel percorso — e per fatti
/// vuoti. Un livello spiegato dalla schermata porterebbe la versione di oggi
/// del motore, non quella registrata: sarebbe la risposta sbagliata con la
/// faccia di quella giusta.
#[must_use]
pub fn from_screen(genere: Spiegabile, chiave: &str, fatti: &str) -> Option<(Explanation, Door)> {
    let porta = match genere {
        Spiegabile::Contenuto | Spiegabile::Livello | Spiegabile::Riscontro => return None,
        Spiegabile::GruppoDiSegnali => Door::SubjectPanel {
            genere: soggetto::CYBER_EVENT,
            chiave: chiave.to_owned(),
        },
        Spiegabile::VicinoOsservato => Door::SubjectPanel {
            genere: soggetto::GRAPH_EDGE_OBSERVED,
            chiave: chiave.to_owned(),
        },
        Spiegabile::VicinoDeciso => Door::SubjectPanel {
            genere: soggetto::GRAPH_EDGE_DECIDED,
            chiave: chiave.to_owned(),
        },
        Spiegabile::Associazione => Door::SubjectPanel {
            genere: soggetto::PERSON_ASSOCIATION,
            chiave: chiave.to_owned(),
        },
        Spiegabile::Tendenza => Door::SubjectPanel {
            genere: soggetto::TREND,
            chiave: chiave.to_owned(),
        },
        Spiegabile::Somiglianza => Door::SubjectPanel {
            genere: soggetto::RESEMBLANCE,
            chiave: chiave.to_owned(),
        },
        Spiegabile::Avviso
        | Spiegabile::RiscontroRetroattivo
        | Spiegabile::RigaCronologiaOsservata
        | Spiegabile::RigaCronologiaDiUnaPersona
        | Spiegabile::SuggerimentoDiFonte
        | Spiegabile::RicercaPubblica
        | Spiegabile::VoceDellaCoda
        | Spiegabile::Aumento
        | Spiegabile::PeriodoPrioritario => Door::Nowhere,
    };
    let risposta = lisi_services::why::explain(explained_of(genere), fatti)?;
    Some((risposta, porta))
}

/// Il segno d'origine della schermata, dall'origine del dominio.
#[must_use]
pub const fn origine_of(origin: Origin) -> Origine {
    match origin {
        Origin::Observed => Origine::Osservato,
        Origin::Computed => Origine::Calcolato,
        Origin::Operator => Origine::Operatore,
    }
}

/// Mostra la risposta, nelle tre parti.
pub fn show(window: &AppWindow, risposta: &Explanation, porta: &Door) {
    close(window);

    window.set_explain_subject(SharedString::from(risposta.subject()));
    window.set_explain_rule(SharedString::from(risposta.rule()));
    window.set_explain_facts(SharedString::from(risposta.facts()));
    window.set_explain_origin(origine_of(risposta.certainty()));
    window.set_explain_origin_note(crate::lingua::schermo(risposta.certainty().as_sentence()));
    window.set_explain_not_meaning(SharedString::from(risposta.does_not_mean()));

    match porta {
        Door::ContentPath(contenuto) => {
            window.set_explain_door_content(*contenuto);
            window.set_explain_has_door(true);
        }
        Door::SubjectPanel { genere, chiave } => {
            window.set_explain_door_subject(*genere);
            window.set_explain_door_key(SharedString::from(chiave.as_str()));
            window.set_explain_has_door(true);
        }
        Door::Nowhere => {}
    }

    window.set_explain_open(true);
}

/// Dice che la risposta non è disponibile, e nient'altro.
pub fn show_unavailable(window: &AppWindow, explained: Explained, frase: &str) {
    close(window);
    window.set_explain_subject(crate::lingua::schermo(explained.label()));
    window.set_explain_unavailable(crate::lingua::schermo(frase));
    window.set_explain_open(true);
}

/// Chiude il pannello, svuotando ogni campo.
///
/// # Perché si svuota tutto
///
/// Perché una parte rimasta dietro un pannello chiuso tornerebbe a comparire
/// accanto a un elemento diverso, e una porta rimasta aperta porterebbe alla
/// provenienza di un altro.
fn close(window: &AppWindow) {
    window.set_explain_open(false);
    window.set_explain_subject(SharedString::new());
    window.set_explain_rule(SharedString::new());
    window.set_explain_facts(SharedString::new());
    window.set_explain_origin(Origine::NonRegistrata);
    window.set_explain_origin_note(SharedString::new());
    window.set_explain_not_meaning(SharedString::new());
    window.set_explain_has_door(false);
    window.set_explain_unavailable(SharedString::new());
    window.set_explain_door_content(-1);
    window.set_explain_door_subject(-1);
    window.set_explain_door_key(SharedString::new());
}

/// Apre la provenienza a cui porta l'ultima risposta.
fn open_door(window: &AppWindow) {
    let contenuto = window.get_explain_door_content();
    let genere = window.get_explain_door_subject();
    let chiave = window.get_explain_door_key();
    let fatti = window.get_explain_facts();
    close(window);

    if contenuto > 0 {
        // Il contenuto della risposta diventa quello scelto, se non lo era:
        // il percorso si apre sul contenuto scelto, e il pannello del percorso
        // chiude quello di un altro contenuto.
        if window.get_selected_content() != contenuto {
            window.invoke_select_content(contenuto);
        }
        window.invoke_history_open_why(contenuto);
    } else if genere >= 0 {
        crate::why_subject::open(window, genere, chiave.as_str(), fatti.as_str());
    }
}

/// Collega il pannello.
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_explain_this(move |genere, chiave, fatti| {
            if crate::lock::refuse_while_locked("explain_this") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            if let Some((risposta, porta)) = from_screen(genere, chiave.as_str(), fatti.as_str()) {
                show(&window, &risposta, &porta);
            }
        });
    }

    {
        let handle = window.as_weak();
        window.on_explain_open_provenance(move || {
            if crate::lock::refuse_while_locked("explain_open_provenance") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                open_door(&window);
            }
        });
    }

    {
        let handle = window.as_weak();
        window.on_close_explain(move || {
            if crate::lock::refuse_while_locked("close_explain") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close(&window);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::explanation::{Explained, PART_CAUSE, PART_CERTAINTY, PART_NOT_MEANING};

    use super::{Door, explained_of, from_screen};
    use crate::Spiegabile;

    /// La finestra, il componente e questo modulo, per le guardie sulla forma.
    const UI: &str = include_str!("../ui/app-window.slint");
    const COMPONENTI: &str = include_str!("../ui/components.slint");
    const THIS_MODULE: &str = include_str!("explain.rs");

    /// Ogni genere della schermata, con il nome che ha nel file Slint.
    const COMANDI: &[(&str, Spiegabile)] = &[
        ("contenuto", Spiegabile::Contenuto),
        ("avviso", Spiegabile::Avviso),
        ("livello", Spiegabile::Livello),
        ("riscontro", Spiegabile::Riscontro),
        ("riscontro-retroattivo", Spiegabile::RiscontroRetroattivo),
        ("gruppo-di-segnali", Spiegabile::GruppoDiSegnali),
        (
            "riga-cronologia-osservata",
            Spiegabile::RigaCronologiaOsservata,
        ),
        (
            "riga-cronologia-di-una-persona",
            Spiegabile::RigaCronologiaDiUnaPersona,
        ),
        ("suggerimento-di-fonte", Spiegabile::SuggerimentoDiFonte),
        ("ricerca-pubblica", Spiegabile::RicercaPubblica),
        ("voce-della-coda", Spiegabile::VoceDellaCoda),
        ("vicino-osservato", Spiegabile::VicinoOsservato),
        ("vicino-deciso", Spiegabile::VicinoDeciso),
        ("tendenza", Spiegabile::Tendenza),
        ("aumento", Spiegabile::Aumento),
        ("somiglianza", Spiegabile::Somiglianza),
        ("associazione", Spiegabile::Associazione),
        ("periodo-prioritario", Spiegabile::PeriodoPrioritario),
    ];

    /// Il file Slint senza i commenti: un genere nominato in un commento non è
    /// un comando.
    fn senza_commenti(sorgente: &str) -> String {
        sorgente
            .lines()
            .map(|riga| riga.split_once("//").map_or(riga, |(codice, _)| codice))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco che comincia in `inizio`, fino alla graffa che lo chiude.
    ///
    /// Salta le stringhe: una graffa in un testo non chiude niente.
    fn blocco(sorgente: &str, inizio: usize) -> &str {
        let mut profondita = 0_i32;
        let mut in_stringa = false;
        let mut precedente = ' ';
        for (posizione, carattere) in sorgente[inizio..].char_indices() {
            match carattere {
                '"' if precedente != '\\' => in_stringa = !in_stringa,
                '{' if !in_stringa => profondita += 1,
                '}' if !in_stringa => {
                    profondita -= 1;
                    if profondita == 0 {
                        return &sorgente[inizio..=inizio + posizione];
                    }
                }
                _ => {}
            }
            precedente = carattere;
        }
        &sorgente[inizio..]
    }

    /// **Ogni genere di elemento ha il suo comando sullo schermo** (PR-02,
    /// controllo negativo 1).
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che un genere esista nel dominio — con la sua regola, la sua origine,
    /// la sua frase — e che nessun elenco offra la domanda. Chi la impara su un
    /// elenco la cerca sugli altri, e non trovandola conclude che lì non c'è
    /// niente da chiedere.
    #[test]
    fn ogni_genere_ha_il_suo_comando() {
        let ui = senza_commenti(UI);
        // Il genere del Team passa dal suo comando: `team-explain`.
        assert!(ui.contains("root.team-explain(riga.content-id)"));
        let mut coperti = vec![Explained::WorkQueueItem];

        for (nome, variante) in COMANDI {
            if ui.contains(&format!("Spiegabile.{nome},"))
                || ui.contains(&format!("Spiegabile.{nome};"))
                || ui.contains(&format!("Spiegabile.{nome} "))
            {
                coperti.push(explained_of(*variante));
            }
        }

        for genere in Explained::ALL {
            assert!(
                coperti.contains(&genere),
                "«{}» non ha il comando «Perché vedo questo?» su nessun elenco",
                genere.label()
            );
        }
    }

    /// **La tabella dei nomi è la stessa dell'enumerazione Slint**: un genere
    /// aggiunto nella schermata e dimenticato qui passerebbe la prova qui
    /// sopra senza essere guardato.
    #[test]
    fn la_tabella_e_l_enumerazione_coincidono() {
        let Some((_, dopo)) = COMPONENTI.split_once("export enum Spiegabile {") else {
            panic!("l'enumerazione Spiegabile deve esistere");
        };
        let Some((corpo, _)) = dopo.split_once('}') else {
            panic!("l'enumerazione deve chiudersi");
        };
        let nomi: Vec<&str> = corpo
            .split(',')
            .map(str::trim)
            .filter(|nome| !nome.is_empty())
            .collect();
        let tabella: Vec<&str> = COMANDI.iter().map(|(nome, _)| *nome).collect();
        assert_eq!(nomi, tabella);
    }

    /// **L'etichetta del comando è una sola**, e nessuna istanza la cambia.
    #[test]
    fn il_comando_ha_un_nome_solo() {
        assert!(crate::surface_text::assegna(
            COMPONENTI,
            "label",
            "Perché vedo questo?"
        ));
        let ui = senza_commenti(UI);
        for (inizio, _) in ui.match_indices("PercheVedoQuesto {") {
            assert!(
                !blocco(&ui, inizio).contains("label:"),
                "un'istanza di PercheVedoQuesto non può cambiare l'etichetta"
            );
        }
        assert!(ui.matches("PercheVedoQuesto {").count() >= 17);
        for vecchio in [
            "label: \"Perché sto vedendo questo?\"",
            "label: \"Che genere di certezza è?\"",
            "root.open-why-subject(",
        ] {
            assert!(!ui.contains(vecchio), "resta il vecchio nome: {vecchio}");
        }
    }

    /// **Le tre parti, con i titoli del dominio, in quest'ordine**, e la terza
    /// senza condizioni (PR-02, controllo negativo 3 per la schermata).
    #[test]
    fn il_pannello_ha_le_tre_parti_e_la_terza_non_ha_condizioni() {
        let ui = senza_commenti(UI);
        let Some(inizio) = ui.find("if root.explain-open: Rectangle {") else {
            panic!("il pannello deve esistere");
        };
        let pannello = &ui[inizio..];
        let (Some(uno), Some(due), Some(tre)) = (
            pannello.find(&format!("text: @tr(\"{PART_CAUSE}\")")),
            pannello.find(&format!("text: @tr(\"{PART_CERTAINTY}\")")),
            pannello.find(&format!("text: @tr(\"{PART_NOT_MEANING}\")")),
        ) else {
            panic!("una delle tre parti manca dal pannello");
        };
        assert!(uno < due && due < tre);

        let Some(frase) = pannello.find("text: root.explain-not-meaning;") else {
            panic!("la parte 3 deve essere mostrata");
        };
        let Some(scorrimento) = pannello.find("HudScroll {") else {
            panic!("il pannello deve scorrere");
        };
        assert!(
            !pannello[scorrimento..frase].contains("if "),
            "la parte 3 non deve avere condizioni oltre alla disponibilità della risposta"
        );
    }

    /// **Chiudere svuota ogni campo**, porta compresa.
    #[test]
    fn chiudere_svuota_ogni_campo() {
        let Some((_, dopo)) = THIS_MODULE.split_once("fn close(window: &AppWindow) {") else {
            panic!("close deve esistere");
        };
        let Some((corpo, _)) = dopo.split_once("\n}\n") else {
            panic!("close deve chiudersi");
        };
        let ui = senza_commenti(UI);
        let proprieta: Vec<&str> = ui
            .lines()
            .filter_map(|riga| riga.trim().strip_prefix("in property <"))
            .filter_map(|resto| resto.split_once("> ").map(|(_, nome)| nome))
            .filter_map(|nome| nome.split([':', ';']).next())
            .filter(|nome| nome.starts_with("explain-"))
            .collect();
        assert!(proprieta.len() >= 12, "{proprieta:?}");
        for nome in proprieta {
            let setter = format!("set_{}(", nome.replace('-', "_"));
            assert!(corpo.contains(&setter), "close non svuota «{nome}»");
        }
    }

    /// **Ciò che si spiega dall'archivio non si spiega dalla schermata.**
    #[test]
    fn i_generi_dell_archivio_non_si_spiegano_dalla_schermata() {
        for genere in [
            Spiegabile::Contenuto,
            Spiegabile::Livello,
            Spiegabile::Riscontro,
        ] {
            assert!(
                from_screen(genere, "1", "Un fatto.").is_none(),
                "{genere:?}"
            );
        }
        let ui = senza_commenti(UI);
        for nome in ["contenuto", "livello", "riscontro,"] {
            assert!(
                !ui.contains(&format!("root.explain-this(Spiegabile.{nome}")),
                "«{nome}» chiesto alla schermata invece che all'archivio"
            );
        }
    }

    /// **La porta c'è dove l'Explorer copre l'elemento**, e non altrove.
    #[test]
    fn la_porta_c_e_dove_l_explorer_copre_l_elemento() {
        let Some((_, porta)) = from_screen(Spiegabile::Tendenza, "molotov", "14 volte.") else {
            panic!("una tendenza con fatti ha una risposta");
        };
        assert!(matches!(porta, Door::SubjectPanel { genere: 4, .. }));
        let Some((_, porta)) = from_screen(Spiegabile::Aumento, "molotov", "14 volte.") else {
            panic!("un aumento con fatti ha una risposta");
        };
        assert_eq!(porta, Door::Nowhere);
    }

    /// **Stessa domanda, stessa risposta**, e il modulo non legge l'orologio
    /// (PR-02, controllo negativo 4 per la schermata).
    #[test]
    fn la_risposta_non_dipende_dall_orologio() {
        for (_, variante) in COMANDI {
            assert_eq!(
                from_screen(*variante, "k", "Un fatto."),
                from_screen(*variante, "k", "Un fatto.")
            );
        }
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for vietato in ["now(", "SystemTime", "Instant::"] {
            assert!(!produzione.contains(vietato), "«{vietato}» nel modulo");
        }
    }
}

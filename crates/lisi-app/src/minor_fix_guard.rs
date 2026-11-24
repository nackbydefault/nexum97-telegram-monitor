//! Le voci di NEXUM97-MINOR-FIX-01 (ADR-0155) che vivono nell'interfaccia, sotto
//! prova sul sorgente.
//!
//! Sono frasi, condizioni e comandi che senza una finestra non si guardano: la
//! prova legge lo slint e il Rust e fallisce se una correzione sparisce. La
//! verifica a vista resta nella coda umana (HVQ-119).

const UI: &str = include_str!("../ui/app-window.slint");
const COMPONENTS: &str = include_str!("../ui/components.slint");
const RECOVERY: &str = include_str!("recovery.rs");
const DICTIONARIES: &str = include_str!("dictionaries.rs");
const GRAPH: &str = include_str!("graph.rs");

/// Il corpo di una funzione Rust, fino alla prima riga che chiude a colonna 0.
fn corpo<'a>(codice: &'a str, firma: &str) -> &'a str {
    let Some(inizio) = codice.find(firma) else {
        panic!("«{firma}» deve esistere");
    };
    let resto = &codice[inizio..];
    let fine = resto.find("\n}\n").unwrap_or(resto.len());
    &resto[..fine]
}

/// **In Esercitazione i due recuperi dicono la frase dell'Esercitazione**
/// (CA02-06), prima di toccare il monitoraggio.
#[test]
fn in_esercitazione_i_recuperi_dicono_la_frase_dell_esercitazione() {
    for firma in ["fn begin_survey(", "fn begin_retro_search("] {
        let testo = corpo(RECOVERY, firma);
        let (Some(rifiuto), Some(prestito)) =
            (testo.find("exercise_refusal("), testo.find("borrow_mut()"))
        else {
            panic!("«{firma}» deve chiedere la frase dell'Esercitazione");
        };
        assert!(rifiuto < prestito, "«{firma}»: la frase viene prima");
    }
}

/// **Il Blocco senza account attivo lo dice** (CA02-07): la frase segue la
/// condizione, che il Rust imposta.
#[test]
fn il_blocco_senza_account_lo_dice() {
    assert!(UI.contains("text: !root.lock-has-account"));
    assert!(include_str!("lock.rs").contains("window.set_lock_has_account(has_account);"));
}

/// **Da Fonti si va ad Account** (E2E01-21), fuori dall'Esercitazione.
#[test]
fn da_fonti_si_va_ad_account() {
    let Some(frase) = UI.find("Accedere con l'account d'ufficio per vedere le fonti disponibili.")
    else {
        panic!("la frase deve esistere");
    };
    let dopo = &UI[frase..];
    let Some(pulsante) = dopo.find("label: @tr(\"Vai ad Account\");") else {
        panic!("il pulsante deve seguire la frase");
    };
    assert!(dopo[pulsante..].contains("root.open-page(2);"));
}

/// **La ricerca condivisa fra Avvisi e Storico si dichiara, con il numero**
/// (E2E01-17).
#[test]
fn la_ricerca_condivisa_si_dichiara() {
    // La dichiarazione compare con la ricerca attiva, e conta ciò che si vede.
    let Some(inizio) = UI.find("if root.filter != \"\" || root.only-pending: Rectangle {") else {
        panic!("la dichiarazione deve seguire la ricerca attiva");
    };
    let blocco = &UI[inizio..];
    let fine = blocco.find("\n        }\n").unwrap_or(blocco.len());
    assert!(blocco[..fine].contains("root.entries.length"));
}

/// **La legenda delle origini si legge senza codice** (E2E01-19).
#[test]
fn la_legenda_si_legge_senza_codice() {
    let Some(inizio) = COMPONENTS.find("export component LegendaOrigini") else {
        panic!("la legenda deve esistere");
    };
    let legenda = &COMPONENTS[inizio..];
    let fine = legenda.find("\n}\n").unwrap_or(legenda.len());
    let legenda = &legenda[..fine];
    assert!(legenda.contains("\"Da dove viene ciò che si legge qui sotto:\""));
    for voce in ["(da Telegram)", "(dal programma)", "(da una persona)"] {
        assert!(legenda.contains(voce), "manca «{voce}»");
    }
    assert!(
        !legenda.contains("text: \": \" +"),
        "il vecchio «: …» è tornato"
    );
}

/// **Esc chiude l'elenco a tendina aperto col mouse** (CA02-09): l'elenco
/// prende il fuoco quando si apre, e il campo ha la riserva di Esc.
#[test]
fn esc_chiude_l_elenco_aperto_col_mouse() {
    let Some(inizio) = COMPONENTS.find("export component HudSelect") else {
        panic!("HudSelect deve esistere");
    };
    let select = &COMPONENTS[inizio..];
    let fine = select.find("\nexport component ").unwrap_or(select.len());
    let select = &select[..fine];
    assert!(select.contains("event.text == Key.Escape && root.list-open"));
    let Some(chiavi) = select.find("keys := FocusScope {") else {
        panic!("l'elenco aperto ha il suo ambito dei tasti");
    };
    assert!(
        select[chiavi..]
            .trim_start_matches("keys := FocusScope {")
            .trim_start()
            .contains("init => {"),
        "l'elenco prende il fuoco all'apertura"
    );
}

/// **Il Grafo non tiene un avviso vecchio** (E2E01-20, CA02-10): tornando alla
/// pagina senza figura aperta l'avviso si toglie; Invio nel campo apre.
#[test]
fn il_grafo_non_tiene_un_avviso_vecchio() {
    let mostrato = corpo(GRAPH, "window.on_graph_shown(");
    assert!(mostrato.contains("forget_stale_message(&window)"));
    let Some(campo) = UI.find("label: @tr(\"Contenuto da cui partire\");") else {
        panic!("il campo del numero deve esistere");
    };
    let dopo = &UI[campo..];
    let fine = dopo.find("HudButton").unwrap_or(dopo.len());
    assert!(dopo[..fine].contains("accepted => {"));
    assert!(dopo[..fine].contains("root.graph-start-requested();"));
}

/// **Un dizionario pubblicato si esporta dalla schermata** (GAP-19), con il
/// gestore che rifiuta a postazione bloccata.
#[test]
fn un_dizionario_si_esporta_dalla_schermata() {
    assert!(UI.contains("root.export-dictionary(entry.dictionary-id);"));
    assert!(DICTIONARIES.contains("refuse_while_locked(\"export_dictionary\")"));
    assert!(DICTIONARIES.contains("export_published("));
    assert!(DICTIONARIES.contains("Impronta dei termini"));
}

/// **Il numero dei dizionari utilizzabili segue il plurale** (E2E01-15).
#[test]
fn i_dizionari_utilizzabili_seguono_il_numero() {
    assert!(UI.contains("root.dictionaries-usable-count == 1"));
}

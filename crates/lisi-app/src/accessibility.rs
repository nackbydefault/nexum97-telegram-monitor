//! Verifiche sull'accessibilità dell'interfaccia.
//!
//! Il file `.slint` è codice, ma non è codice Rust: nessuna verifica del
//! compilatore impedisce di aggiungere un elemento cliccabile che la tastiera
//! non raggiunge, o un campo di testo che una tecnologia assistiva legge come
//! «casella di testo» e nient'altro. Questi controlli leggono il file a tempo
//! di compilazione e lo dicono.
//!
//! # Perché non basta guardarlo
//!
//! Un'interfaccia si prova con il mouse mille volte e con il Tab nessuna. Il
//! difetto non si vede: si vede l'assenza di qualcosa che non c'è mai stato.
//! Queste verifiche non sostituiscono la prova con una tecnologia assistiva
//! reale — che resta da fare, ed è dichiarata come tale — ma impediscono la
//! regressione più probabile, cioè l'elemento nuovo aggiunto senza fuoco.

/// Sorgenti dell'interfaccia, letti a tempo di compilazione.
///
/// Sono **tutti** i file che possono contenere un elemento interattivo. Con la
/// sola interfaccia principale, un componente della libreria con una
/// `TouchArea` e senza `FocusScope` sfuggirebbe a ogni controllo: la verifica
/// resterebbe verde mentre l'elemento non esiste per la tastiera. Il controllo
/// deve seguire il codice, non la sua forma di ieri.
const UI_SOURCES: [&str; 3] = [
    include_str!("../ui/app-window.slint"),
    include_str!("../ui/components.slint"),
    include_str!("../ui/brand.slint"),
];

/// Finestra di righe attorno a ciascuna occorrenza del frammento indicato.
///
/// Non è un parser: è una finestra abbastanza ampia da contenere le proprietà
/// dell'elemento e abbastanza stretta da non arrivare a quello successivo.
/// Guarda **anche prima** della riga trovata, perché l'ordine delle proprietà
/// in un file `.slint` è libero e un'etichetta può precedere il ruolo.
#[cfg(test)]
fn windows_around(fragment: &str, before: usize, after: usize) -> Vec<String> {
    let mut blocks = Vec::new();

    // Un file per volta: concatenarli farebbe nascere finestre a cavallo fra la
    // fine di un file e l'inizio del successivo, cioe' elementi che sembrano
    // avere accanto proprieta' che appartengono a un altro sorgente.
    for unit in UI_SOURCES {
        let source: Vec<&str> = unit.lines().collect();

        for (index, line) in source.iter().enumerate() {
            if line.contains(fragment) {
                let start = index.saturating_sub(before);
                let end = index.saturating_add(after).min(source.len());
                blocks.push(source[start..end].join("\n"));
            }
        }
    }
    blocks
}

/// Occorrenze di un frammento, contate per riga.
///
/// `contains` e non `starts_with`: un elemento con un nome — `touch :=
/// TouchArea {` — è la forma più comune, e cercarlo a inizio riga non ne
/// troverebbe nessuno. È il primo modo in cui questo controllo poteva essere
/// verde senza verificare niente, ed è successo scrivendolo.
#[cfg(test)]
fn occurrences(fragment: &str) -> usize {
    UI_SOURCES
        .iter()
        .flat_map(|unit| unit.lines())
        .filter(|line| line.contains(fragment))
        .count()
}

#[cfg(test)]
mod tests {
    use super::{occurrences, windows_around};

    #[test]
    fn everything_that_can_be_clicked_can_also_be_focused() {
        // Ogni elemento interattivo costruito a mano usa una `TouchArea` per il
        // mouse. Se non ha accanto un `FocusScope`, quell'elemento **non esiste
        // per la tastiera**: e' il caso del menu di navigazione, che senza
        // fuoco rende l'applicazione intera non percorribile senza mouse.
        let clickable = occurrences("TouchArea {");
        let focusable = occurrences("FocusScope {");

        assert!(
            focusable >= clickable,
            "ci sono {clickable} aree cliccabili e solo {focusable} raggiungibili \
             con la tastiera: un elemento cliccabile senza fuoco non esiste per \
             chi non usa il mouse"
        );
    }

    #[test]
    fn every_focusable_element_shows_where_the_focus_is() {
        // Un fuoco invisibile e' peggio di nessun fuoco: chi si muove con il
        // Tab preme Invio senza sapere su che cosa.
        //
        // Il token si chiamava `focus-ring` fino alla Milestone 15, quando i
        // nomi sono diventati semantici: un token chiamato con il proprio
        // colore mente alla prima modifica di palette (MP-15B).
        let rings = super::UI_SOURCES
            .iter()
            .map(|unit| unit.matches("Palette.focus").count())
            .sum::<usize>();
        assert!(
            rings >= occurrences("FocusScope {"),
            "solo {rings} elementi disegnano l'anello di fuoco, \
             mentre {} possono riceverlo",
            occurrences("FocusScope {")
        );
    }

    #[test]
    fn every_text_input_has_a_name_that_does_not_disappear() {
        // Il testo segnaposto sparisce appena si scrive: da solo non e'
        // un'etichetta. Un campo senza nome viene letto come «casella di
        // testo», e chi non vede il modulo non sa che cosa vi si scrive.
        //
        // Il controllo cercava `LineEdit {`, che era il campo di libreria.
        // Dalla Milestone 15 i campi sono `HudInput`, e un controllo lasciato
        // sul nome vecchio sarebbe rimasto **verde senza verificare niente**:
        // e' il modo piu' comune in cui una verifica smette di essere una
        // verifica.
        let fields = occurrences("HudInput {");
        assert!(
            fields > 0,
            "nessun campo di testo trovato: il controllo cerca un nome che \
             l'interfaccia non usa piu'"
        );

        for block in windows_around("HudInput {", 0, 14) {
            assert!(
                block.contains("label:"),
                "un campo di testo e' senza etichetta:\n{block}"
            );
        }
    }

    #[test]
    fn a_row_to_choose_shows_a_box_not_a_dot() {
        // Le fonti e i dizionari del nuovo monitoraggio, da non scelti,
        // mostravano un punto: a schermo non diceva che la riga si sceglie.
        // Ora hanno la casella delle righe del Report (FINAL-PRODUCT-REVIEW-02).
        let dot = r#"selected ? "\u{2713}" : "\u{00b7}""#;
        for unit in super::UI_SOURCES {
            assert!(
                !unit.contains(dot),
                "una riga da scegliere usa di nuovo un punto invece della casella"
            );
        }
    }

    #[test]
    fn every_field_without_a_placeholder_shows_its_name_on_screen() {
        // L'etichetta di `HudInput` la sente soltanto chi usa un lettore di
        // schermo: a schermo parla il segnaposto. Un campo senza segnaposto,
        // o che parte con un valore, a schermo non ha nome se il nome non è
        // scritto sopra. Le catture hanno mostrato il motivo della pausa e i
        // campi di TAXII (QUALITY-02, INTEGRATION-01); cercando nel sorgente
        // ne sono usciti altri sei. Nessuna prova li vedeva.
        let mut nameless = Vec::new();
        for unit in super::UI_SOURCES {
            let source: Vec<&str> = unit.lines().collect();
            for (index, line) in source.iter().enumerate() {
                if !line.contains("HudInput {") {
                    continue;
                }
                // Il campo finisce dove si chiude la sua graffa: una finestra
                // fissa arriverebbe al segnaposto del campo successivo.
                let (mut opened, mut closed) = (0_usize, 0_usize);
                let mut block = Vec::new();
                for inner in &source[index..] {
                    block.push(*inner);
                    opened += inner.matches('{').count();
                    closed += inner.matches('}').count();
                    if closed >= opened {
                        break;
                    }
                }
                if block.iter().any(|inner| inner.contains("placeholder:")) {
                    continue;
                }
                let Some(label) = block
                    .iter()
                    .find_map(|inner| inner.trim().strip_prefix("label:"))
                    .map(|label| label.trim().trim_end_matches(';'))
                else {
                    continue;
                };
                let shown = format!("text: {label};");
                let before = &source[index.saturating_sub(10)..index];
                if !before.iter().any(|inner| inner.contains(&shown)) {
                    nameless.push(label.to_owned());
                }
            }
        }
        assert!(
            nameless.is_empty(),
            "questi campi non hanno segnaposto né il nome scritto sopra: {nameless:?}"
        );
    }

    #[test]
    fn nothing_that_declares_a_role_forgets_its_name() {
        // Un ruolo senza nome dice a una tecnologia assistiva che c'e' un
        // pulsante, e non quale.
        // La finestra e' generosa perche' fra il ruolo e il nome puo' esserci
        // il commento che spiega **perche'** quel nome dice quelle cose.
        //
        // `accessible-role: none` e' l'eccezione, e non e' una scappatoia:
        // dichiara che quell'elemento **non va esposto affatto**. E' cio' che
        // si scrive sulle parti interne di un componente - il testo segnaposto
        // di un campo, la spunta dentro una casella - perche' sia il componente
        // a presentarsi una volta sola invece di annunciarsi a pezzi. Chiedere
        // un nome a un elemento che ha dichiarato di non avere voce sarebbe
        // chiedere il contrario di cio' che il controllo protegge.
        for block in windows_around("accessible-role:", 3, 9) {
            if block.contains("accessible-role: none") {
                continue;
            }
            assert!(
                block.contains("accessible-label"),
                "un elemento dichiara un ruolo ma non un nome:\n{block}"
            );
        }
    }

    #[test]
    fn the_navigation_stays_free_of_icons() {
        // Il sistema grafico approvato prescrive una navigazione di **solo
        // testo**, e i sedici segni disegnati in MP-16 sono usciti con essa
        // (ADR-0026, DEC-135).
        //
        // Questo controllo ha preso il posto dei tre che proteggevano le icone:
        // ogni voce ha il suo segno, ogni segno ha il suo tracciato, nessun
        // segno parla al posto dell'etichetta. Quelle invarianti sono cadute
        // con le icone, ma **la protezione non va persa insieme a loro**: se un
        // giorno un'icona rientra, deve rientrare da una decisione e non di
        // passaggio, e questo test è ciò che lo impone.
        //
        // Rimetterle è legittimo. Cancellare questo test senza scrivere perché,
        // no.
        let entries = occurrences("NavigationItem {");
        assert!(
            entries > 0,
            "nessuna voce di menu trovata: il controllo cerca un nome che \
             l'interfaccia non usa piu'"
        );

        for forbidden in ["export enum Glyph", "export component Icon", "glyph:"] {
            let found = super::UI_SOURCES
                .iter()
                .any(|unit| unit.contains(forbidden));
            assert!(
                !found,
                "«{forbidden}» è tornato nell'interfaccia: la navigazione \
                 approvata è di solo testo, e un segno che rientra va motivato \
                 in un ADR prima che in un file .slint"
            );
        }
    }

    #[test]
    fn a_level_colour_never_paints_text() {
        // Il rosso del livello 4 (`#E63950`) vale **4,43** contro il pannello.
        // La soglia del testo è 4,5, quella del non testuale è 3:1. Nel bordo
        // di una targhetta e nel binario di livello la regge; su una parola no.
        //
        // Da qui la regola: **la rampa colora aree, mai testo** (DEC-137). È
        // ciò che permette a `verify-contrast.ps1` di misurare `level-4` come
        // `ui` invece che come `text` — e senza questo controllo quella
        // riclassificazione sarebbe un'affermazione senza nulla che la tenga.
        //
        // Il controllo guarda le righe che assegnano `color:`, che in questa
        // interfaccia è sempre il colore di un testo. `border-color:` e
        // `background:` non lo riguardano: quelli sono aree, ed è lì che la
        // rampa deve stare.
        for unit in super::UI_SOURCES {
            for line in unit.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("color:") && trimmed.contains("Palette.level") {
                    panic!(
                        "un colore della rampa dipinge del testo:\n{trimmed}\n\
                         La rampa colora aree - binario di livello e bordo \
                         della targhetta - e mai una parola: il livello 4 sta \
                         sotto la soglia di contrasto del testo (DEC-137)."
                    );
                }
            }
        }
    }

    #[test]
    fn a_masked_field_never_hands_its_value_to_a_screen_reader() {
        // `accessible-value` e' cio' che una tecnologia assistiva legge ad alta
        // voce. Un campo mascherato che lo esponesse proteggerebbe dallo
        // sguardo di chi passa e non dall'orecchio di chi e' nella stanza — e
        // la maschera darebbe l'impressione di una protezione che non c'e'.
        //
        // Il controllo cerca la forma esatta perche' e' una riga sola in tutta
        // l'interfaccia: se qualcuno la semplifica in `accessible-value:
        // root.value`, questo test cade e la modifica va motivata invece che
        // fatta di passaggio.
        let guarded = super::UI_SOURCES
            .iter()
            .any(|unit| unit.contains(r#"accessible-value: root.masked ? "" : root.value;"#));

        assert!(
            guarded,
            "il campo di testo non protegge piu' il proprio contenuto \
             mascherato da cio' che viene letto ad alta voce"
        );
    }

    #[test]
    fn the_password_fields_name_the_field_and_never_the_value() {
        // L'etichetta e' il nome che viene letto ad alta voce: se contenesse il
        // valore, un segreto verrebbe pronunciato.
        for block in windows_around("input-type:", 2, 6) {
            assert!(
                !block.contains("accessible-label: root."),
                "l'etichetta di un campo mascherato non deve venire dal valore:\n{block}"
            );
        }
    }
}

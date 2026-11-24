//! Verifica che l'attribuzione stia dove deve, e solo lì.
//!
//! Sono due decisioni di prodotto sovrapposte: il credito personale compare
//! nella sola schermata «Informazioni e licenze» e non nelle schermate
//! operative (DEC-089), e da DEC-120 è **una riga sola**, non due. Una
//! decisione del genere, affidata alla sola verifica a vista, dura fino al
//! primo refactor: qualcuno riaggiunge un piè di pagina «per completezza» e
//! nessuna suite se ne accorge. Questo controllo lo impedisce.
//!
//! Non sostituisce la verifica a vista, che vede cose che una `grep` non vede.
//! Fissa però l'invariante che la verifica a vista ha appena confermato, così
//! che non regredisca in silenzio — come già fa un test per la formula
//! prescritta in `lisi-core`.

/// Interfaccia principale, letta a tempo di compilazione.
#[cfg(test)]
const UI: &str = include_str!("../ui/app-window.slint");

/// Marcatore d'inizio della schermata «Informazioni e licenze» (pagina 1).
///
/// È l'ultimo blocco di pagina del file: tutto ciò che lo precede è una
/// schermata operativa, tutto ciò che lo segue è la pagina delle informazioni.
#[cfg(test)]
const INFO_PAGE_MARKER: &str = "current-page == 1: Rectangle";

#[cfg(test)]
mod tests {
    use super::{INFO_PAGE_MARKER, UI};

    /// Numero di occorrenze non sovrapposte di `needle` in `haystack`.
    fn count(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    /// Divide il file in «prima della pagina informazioni» e «dalla pagina in
    /// poi». Il punto di taglio è il marcatore della pagina 1.
    fn split_at_info_page() -> (&'static str, &'static str) {
        let Some(index) = UI.find(INFO_PAGE_MARKER) else {
            panic!(
                "marcatore della pagina informazioni non trovato: se la pagina e' stata \
                 rinominata o riordinata, aggiornare INFO_PAGE_MARKER"
            );
        };
        UI.split_at(index)
    }

    #[test]
    fn no_operational_screen_shows_a_personal_credit() {
        // Le schermate operative sono tutte prima della pagina informazioni.
        // Un pie' di pagina globale con `root.attribution` ricomparirebbe qui.
        let (operational, _) = split_at_info_page();

        assert_eq!(
            count(operational, "text: root.attribution"),
            0,
            "un credito personale e' comparso in una schermata operativa: \
             le attribuzioni vivono nella sola pagina «Informazioni e licenze» (DEC-089)"
        );
    }

    #[test]
    fn the_info_page_shows_the_attribution_once() {
        let (_, info) = split_at_info_page();

        assert_eq!(
            count(info, "text: root.attribution;"),
            1,
            "l'attribuzione deve comparire una volta nella pagina informazioni"
        );
    }

    #[test]
    fn the_attribution_is_a_single_line_in_the_whole_interface() {
        // La pagina ne mostrava due, perche' le formule erano quattro
        // (DEC-120). Il modo di tornare indietro e' aggiungere una proprieta'
        // accanto a quella esistente: compilerebbe, e nessuna suite se ne
        // accorgerebbe. Il conteggio e' sull'intero file, non sulla sola
        // pagina informazioni, perche' la seconda riga potrebbe ricomparire
        // altrove.
        assert_eq!(
            count(UI, "text: root.attribution"),
            1,
            "l'attribuzione del prodotto e' una sola riga, in un solo punto (DEC-120)"
        );
    }

    #[test]
    fn the_slint_attribution_obligation_stays_on_the_info_page() {
        // ADR-0005: l'attribuzione Slint e il widget AboutSlint devono restare
        // raggiungibili da questa pagina. Se sparissero, l'obbligo di licenza
        // sarebbe violato mentre tutto il resto compila.
        let (_, info) = split_at_info_page();

        assert!(
            info.contains("AboutSlint"),
            "il widget AboutSlint deve restare nella pagina informazioni (ADR-0005)"
        );
        assert!(
            info.contains("realizzata con Slint"),
            "l'attribuzione testuale di Slint deve restare (ADR-0005)"
        );
        assert!(
            info.contains("third-party-components"),
            "l'elenco dei componenti di terze parti deve restare nella pagina informazioni"
        );
    }
}

#[cfg(test)]
mod formula_tests {
    /// Tutti i file `.rs` sotto il percorso indicato.
    fn sorgenti(percorso: &std::path::Path, trovati: &mut Vec<std::path::PathBuf>) {
        let Ok(voci) = std::fs::read_dir(percorso) else {
            return;
        };
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.is_dir() {
                sorgenti(&percorso, trovati);
            } else if percorso
                .extension()
                .is_some_and(|estensione| estensione == "rs")
            {
                trovati.push(percorso);
            }
        }
    }

    /// **La formula d'attribuzione compare solo nella sua forma, in qualunque
    /// crate** (DEC-120; FINAL-REVIEW-01, FR-029).
    ///
    /// La guardia di `lisi-core` contava le dichiarazioni in `branding.rs`, e
    /// una variante in minuscolo era nata in un altro crate, nel manifesto dei
    /// report. Qui si cerca in tutto il codice di produzione: la formula può
    /// comparire, ma solo identica a quella di `branding.rs`.
    #[test]
    fn the_attribution_formula_is_written_only_in_branding() {
        let Some(crates) = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
            panic!("la cartella dei crate deve esistere");
        };
        let mut file = Vec::new();
        sorgenti(crates, &mut file);
        assert!(
            file.len() > 50,
            "la guardia non sta percorrendo il prodotto"
        );

        let mut varianti = Vec::new();
        for percorso in file {
            if percorso.ends_with("branding.rs")
                || percorso
                    .components()
                    .any(|parte| parte.as_os_str() == "tests")
            {
                continue;
            }
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                continue;
            };
            let produzione = testo
                .split_once("\n#[cfg(test)]")
                .map_or(testo.as_str(), |(prima, _)| prima);
            for riga in produzione.lines() {
                let pulita = riga.trim_start();
                if pulita.starts_with("//") {
                    continue;
                }
                if pulita.to_lowercase().contains("ideazione e progettazione")
                    && !pulita.contains(lisi_core::branding::ATTRIBUTION)
                {
                    varianti.push(format!("{}: {pulita}", percorso.display()));
                }
            }
        }
        assert!(
            varianti.is_empty(),
            "una variante della formula d'attribuzione: {varianti:#?}"
        );
    }
}

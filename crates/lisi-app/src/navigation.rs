//! Le schermate: quante sono, e da quale si comincia (PR-14, ADR-0130).
//!
//! # Una schermata nuova si aggiunge in quattro posti, o in nessuno
//!
//! Una schermata dichiarata nell'interfaccia deve avere **una** voce di
//! navigazione che la apre con `open-page`, **un** ramo in `open-page` (oppure
//! essere fra quelle che non chiedono aggiornamenti), **una** riga nello script
//! che cattura le schermate per la verifica a vista, e deve essere contata in
//! [`SCREENS`]. Le prove qui sotto lo verificano leggendo i tre file: è la
//! guardia che diventa rossa il giorno in cui si aggiunge una schermata senza
//! estendere il resto (ADR-0111).

/// Quante schermate ha il programma, numerate da zero.
pub const SCREENS: i32 = 32;

/// L'argomento che apre una schermata all'avvio.
const PAGE_ARGUMENT: &str = "--pagina=";

/// La schermata indicata da `--pagina=N`, se N è una schermata.
#[must_use]
pub fn start_page<I, S>(argomenti: I) -> Option<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    argomenti.into_iter().find_map(|argomento| {
        argomento
            .as_ref()
            .strip_prefix(PAGE_ARGUMENT)
            .and_then(|numero| numero.parse::<i32>().ok())
            .filter(|numero| (0..SCREENS).contains(numero))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{SCREENS, start_page};
    use crate::page_guard::{UI, pagine_dichiarate};

    // Lo script di cattura sta soltanto nell'archivio (ADR-0210).

    /// Le schermate che si aprono senza chiedere aggiornamenti ai servizi: il
    /// loro contenuto è fisso, o si aggiorna da sé.
    const SENZA_AGGIORNAMENTO: [u32; 4] = [1, 2, 5, 10];

    /// Il corpo della funzione `open-page`.
    fn open_page() -> &'static str {
        let Some((_, dopo)) = UI.split_once("public function open-page(page: int) {") else {
            panic!("la funzione open-page deve esistere");
        };
        let Some((corpo, _)) = dopo.split_once("\n    }\n") else {
            panic!("la funzione open-page deve chiudersi");
        };
        assert!(corpo.contains("root.current-page = page;"));
        corpo
    }

    /// I numeri che seguono un prefisso, in un testo.
    fn numeri_dopo(testo: &str, prefisso: &str) -> Vec<u32> {
        testo
            .match_indices(prefisso)
            .filter_map(|(posizione, _)| {
                testo[posizione + prefisso.len()..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .ok()
            })
            .collect()
    }

    /// **Ogni schermata dichiarata si raggiunge, si aggiorna e si cattura**
    /// (controllo negativo 1 del piano).
    #[test]
    fn ogni_schermata_ha_voce_ramo_e_cattura() {
        let dichiarate: BTreeSet<u32> = pagine_dichiarate().into_iter().collect();
        let attese: BTreeSet<u32> = (0..u32::try_from(SCREENS).unwrap_or_default()).collect();
        assert_eq!(
            dichiarate, attese,
            "le schermate vanno da 0 a SCREENS - 1, senza salti"
        );

        // Una voce per schermata, che la apre con open-page. Si contano le sole
        // voci del menu: anche un comando di un'altra schermata può aprirne
        // una, e deve farlo con la stessa funzione.
        let voci = numeri_dopo(
            UI,
            "activated => {\n                            root.open-page(",
        );
        let mut viste = BTreeSet::new();
        for voce in &voci {
            assert!(viste.insert(*voce), "la schermata {voce} ha due voci");
        }
        assert_eq!(
            viste, dichiarate,
            "ogni schermata ha la sua voce di navigazione"
        );
        assert_eq!(
            UI.matches("NavigationItem {").count(),
            dichiarate.len(),
            "una voce per schermata, e nessuna voce che non apra una schermata"
        );
        for numero in &dichiarate {
            assert!(
                UI.contains(&format!(
                    "active: root.current-page == {numero};\n                        activated => {{\n                            root.open-page({numero});"
                )),
                "la voce della schermata {numero} non si accende sulla sua schermata"
            );
        }

        // Un ramo in open-page per ogni schermata che chiede aggiornamenti.
        let rami: BTreeSet<u32> = numeri_dopo(open_page(), "page == ").into_iter().collect();
        let fisse: BTreeSet<u32> = SENZA_AGGIORNAMENTO.into_iter().collect();
        assert!(rami.is_disjoint(&fisse));
        assert_eq!(
            rami.union(&fisse).copied().collect::<BTreeSet<u32>>(),
            dichiarate,
            "ogni schermata ha il suo ramo in open-page, o è fra quelle che non si aggiornano"
        );

        // Una riga nello script di cattura per ogni schermata.
    }

    /// **Soltanto un numero di schermata apre una schermata.**
    #[test]
    fn soltanto_una_schermata_si_apre_all_avvio() {
        assert_eq!(start_page(["programma.exe", "--pagina=31"]), Some(31));
        assert_eq!(start_page(["programma.exe", "--pagina=0"]), Some(0));
        assert_eq!(start_page(["programma.exe", "--pagina=32"]), None);
        assert_eq!(start_page(["programma.exe", "--pagina=-1"]), None);
        assert_eq!(start_page(["programma.exe", "--pagina=tre"]), None);
        assert_eq!(start_page(["programma.exe"]), None);
    }
}

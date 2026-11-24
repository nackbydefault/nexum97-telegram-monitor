//! Verifica che la voce di menu «Guida» e la pagina che apre restino allineate.
//!
//! L'indice di pagina della Guida (10) compare due volte nel file
//! dell'interfaccia: nella voce di menu che vi naviga e nel blocco di pagina che
//! mostra il contenuto. Nulla, nel solo `.slint`, lega i due punti: un rinumero
//! delle pagine che ne aggiornasse uno solo lascerebbe il menu «Guida» a puntare
//! altrove, e il difetto si vedrebbe soltanto a vista.
//!
//! È lo stesso rigore già applicato alla schermata Monitoraggio, dove l'indice è
//! una costante Rust verificata contro il file. La Guida non ha una costante
//! propria — il suo collegamento vive interamente nel `.slint` — quindi il
//! controllo vive qui, accanto agli altri guardiani dell'interfaccia.

/// Interfaccia principale, letta a tempo di compilazione.
#[cfg(test)]
const UI: &str = include_str!("../ui/app-window.slint");

/// Indice della pagina Guida nell'interfaccia.
#[cfg(test)]
const GUIDE_PAGE: i32 = 10;

#[cfg(test)]
mod tests {
    use super::{GUIDE_PAGE, UI};

    #[test]
    fn the_guide_nav_item_and_page_share_one_index() {
        // La voce di menu evidenzia se stessa quando la pagina corrente è la
        // Guida, e naviga a quello stesso indice al clic.
        assert!(
            UI.contains(&format!("active: root.current-page == {GUIDE_PAGE};")),
            "la voce di menu «Guida» non si evidenzia sull'indice {GUIDE_PAGE}: \
             se le pagine sono state rinumerate, aggiornare GUIDE_PAGE e l'interfaccia"
        );
        assert!(
            UI.contains(&format!("root.open-page({GUIDE_PAGE});")),
            "la voce di menu «Guida» non naviga all'indice {GUIDE_PAGE}"
        );

        // E la pagina che quel comando apre esiste davvero con quell'indice.
        assert!(
            UI.contains(&format!("root.current-page == {GUIDE_PAGE}: Rectangle")),
            "la pagina Guida con indice {GUIDE_PAGE} non è nell'interfaccia: \
             il menu porterebbe a una pagina inesistente"
        );
    }
}

//! Il corpo di una pagina dell'interfaccia, **dimostrato**.
//!
//! # Perché questo modulo esiste
//!
//! Venti moduli dell'interfaccia contengono una guardia che legge il corpo di
//! una pagina e verifica che qualcosa vi sia — o che qualcosa non vi sia. Fino a
//! HARDEN-02 ciascuno ritagliava quel corpo **per conto proprio**, con quattro
//! delimitatori diversi: il numero della pagina successiva scritto a mano, una
//! ricerca che dipendeva dall'indentazione, uno `split_once` sul marcatore, un
//! commento che stava più avanti nel file.
//!
//! È la famiglia di guardie che in questo progetto si è già rotta **tre volte**,
//! e sempre allo stesso modo: **l'estrattore smetteva di estrarre ciò che
//! credeva, e nessuno se ne accorgeva.**
//!
//! - SEARCH-01 ha inserito una pagina in mezzo, e l'estrattore delle note ha
//!   cominciato a restituirne **due**: la guardia che vieta un comando di
//!   modifica ha visto la parola «modifica» della pagina delle ricerche.
//! - La guardia del Cyber Watch condiviso cercava una parola vietata in tutta la
//!   pagina e la trovava dentro `Typography.body`.
//! - La guardia della presenza delimitava il corpo di una funzione con «il
//!   commento della funzione successiva», e si è rotta appena una funzione è
//!   stata inserita accanto.
//!
//! Le prime due sono diventate rosse e si sono corrette. **Il caso pericoloso è
//! l'altro**: un estrattore che restituisce **troppo poco** — un corpo vuoto, o
//! la pagina sbagliata — non fa fallire niente. Ogni `assert!(!corpo.contains(…))`
//! che lo usa continua a passare, e il documento delle prove dichiara difesa una
//! cosa che nessuno guarda più.
//!
//! # Che cosa questo modulo garantisce
//!
//! Che chi chiede il corpo di una pagina **lo ottenga o si fermi**. Non esiste
//! un modo di ricevere una stringa vuota, né il file intero, né la pagina
//! accanto: ogni condizione che lo produrrebbe è un `panic!` che nomina la
//! pagina.
//!
//! # Perché la fine è «la pagina successiva, qualunque sia»
//!
//! Perché il numero della pagina successiva **non è una proprietà della pagina
//! che si sta leggendo**: dipende da come il file è ordinato oggi. Scriverlo a
//! mano lega la guardia a un ordine che nessuno si è impegnato a mantenere, e il
//! giorno in cui qualcuno inserisce una pagina l'estrattore ne restituisce due
//! senza dirlo.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0111-UNA-GUARDIA-CHE-NON-GUARDA-NIENTE-PASSA-SEMPRE.md`.

/// L'interfaccia principale: la fonte di ogni corpo di pagina.
#[cfg(test)]
pub const UI: &str = include_str!("../ui/app-window.slint");

/// Quanto deve essere lungo un corpo di pagina perché sia un corpo di pagina.
///
/// # Perché una soglia e non «non vuoto»
///
/// Perché il caso che fa danno non è la stringa vuota — quella si nota — ma il
/// ritaglio che coglie l'apertura e poco altro, perché il delimitatore di fine
/// ha trovato qualcosa troppo presto. Duecento caratteri sono meno di qualunque
/// pagina reale di questa interfaccia e più di qualunque ritaglio degenere.
#[cfg(test)]
const CORPO_MINIMO: usize = 200;

/// Il corpo della pagina indicata, oppure un fallimento che la nomina.
///
/// # Panico
///
/// Fallisce se la pagina non esiste, se il suo corpo è più corto di
/// [`CORPO_MINIMO`], o se il corpo contiene l'apertura di un'altra pagina — che
/// significherebbe che il delimitatore di fine non ha funzionato.
///
/// **Fallire è il comportamento giusto.** Una guardia che riceve un corpo
/// sbagliato e continua dichiara difesa una cosa che non ha guardato.
#[cfg(test)]
pub fn corpo_della_pagina(numero: u32) -> String {
    let frammenti = frammenti_della_pagina(numero);
    assert!(
        !frammenti.is_empty(),
        "la pagina {numero} non esiste nell'interfaccia: se e' stata rinumerata, la \
         guardia che la sorveglia va aggiornata insieme al numero"
    );

    let corpo = frammenti.join("\n");
    assert!(
        corpo.len() >= CORPO_MINIMO,
        "il corpo della pagina {numero} e' lungo {} caratteri: il delimitatore di fine ha \
         trovato qualcosa troppo presto, e ogni guardia che usa questo corpo starebbe \
         guardando quasi niente",
        corpo.len()
    );
    assert_eq!(
        corpo.matches("if root.current-page ==").count(),
        frammenti.len(),
        "il corpo della pagina {numero} apre piu' pagine di quante ne ha: il delimitatore \
         di fine non ha funzionato, e ogni divieto su questa pagina vale anche per quella \
         accanto"
    );

    corpo
}

/// I frammenti con cui l'interfaccia disegna una pagina.
///
/// # Perché una pagina può avere più di un frammento
///
/// Perché una condizione può essere composta: la pagina iniziale si apre due
/// volte, `== 0 && !DocumentProfile.answered` e `== 0 && DocumentProfile.answered`,
/// e sono due metà della **stessa** schermata.
///
/// **Restituirne una sola sarebbe il difetto silenzioso che questo modulo esiste
/// per impedire**: una guardia che vieta qualcosa sulla pagina iniziale ne
/// guarderebbe metà, e passerebbe su ciò che sta nell'altra.
#[cfg(test)]
fn frammenti_della_pagina(numero: u32) -> Vec<&'static str> {
    let apertura = format!("if root.current-page == {numero}");
    let mut frammenti = Vec::new();

    for (inizio, _) in UI.match_indices(&apertura) {
        // IL NUMERO DEVE FINIRE QUI. Senza questo controllo la pagina 2
        // troverebbe anche l'apertura della 20, e restituirebbe un corpo che
        // non e' il suo.
        let dopo_numero = &UI[inizio + apertura.len()..];
        let Some(carattere) = dopo_numero.chars().next() else {
            continue;
        };
        if carattere.is_ascii_digit() {
            continue;
        }

        // LA FINE E' LA PAGINA SUCCESSIVA, QUALUNQUE SIA E COMUNQUE SIA
        // INDENTATA.
        //
        // Il numero della pagina successiva non e' una proprieta' di questa
        // pagina: dipende da come il file e' ordinato oggi. Scriverlo a mano
        // lega la guardia a un ordine che nessuno si e' impegnato a mantenere,
        // ed e' cosi' che l'estrattore delle note ha cominciato a restituire
        // due pagine quando SEARCH-01 ne ha inserita una in mezzo.
        let fine = dopo_numero
            .find("if root.current-page ==")
            .map_or(UI.len(), |lunghezza| inizio + apertura.len() + lunghezza);
        frammenti.push(&UI[inizio..fine]);
    }

    frammenti
}

/// I numeri delle pagine che l'interfaccia dichiara.
///
/// Serve alla prova che le percorre tutte: un elenco scritto a mano scadrebbe
/// alla pagina successiva.
#[cfg(test)]
pub fn pagine_dichiarate() -> Vec<u32> {
    let mut numeri = Vec::new();
    for (posizione, _) in UI.match_indices("if root.current-page == ") {
        let coda = &UI[posizione + "if root.current-page == ".len()..];
        let cifre: String = coda.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(numero) = cifre.parse::<u32>() {
            numeri.push(numero);
        }
    }
    numeri.sort_unstable();
    numeri.dedup();
    numeri
}

#[cfg(test)]
mod tests {
    use super::{UI, corpo_della_pagina, pagine_dichiarate};

    /// La misura minima **verificata a vista**, in pixel logici
    /// (FINAL-FPR-ALL-16, FPR-16).
    ///
    /// Non è una preferenza: è la misura a cui il prodotto è stato guardato,
    /// in Esercitazione, sulle schermate più dense — la composizione di un
    /// monitoraggio, la produzione di una relazione, il Monitoraggio,
    /// Impostazioni. A 900×600, che il prodotto consentiva fino al
    /// 2026-10-11, il wizard tagliava «Indietro» e «Avanti», e a 900×660 il
    /// Monitoraggio tagliava il distintivo dello stato.
    const MISURA_MINIMA_VERIFICATA: (u32, u32) = (1000, 660);

    /// **La finestra non consente una misura in cui il prodotto non è stato
    /// guardato** (FPR-16).
    ///
    /// # Perché legge i numeri invece di cercare una stringa
    ///
    /// Perché la cosa da garantire è un **rapporto fra due fatti** — ciò che
    /// la finestra consente e ciò che qualcuno ha guardato — e non la
    /// presenza di una riga. Cercare `min-width: 1000px` passerebbe anche se
    /// il numero fosse scritto in un commento, e non direbbe niente il giorno
    /// in cui la misura verificata cambia (DEC-388).
    #[test]
    fn la_finestra_non_consente_una_misura_in_cui_non_e_stata_guardata() {
        let (larghezza, altezza) = MISURA_MINIMA_VERIFICATA;

        // Le quattro proprietà si leggono **dentro la dichiarazione della
        // finestra**: `min-width` compare anche in una decina di componenti, e
        // la prima occorrenza del file è quella di un pulsante.
        let Some((_, finestra)) = UI.split_once("    title: (root.exercise-mode") else {
            panic!("la finestra non dichiara il proprio titolo: la guardia non sa dove guardare");
        };
        let Some((finestra, _)) = finestra.split_once("    VerticalLayout {") else {
            panic!("la dichiarazione della finestra non si chiude dove la guardia l'aspetta");
        };

        let dichiarato = |proprieta: &str| -> u32 {
            let Some((_, dopo)) = finestra.split_once(&format!("{proprieta}: ")) else {
                panic!("la finestra non dichiara «{proprieta}»");
            };
            let cifre: String = dopo.chars().take_while(char::is_ascii_digit).collect();
            let Ok(valore) = cifre.parse::<u32>() else {
                panic!("«{proprieta}» non dichiara un numero: «{cifre}»");
            };
            valore
        };

        assert_eq!(
            dichiarato("min-width"),
            larghezza,
            "la finestra consente una larghezza diversa da quella verificata: \
             o si rimisura e si aggiorna questa costante, o si riporta il minimo \
             a ciò che è stato guardato"
        );
        assert_eq!(
            dichiarato("min-height"),
            altezza,
            "la finestra consente un'altezza diversa da quella verificata"
        );

        // La misura predefinita non può essere più piccola della minima: una
        // finestra che si apre più piccola di quanto si possa restringere è
        // una contraddizione che il sistema risolve a caso.
        assert!(
            dichiarato("preferred-width") >= larghezza && dichiarato("preferred-height") >= altezza,
            "la misura predefinita è più piccola della minima"
        );
    }

    /// **Gli avvisi sopra il corpo hanno un'altezza massima, e il corpo una
    /// minima** (FINAL-REVIEW-01, FR-030).
    ///
    /// Si sommavano senza limite: alla misura predefinita il menu si riduceva
    /// a due voci, alla minima usciva dalla finestra con «Scopri NEXUM». La
    /// verifica a vista ha confermato la correzione a 900×600, 1120×720 e
    /// 1600×1000; questa guardia ne fissa la forma.
    ///
    /// Dal 2026-10-12 la misura minima consentita è **1000×660** e non più
    /// 900×600 (FINAL-FPR-ALL-16, FPR-16): a 900×600 il wizard tagliava i
    /// propri comandi. Il minimo garantito del corpo, che questa guardia
    /// verifica, resta la ragione per cui il menu non esce dalla finestra.
    #[test]
    fn the_notices_are_bounded_and_the_body_keeps_its_room() {
        assert!(UI.contains("pila-avvisi := VerticalLayout {"));
        assert!(UI.contains("max-height: pila-avvisi.preferred-height;"));
        let Some((_, corpo)) = UI.split_once("corpo-finestra := HorizontalLayout {") else {
            panic!("il corpo della finestra deve esistere");
        };
        let Some((testa, _)) = corpo.split_once("Rectangle {") else {
            panic!("il corpo deve avere la colonna del menu");
        };
        assert!(
            testa.contains("min-height: 230px;"),
            "il corpo deve avere un minimo garantito"
        );
        let Some((prima, _)) = UI.split_once("pila-avvisi := VerticalLayout {") else {
            panic!("la pila degli avvisi deve esistere");
        };
        assert!(
            prima.contains("fascia-esercitazione := VerticalLayout {"),
            "la fascia dell'Esercitazione resta fuori dalla zona che scorre (SIC-17)"
        );
    }

    /// **La schermata Persone ha un solo scorrimento, e l'elenco dei soggetti
    /// è dentro** (FINAL-REVIEW-01, FR-031).
    #[test]
    fn the_people_screen_scrolls_as_a_whole() {
        let pagina = corpo_della_pagina(14);
        let Some((_, dopo_lo_scorrimento)) = pagina.split_once("HudScroll {") else {
            panic!("la schermata Persone deve scorrere");
        };
        assert_eq!(
            pagina.matches("HudScroll {").count(),
            1,
            "uno scorrimento solo: gli scorrimenti annidati non si usano"
        );
        assert!(
            dopo_lo_scorrimento.contains("for soggetto in root.person-rows"),
            "l'elenco dei soggetti deve stare dentro lo scorrimento"
        );
    }

    /// **Nessun modulo ritaglia una pagina per conto proprio.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la famiglia si riformi. Prima di HARDEN-02 c'erano **tredici**
    /// estrattori, con quattro delimitatori diversi: il numero della pagina
    /// successiva scritto a mano, una ricerca che dipendeva dall'indentazione,
    /// uno `split_once` sul marcatore, un `get(30..)` con un numero magico. Uno
    /// di essi — quello del Cyber Watch — restituiva **dal proprio marcatore
    /// alla fine del file**: le sue guardie cercavano parole vietate in altre
    /// tredici pagine.
    ///
    /// Convertirli tutti non impedisce che il quattordicesimo nasca domani. Un
    /// elenco di moduli convertiti sarebbe una promessa; questa e' una
    /// condizione.
    ///
    /// # Che cosa resta permesso
    ///
    /// **Chiedere all'interfaccia se una pagina esiste.** `UI.contains(…)` non
    /// ritaglia niente e non puo' guardare la pagina sbagliata: cerca in tutto
    /// il file, e lo sa.
    #[test]
    fn nessun_modulo_ritaglia_una_pagina_per_conto_proprio() {
        let Some(crate_dir) = option_env!("CARGO_MANIFEST_DIR") else {
            panic!("la guardia legge i sorgenti: serve la cartella della crate");
        };
        let sorgenti = std::path::Path::new(crate_dir).join("src");
        let Ok(voci) = std::fs::read_dir(&sorgenti) else {
            panic!("i sorgenti dell'interfaccia non si leggono: la guardia non ha guardato nulla");
        };

        let mut moduli_letti = 0;
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Some(nome) = percorso.file_name().and_then(|nome| nome.to_str()) else {
                continue;
            };
            // QUESTO MODULO E' L'ECCEZIONE, ed e' l'unica: qui il ritaglio si fa
            // e si dimostra.
            if nome == "page_guard.rs" {
                continue;
            }

            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                panic!("il modulo «{nome}» non si legge");
            };
            moduli_letti += 1;

            for forma in [
                ".find(\"if root.current-page",
                ".split_once(\"current-page ==",
                ".split_once(&format!(\"current-page ==",
                ".find(&format!(\"if root.current-page",
            ] {
                assert!(
                    !testo.contains(forma),
                    "«{nome}» ritaglia una pagina per conto proprio con «{forma}»: un \
                     ritaglio che coglie troppo poco non fa fallire niente, e ogni divieto \
                     su quella pagina resta vero perche' non c'e' piu' niente da vietare. \
                     Si usa `crate::page_guard::corpo_della_pagina`, che dimostra di aver \
                     letto qualcosa (ADR-0111)"
                );
            }
        }

        assert!(
            moduli_letti > 30,
            "solo {moduli_letti} moduli letti: se la cartella dei sorgenti e' stata \
             spostata, questa guardia va aggiornata insieme al percorso"
        );
    }

    /// **L'interfaccia dichiara delle pagine, e l'estrattore le trova tutte.**
    ///
    /// # Perché questa prova vale più di tutte le altre di questo modulo
    ///
    /// Perché è l'unica che fallirebbe il giorno in cui una pagina venisse
    /// aggiunta con una forma diversa. Un elenco scritto a mano di pagine da
    /// verificare scadrebbe in silenzio; questo le legge dal file.
    #[test]
    fn ogni_pagina_dichiarata_ha_un_corpo() {
        let pagine = pagine_dichiarate();
        assert!(
            pagine.len() > 20,
            "solo {} pagine trovate: se la forma con cui l'interfaccia le apre e' cambiata, \
             questo modulo va aggiornato insieme",
            pagine.len()
        );

        for numero in pagine {
            let corpo = corpo_della_pagina(numero);
            assert!(
                corpo.starts_with(&format!("if root.current-page == {numero}")),
                "il corpo della pagina {numero} non comincia dalla sua apertura"
            );
        }
    }

    /// **Una pagina che non esiste ferma la guardia.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un estrattore che restituisse una stringa vuota per una pagina
    /// rinumerata renderebbe **vere** tutte le guardie che vietano qualcosa su
    /// quella pagina: non c'è niente, quindi non c'è niente di vietato. La
    /// schermata potrebbe offrire esattamente ciò che la guardia esisteva per
    /// impedire.
    #[test]
    #[should_panic(expected = "non esiste nell'interfaccia")]
    fn una_pagina_che_non_esiste_ferma_la_guardia() {
        let _ = corpo_della_pagina(9_999);
    }

    /// **Due pagine diverse hanno corpi diversi.**
    ///
    /// Un estrattore che restituisse il file intero passerebbe ogni prova di
    /// presenza e fallirebbe ogni prova di assenza: le une per caso, le altre
    /// per una parola che sta in un'altra schermata.
    #[test]
    fn due_pagine_diverse_hanno_corpi_diversi() {
        let pagine = pagine_dichiarate();
        let (Some(&prima), Some(&ultima)) = (pagine.first(), pagine.last()) else {
            panic!("l'interfaccia deve dichiarare almeno due pagine");
        };
        assert_ne!(prima, ultima);

        let corpo_prima = corpo_della_pagina(prima);
        let corpo_ultima = corpo_della_pagina(ultima);
        assert_ne!(
            corpo_prima, corpo_ultima,
            "due pagine diverse hanno lo stesso corpo: l'estrattore non sta ritagliando"
        );
        assert!(
            corpo_prima.len() < UI.len(),
            "il corpo di una pagina e' lungo quanto tutta l'interfaccia: l'estrattore non \
             sta ritagliando"
        );
    }

    /// **Nessun corpo contiene l'apertura di un'altra pagina.**
    ///
    /// È il difetto che SEARCH-01 ha prodotto davvero: una pagina inserita in
    /// mezzo, e l'estrattore delle note che ne restituiva due.
    #[test]
    fn nessun_corpo_contiene_l_apertura_di_un_altra_pagina() {
        for numero in pagine_dichiarate() {
            let corpo = corpo_della_pagina(numero);
            let aperture = corpo.matches("if root.current-page ==").count();
            let sue = corpo
                .matches(&format!("if root.current-page == {numero}"))
                .count();
            assert_eq!(
                aperture, sue,
                "il corpo della pagina {numero} apre {aperture} pagine di cui {sue} sue: \
                 l'estrattore ne restituisce anche un'altra, e ogni divieto vale anche \
                 per quella accanto"
            );
        }
    }
}

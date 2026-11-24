//! La figura del grafo per i documenti (GRAPH-03, ADR-0056).
//!
//! # Una figura sola, non una per formato
//!
//! DOCX e PDF saprebbero disegnare ciascuno per sé — il PDF ha operatori di
//! linea nativi, il DOCX ha le forme di DrawingML — e **due disegnatori
//! sarebbero due figure**. Divergerebbero alla prima modifica, e chi consegna un
//! rapporto non potrebbe più dire quale delle due ha guardato.
//!
//! Si produce **un'immagine sola**, e i due formati la incorporano.
//!
//! # Le parole stanno fuori dalla figura, ed è la decisione che conta
//!
//! **Un testo dentro un'immagine è un testo che non esiste.** Non si cerca, non
//! si copia, non si legge ad alta voce da una tecnologia assistiva, non entra in
//! un indice. In un atto che qualcuno rileggerà fra due anni, una frase
//! disegnata dentro un rettangolo è una frase perduta.
//!
//! La figura porta la **forma**; la legenda porta le **parole**. Ogni nodo è un
//! riquadro con un numero, e la legenda dice per quel numero che cosa è, per
//! quale fatto è collegato al centro, e da dove viene quel fatto.
//!
//! I numeri sono l'unico testo dentro l'immagine, e si disegnano con una matrice
//! di tre per cinque punti: nessun motore tipografico, nessun carattere da
//! ridistribuire.
//!
//! # Le due guardie di GRAPH-01 valgono anche qui
//!
//! Nella figura **ogni segmento parte dal centro**. Una linea fra due vicini non
//! corrisponde ad alcun arco, e in un documento farebbe più danno che altrove: un
//! documento si stacca dal programma, gira, e non ha accanto nessuno a cui
//! chiedere.
//!
//! E la legenda porta **l'avvertenza del vicinato** — quella che dice che due
//! nodi collegati attraverso un terzo non hanno per questo a che fare l'uno con
//! l'altro — come testo, non come immagine.
//!
//! # La figura è deterministica, e si prova
//!
//! Due rese degli stessi archi danno **gli stessi byte**. Un rapporto porta un
//! manifesto SHA-256, e una figura che cambiasse a ogni generazione renderebbe
//! quel manifesto la firma di nulla.

use lisi_core::model::evidence_graph::Neighbourhood;
use lisi_core::model::graph_layout::{NodePlacement, layout_of};

use crate::error::{ServiceError, ServiceResult};

/// Larghezza della figura, in punti dell'immagine.
///
/// # Perché una misura fissa
///
/// Perché la figura finisce in una pagina, e una pagina ha una larghezza sola.
/// Una misura che dipendesse dal numero di nodi darebbe figure di dimensioni
/// diverse nello stesso rapporto, e due figure di dimensioni diverse si leggono
/// come due cose di importanza diversa.
pub const FIGURE_WIDTH: u32 = 1_000;

/// Altezza della figura, in punti dell'immagine.
pub const FIGURE_HEIGHT: u32 = 1_000;

/// Metà larghezza del riquadro di un nodo.
const BOX_HALF_WIDTH: i64 = 46;

/// Metà altezza del riquadro di un nodo.
const BOX_HALF_HEIGHT: i64 = 26;

/// Il fondo della figura: bianco.
///
/// # Perché non il fondo scuro dell'interfaccia
///
/// Perché la figura va in un documento che qualcuno stampa, e un fondo scuro
/// stampato consuma l'inchiostro di mezza pagina per mostrare sei rettangoli.
const BACKGROUND: [u8; 3] = [0xFF, 0xFF, 0xFF];

/// Il tratto delle linee e dei bordi: quasi nero.
const INK: [u8; 3] = [0x1A, 0x1A, 0x1A];

/// Il riempimento del nodo centrale.
const CENTRE_FILL: [u8; 3] = [0xE0, 0xE8, 0xF4];

/// Il riempimento di un vicino osservato.
const OBSERVED_FILL: [u8; 3] = [0xF2, 0xF2, 0xF2];

/// Il riempimento di un vicino collegato per **decisione di una persona**.
///
/// # Perché un riempimento diverso e non un colore diverso del tratto
///
/// Perché un documento si fotocopia, e una fotocopia in bianco e nero perde le
/// tinte ma conserva i toni. La differenza fra un fatto osservato e l'atto di
/// una persona deve sopravvivere alla fotocopiatrice: la legenda la dice a
/// parole, e il tono la mostra.
const DECIDED_FILL: [u8; 3] = [0xC8, 0xC8, 0xC8];

/// Le cifre, tre punti per cinque.
///
/// # Perché una matrice a mano e non un carattere tipografico
///
/// Perché disegnare del testo richiederebbe un motore e un carattere da
/// ridistribuire, con la sua licenza. Qui servono **dieci glifi**, e dieci glifi
/// stanno in cinquanta byte.
const DIGITS: [[u8; 5]; 10] = [
    [0b111, 0b101, 0b101, 0b101, 0b111], // 0
    [0b010, 0b110, 0b010, 0b010, 0b111], // 1
    [0b111, 0b001, 0b111, 0b100, 0b111], // 2
    [0b111, 0b001, 0b111, 0b001, 0b111], // 3
    [0b101, 0b101, 0b111, 0b001, 0b001], // 4
    [0b111, 0b100, 0b111, 0b001, 0b111], // 5
    [0b111, 0b100, 0b111, 0b101, 0b111], // 6
    [0b111, 0b001, 0b001, 0b001, 0b001], // 7
    [0b111, 0b101, 0b111, 0b101, 0b111], // 8
    [0b111, 0b101, 0b111, 0b001, 0b111], // 9
];

/// Quanto è ingrandito un punto della matrice delle cifre.
const DIGIT_SCALE: i64 = 4;

/// Una riga della legenda: che cosa è quel numero.
///
/// # Perché la legenda è testo e non parte dell'immagine
///
/// Vedere la nota di modulo: un testo dentro un'immagine è un testo che non
/// esiste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegendRow {
    /// Il numero che compare nel riquadro.
    pub number: usize,
    /// Che genere di cosa è.
    pub kind: String,
    /// Come si chiama.
    pub label: String,
    /// **Perché è collegato al centro**, con la provenienza del fatto.
    pub why: String,
    /// Se l'arco che lo collega è l'atto di una persona.
    pub decided_by_a_person: bool,
}

/// La figura, con la sua legenda e la sua avvertenza.
///
/// # Perché l'avvertenza viaggia con la figura
///
/// Perché un documento si stacca dal programma e gira. La frase che dice che due
/// nodi collegati attraverso un terzo non hanno per questo a che fare l'uno con
/// l'altro deve stare **accanto all'immagine**, non nella schermata da cui
/// l'immagine è uscita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFigure {
    /// L'immagine, in PNG.
    png: Vec<u8>,
    /// Il numero zero: il nodo al centro.
    centre: LegendRow,
    /// I vicini, nell'ordine dei loro numeri.
    legend: Vec<LegendRow>,
    /// Che cosa questa figura non dice.
    caveat: String,
}

impl GraphFigure {
    /// L'immagine, in PNG.
    #[must_use]
    pub fn png(&self) -> &[u8] {
        &self.png
    }

    /// Il nodo al centro, che porta il numero zero.
    #[must_use]
    pub const fn centre(&self) -> &LegendRow {
        &self.centre
    }

    /// Le righe della legenda.
    #[must_use]
    pub fn legend(&self) -> &[LegendRow] {
        &self.legend
    }

    /// Che cosa questa figura non dice.
    #[must_use]
    pub fn caveat(&self) -> &str {
        &self.caveat
    }
}

/// Rende la figura di un vicinato.
///
/// # Errori
///
/// Restituisce un errore se la scrittura del PNG non riesce. Non è un caso che
/// ci si aspetti: la scrittura avviene in memoria, e un errore qui significa che
/// qualcosa di più grande non va.
pub fn render(neighbourhood: &Neighbourhood) -> ServiceResult<GraphFigure> {
    let figura = layout_of(neighbourhood);
    let mut tela = Canvas::new();

    // LE LINEE PER PRIME, cosi' i riquadri le coprono agli estremi.
    //
    // OGNI SEGMENTO PARTE DAL CENTRO. Una linea fra due vicini non corrisponde
    // ad alcun arco, e in un documento farebbe piu' danno che altrove.
    let (centro_x, centro_y) = punto(&figura.centre);
    for posto in &figura.neighbours {
        let (x, y) = punto(posto);
        tela.line(centro_x, centro_y, x, y, INK);
    }

    // I VICINI, numerati da uno.
    for (indice, posto) in figura.neighbours.iter().enumerate() {
        let (x, y) = punto(posto);
        let deciso = neighbourhood
            .edges()
            .get(indice)
            .is_some_and(|arco| arco.provenance().is_a_human_act());
        let riempimento = if deciso { DECIDED_FILL } else { OBSERVED_FILL };

        tela.box_with_border(x, y, BOX_HALF_WIDTH, BOX_HALF_HEIGHT, riempimento, INK);
        tela.number(x, y, indice + 1, INK);
    }

    // IL CENTRO PER ULTIMO: sta sopra le linee, come sullo schermo.
    tela.box_with_border(
        centro_x,
        centro_y,
        BOX_HALF_WIDTH + 12,
        BOX_HALF_HEIGHT + 6,
        CENTRE_FILL,
        INK,
    );
    tela.number(centro_x, centro_y, 0, INK);

    let png = tela.into_png()?;

    let centre = LegendRow {
        number: 0,
        kind: neighbourhood.node().kind_label().to_owned(),
        label: neighbourhood.node().as_sentence(),
        why: String::from(
            "\u{c8} l'elemento da cui la figura parte. Non \u{e8} collegato a nulla per un \
             fatto: \u{e8} la cosa di cui si stanno guardando i collegamenti.",
        ),
        decided_by_a_person: false,
    };

    let legend = neighbourhood
        .edges()
        .iter()
        .enumerate()
        .zip(figura.neighbours.iter())
        .map(|((indice, arco), posto)| LegendRow {
            number: indice + 1,
            kind: posto.node.kind_label().to_owned(),
            label: posto.node.as_sentence(),
            why: arco.why(),
            decided_by_a_person: arco.provenance().is_a_human_act(),
        })
        .collect();

    Ok(GraphFigure {
        png,
        centre,
        legend,
        caveat: neighbourhood.caveat(),
    })
}

/// Il punto dell'immagine in cui cade una posizione.
///
/// La disposizione parla in frazioni da zero a uno; qui si moltiplica per la
/// misura della figura. È lo stesso calcolo che fa lo schermo con la propria
/// larghezza, ed è la ragione per cui le due figure coincidono.
fn punto(posto: &NodePlacement) -> (i64, i64) {
    (scala(posto.x, FIGURE_WIDTH), scala(posto.y, FIGURE_HEIGHT))
}

/// Una frazione, portata alla misura indicata.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "le frazioni stanno fra zero e uno e la misura e' mille: il prodotto sta in i64"
)]
fn scala(frazione: f32, misura: u32) -> i64 {
    (frazione * misura as f32) as i64
}

/// La tela su cui si disegna: punti, e nient'altro.
///
/// # Perché una tela a mano e non una libreria di disegno
///
/// Perché servono tre primitive — un segmento, un rettangolo, una cifra — e una
/// libreria di disegno porterebbe con sé anti-aliasing, curve e trasformazioni:
/// tutto codice che non si usa, e un anti-aliasing è anche una sorgente di
/// differenze fra due rese.
struct Canvas {
    /// I punti, tre byte ciascuno, per righe.
    pixels: Vec<u8>,
}

impl Canvas {
    /// Una tela vuota, del colore del fondo.
    fn new() -> Self {
        let quanti = (FIGURE_WIDTH as usize) * (FIGURE_HEIGHT as usize);
        let mut pixels = Vec::with_capacity(quanti * 3);
        for _ in 0..quanti {
            pixels.extend_from_slice(&BACKGROUND);
        }
        Self { pixels }
    }

    /// Accende un punto, se cade dentro la tela.
    ///
    /// Un punto fuori dalla tela **si scarta in silenzio**: è il caso ordinario
    /// ai bordi di un riquadro, e non c'è nulla da segnalare.
    fn dot(&mut self, x: i64, y: i64, colore: [u8; 3]) {
        if x < 0 || y < 0 || x >= i64::from(FIGURE_WIDTH) || y >= i64::from(FIGURE_HEIGHT) {
            return;
        }
        let Ok(indice) = usize::try_from((y * i64::from(FIGURE_WIDTH) + x) * 3) else {
            return;
        };
        let Some(punto) = self.pixels.get_mut(indice..indice + 3) else {
            return;
        };
        punto.copy_from_slice(&colore);
    }

    /// Un segmento, punto per punto.
    ///
    /// L'algoritmo è quello di Bresenham, in numeri interi: nessuna divisione,
    /// nessun arrotondamento, e quindi nessuna differenza fra due rese.
    fn line(&mut self, mut x0: i64, mut y0: i64, x1: i64, y1: i64, colore: [u8; 3]) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut errore = dx + dy;

        loop {
            self.dot(x0, y0, colore);
            if x0 == x1 && y0 == y1 {
                return;
            }
            let doppio = 2 * errore;
            if doppio >= dy {
                errore += dy;
                x0 += sx;
            }
            if doppio <= dx {
                errore += dx;
                y0 += sy;
            }
        }
    }

    /// Un rettangolo pieno con il proprio bordo, centrato nel punto indicato.
    fn box_with_border(
        &mut self,
        cx: i64,
        cy: i64,
        mezza_larghezza: i64,
        mezza_altezza: i64,
        riempimento: [u8; 3],
        bordo: [u8; 3],
    ) {
        for y in (cy - mezza_altezza)..=(cy + mezza_altezza) {
            for x in (cx - mezza_larghezza)..=(cx + mezza_larghezza) {
                let sul_bordo = x == cx - mezza_larghezza
                    || x == cx + mezza_larghezza
                    || y == cy - mezza_altezza
                    || y == cy + mezza_altezza;
                self.dot(x, y, if sul_bordo { bordo } else { riempimento });
            }
        }
    }

    /// Un numero, centrato nel punto indicato.
    fn number(&mut self, cx: i64, cy: i64, valore: usize, colore: [u8; 3]) {
        let cifre: Vec<usize> = if valore == 0 {
            vec![0]
        } else {
            let mut resto = valore;
            let mut raccolte = Vec::new();
            while resto > 0 {
                raccolte.push(resto % 10);
                resto /= 10;
            }
            raccolte.reverse();
            raccolte
        };

        // Ogni cifra e' larga tre punti piu' uno di spazio.
        let passo = 4 * DIGIT_SCALE;
        let Ok(quante) = i64::try_from(cifre.len()) else {
            return;
        };
        let larghezza = quante * passo - DIGIT_SCALE;
        let mut x = cx - larghezza / 2;
        let y = cy - (5 * DIGIT_SCALE) / 2;

        for cifra in cifre {
            let Some(matrice) = DIGITS.get(cifra) else {
                continue;
            };
            for (riga, punti) in matrice.iter().enumerate() {
                for colonna in 0..3_i64 {
                    // Il bit piu' alto dei tre e' la colonna di sinistra.
                    if punti & (0b100 >> colonna) == 0 {
                        continue;
                    }
                    let Ok(riga) = i64::try_from(riga) else {
                        continue;
                    };
                    for ingrandito_y in 0..DIGIT_SCALE {
                        for ingrandito_x in 0..DIGIT_SCALE {
                            self.dot(
                                x + colonna * DIGIT_SCALE + ingrandito_x,
                                y + riga * DIGIT_SCALE + ingrandito_y,
                                colore,
                            );
                        }
                    }
                }
            }
            x += passo;
        }
    }

    /// La tela, in PNG.
    ///
    /// # Perché i parametri sono fissati
    ///
    /// Perché due rese devono dare gli stessi byte: un livello di compressione
    /// scelto dalla libreria a seconda della versione produrrebbe file diversi
    /// per la stessa figura, e un manifesto SHA-256 accanto a un file che cambia
    /// è la firma di nulla.
    fn into_png(self) -> ServiceResult<Vec<u8>> {
        let mut fuori = Vec::new();
        {
            let mut codificatore = png::Encoder::new(&mut fuori, FIGURE_WIDTH, FIGURE_HEIGHT);
            codificatore.set_color(png::ColorType::Rgb);
            codificatore.set_depth(png::BitDepth::Eight);
            codificatore.set_compression(png::Compression::Balanced);

            let mut scrittore =
                codificatore
                    .write_header()
                    .map_err(|errore| ServiceError::DocumentGeneration {
                        reason: format!("intestazione dell'immagine PNG non scritta: {errore}"),
                    })?;
            scrittore.write_image_data(&self.pixels).map_err(|errore| {
                ServiceError::DocumentGeneration {
                    reason: format!("punti del PNG non scritti: {errore}"),
                }
            })?;
            scrittore
                .finish()
                .map_err(|errore| ServiceError::DocumentGeneration {
                    reason: format!("PNG non chiuso: {errore}"),
                })?;
        }
        Ok(fuori)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::evidence_graph::{
        ContentFacts, GraphNode, LinkFacts, Neighbourhood, edge_of_link, edges_of_content,
        neighbourhood_of,
    };
    use lisi_core::model::indicator::IndicatorKind;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::Actor;
    use lisi_core::{ContentId, PersonId, SourceId, Timestamp};

    use super::{FIGURE_HEIGHT, FIGURE_WIDTH, render};

    /// Il testo di questo modulo, per le guardie che guardano la forma del
    /// codice e non il suo esito.
    const THIS_MODULE: &str = include_str!("graph_figure.rs");

    const ORA: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    /// La parte di produzione di questo modulo, senza le prove.
    fn produzione() -> &'static str {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        codice
    }

    /// Un vicinato attorno a un contenuto, con il numero di vicini indicato.
    fn vicinato(quanti: usize) -> Neighbourhood {
        let fatti = ContentFacts {
            content: ContentId::new(1),
            source: SourceId::new(7),
            at: ORA,
            identifier: Some(String::from("111")),
            indicators: (0..quanti)
                .map(|i| (IndicatorKind::Domain, format!("esempio{i:03}.it")))
                .collect(),
        };
        let archi = edges_of_content(&fatti);
        neighbourhood_of(&GraphNode::Content(ContentId::new(1)), &archi, 60)
    }

    /// Un vicinato che contiene anche un arco deciso da una persona.
    fn vicinato_con_atto_umano() -> Neighbourhood {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore deve essere valido");
        };
        let Ok(motivo) =
            OperationalReason::try_new("riscontro verificato sul documento acquisito agli atti")
        else {
            panic!("il motivo deve essere valido");
        };

        let arco = edge_of_link(&LinkFacts {
            person: PersonId::new(3),
            identifier: String::from("111"),
            by: attore,
            at: ORA,
            reason: motivo,
        });

        neighbourhood_of(
            &GraphNode::ObservedIdentity(String::from("111")),
            &[arco],
            60,
        )
    }

    /// **Due rese degli stessi archi danno gli stessi byte.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che un rapporto porti un manifesto SHA-256 accanto a un file che cambia a
    /// ogni generazione. Quel manifesto sarebbe la firma di nulla, e chi lo
    /// verifica lo scoprirebbe soltanto trovando un'impronta che non torna.
    ///
    /// # Il controllo negativo
    ///
    /// Facendo dipendere il disegno da qualcosa di variabile — l'orologio, un
    /// valore casuale, un livello di compressione scelto dalla libreria —
    /// questa prova diventa rossa.
    #[test]
    fn due_rese_danno_gli_stessi_byte() {
        let vicinato = vicinato(6);

        let (Ok(prima), Ok(seconda)) = (render(&vicinato), render(&vicinato)) else {
            panic!("la figura deve potersi rendere");
        };

        assert_eq!(
            prima.png(),
            seconda.png(),
            "due rese della stessa figura devono dare gli stessi byte"
        );
    }

    /// **La figura è un PNG valido, con la misura dichiarata.**
    #[test]
    fn la_figura_e_un_png_della_misura_dichiarata() {
        let Ok(figura) = render(&vicinato(4)) else {
            panic!("la figura deve potersi rendere");
        };

        let png = figura.png();
        assert!(
            png.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
            "l'inizio del file deve essere la firma PNG"
        );

        // La misura sta nell'IHDR, subito dopo la firma e la lunghezza.
        let larghezza = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
        let altezza = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
        assert_eq!(larghezza, FIGURE_WIDTH);
        assert_eq!(altezza, FIGURE_HEIGHT);
    }

    /// **Ogni segmento parte dal centro.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la figura affermi, in un documento, che due vicini hanno a che fare
    /// l'uno con l'altro. Un documento si stacca dal programma e gira: non ha
    /// accanto nessuno a cui chiedere, ed e' il posto in cui una figura fa piu'
    /// danno.
    ///
    /// # Il controllo negativo
    ///
    /// Aggiungendo un segmento fra due vicini, questa prova diventa rossa.
    #[test]
    fn ogni_segmento_parte_dal_centro() {
        let codice = produzione();

        let Some(inizio) = codice.find("for posto in &figura.neighbours {") else {
            panic!("le linee devono partire dai vicini della figura");
        };
        let Some(lunghezza) = codice[inizio..].find("\n    }\n") else {
            panic!("il blocco delle linee deve chiudersi");
        };
        let blocco = &codice[inizio..inizio + lunghezza];

        assert!(
            blocco.contains("tela.line(centro_x, centro_y, x, y, INK);"),
            "ogni segmento parte dal centro: {blocco}"
        );
        assert_eq!(
            codice.matches("tela.line(").count(),
            1,
            "esiste un solo punto in cui si disegna un segmento, e parte dal centro"
        );
    }

    /// **La legenda porta una riga per ogni arco, e il centro è il numero zero.**
    #[test]
    fn la_legenda_numera_ogni_vicino() {
        let vicinato = vicinato(5);
        let Ok(figura) = render(&vicinato) else {
            panic!("la figura deve potersi rendere");
        };

        assert_eq!(figura.centre().number, 0);
        assert_eq!(figura.legend().len(), vicinato.edges().len());

        for (posizione, riga) in figura.legend().iter().enumerate() {
            assert_eq!(riga.number, posizione + 1, "i numeri partono da uno");
            assert!(!riga.why.is_empty(), "ogni riga dice perche' e' collegata");
            assert!(
                !riga.kind.is_empty(),
                "ogni riga dice che genere di cosa e'"
            );
        }
    }

    /// **La legenda dice quando un collegamento è l'atto di una persona.**
    ///
    /// In un documento la distinzione fra un fatto osservato e la decisione di
    /// qualcuno non ha un colore che la spieghi: deve stare nelle parole.
    #[test]
    fn la_legenda_distingue_l_atto_di_una_persona() {
        let Ok(figura) = render(&vicinato_con_atto_umano()) else {
            panic!("la figura deve potersi rendere");
        };

        assert_eq!(figura.legend().len(), 1);
        assert!(
            figura.legend()[0].decided_by_a_person,
            "un legame deciso da una persona lo dichiara"
        );
        assert!(
            figura.legend()[0].why.contains("Una persona ha collegato"),
            "{}",
            figura.legend()[0].why
        );
    }

    /// **L'avvertenza viaggia con la figura.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una figura finisca in un documento senza la frase che dice che cosa
    /// non significa. Un documento si stacca dal programma: se l'avvertenza
    /// restasse nella schermata da cui l'immagine e' uscita, chi legge il
    /// documento non la vedrebbe mai.
    #[test]
    fn l_avvertenza_viaggia_con_la_figura() {
        let Ok(figura) = render(&vicinato(3)) else {
            panic!("la figura deve potersi rendere");
        };

        assert!(
            figura
                .caveat()
                .contains("non hanno per questo a che fare l'uno con l'altro"),
            "{}",
            figura.caveat()
        );
    }

    /// **Un vicinato tagliato lo dichiara anche nel documento.**
    #[test]
    fn un_vicinato_tagliato_lo_dichiara_anche_nel_documento() {
        let fatti = ContentFacts {
            content: ContentId::new(1),
            source: SourceId::new(7),
            at: ORA,
            identifier: Some(String::from("111")),
            indicators: (0..30)
                .map(|i| (IndicatorKind::Domain, format!("esempio{i:03}.it")))
                .collect(),
        };
        let archi = edges_of_content(&fatti);
        let stretto = neighbourhood_of(&GraphNode::Content(ContentId::new(1)), &archi, 5);

        let Ok(figura) = render(&stretto) else {
            panic!("la figura deve potersi rendere");
        };
        assert!(
            figura.caveat().contains("Non \u{e8} tutto"),
            "{}",
            figura.caveat()
        );
    }

    /// **La disposizione non si rifà: si riusa quella dello schermo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che il documento e lo schermo mostrino due figure diverse della stessa
    /// cosa, e che chi consegna il documento non possa dire che e' quella che ha
    /// guardato.
    #[test]
    fn la_disposizione_si_riusa_e_non_si_rifa() {
        let codice = produzione();

        assert!(
            codice.contains("use lisi_core::model::graph_layout::"),
            "la figura deve usare la disposizione di GRAPH-02"
        );
        assert!(
            codice.contains("layout_of(neighbourhood)"),
            "la figura deve chiamare la disposizione, non ricalcolarla"
        );
        for calcolo in [".cos()", ".sin()", "PI"] {
            assert!(
                !codice.contains(calcolo),
                "la figura non calcola posizioni: trovato «{calcolo}»"
            );
        }
    }

    /// **Nessun testo entra nell'immagine, tranne i numeri.**
    ///
    /// # Perché è una guardia e non una scelta grafica
    ///
    /// Perché un testo dentro un'immagine e' un testo che non esiste: non si
    /// cerca, non si copia, non si legge ad alta voce da una tecnologia
    /// assistiva. In un atto che qualcuno rileggera' fra due anni, una frase
    /// disegnata dentro un rettangolo e' una frase perduta.
    #[test]
    fn nessun_testo_entra_nell_immagine() {
        let codice = produzione();

        // L'unico disegno di segni e' quello delle cifre.
        assert_eq!(
            codice.matches("fn number(").count(),
            1,
            "esiste un solo modo di disegnare dei segni, e disegna cifre"
        );
        for testo in ["fn text(", "fn glyph(", "fn draw_label(", "font"] {
            assert!(
                !codice.to_lowercase().contains(testo),
                "l'immagine non porta testo: trovato «{testo}»"
            );
        }
        // E le parole stanno nella legenda, che e' testo.
        assert!(
            codice.contains("pub struct LegendRow {"),
            "le parole devono stare in una legenda"
        );
    }

    /// **Un vicinato senza vicini produce comunque una figura leggibile.**
    ///
    /// E' il caso ordinario di un contenuto appena acquisito, e una figura che
    /// esplodesse li' renderebbe impossibile generare il rapporto.
    #[test]
    fn un_vicinato_vuoto_produce_comunque_una_figura() {
        let fatti = ContentFacts {
            content: ContentId::new(1),
            source: SourceId::new(7),
            at: ORA,
            identifier: None,
            indicators: Vec::new(),
        };
        let archi = edges_of_content(&fatti);
        let vuoto = neighbourhood_of(&GraphNode::Content(ContentId::new(99)), &archi, 60);

        let Ok(figura) = render(&vuoto) else {
            panic!("una figura vuota deve potersi rendere");
        };
        assert!(figura.legend().is_empty());
        assert!(!figura.png().is_empty());
        assert_eq!(figura.centre().number, 0);
    }
}

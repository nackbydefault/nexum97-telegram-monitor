//! Dove si disegnano i nodi di un vicinato (GRAPH-02).
//!
//! # Perché la disposizione si calcola qui e non nel disegno
//!
//! Per due ragioni, e la seconda conta più della prima.
//!
//! **La prima:** una disposizione calcolata qui si prova. Due letture degli
//! stessi archi devono dare la **stessa figura** — e una figura che cambia fra
//! due letture è una figura di cui almeno una delle due mente. Un algoritmo a
//! forze, che è il modo consueto di disporre un grafo, non lo garantisce: parte
//! da posizioni casuali e converge dove capita.
//!
//! **La seconda:** GRAPH-03 dovrà rendere lo stesso grafo dentro un documento.
//! Se la disposizione vivesse nel disegno, il documento e lo schermo
//! mostrerebbero due figure diverse della stessa cosa, e chi consegna il
//! documento non potrebbe dire che è quella che ha guardato.
//!
//! # Le coordinate non stanno sul nodo
//!
//! [`NodePlacement`] è un tipo **separato** da
//! [`GraphNode`](crate::model::evidence_graph::GraphNode), e nessun nodo porta
//! una posizione.
//!
//! Non è pedanteria: la guardia di GRAPH-01 vieta i campi numerici sui nodi e
//! sugli archi perché un numero accanto a un pallino con un nome sopra diventa
//! un punteggio. Una coordinata è un numero, e se stesse dentro il nodo la
//! guardia dovrebbe fare un'eccezione — e un'eccezione è il posto da cui, un
//! giorno, entra il numero che non c'entra.
//!
//! Una posizione è una proprietà **della figura**, non della persona.
//!
//! **E non è soltanto una scelta: il tipo non lo consente.** `GraphNode` deriva
//! `Eq` e `Ord` — gli servono per l'ordine stabile del vicinato — e un `f32` non
//! è né l'uno né l'altro. Il controllo negativo che aggiunge una coordinata a un
//! nodo **non compila**, e fallisce due volte: per le derivazioni che non
//! reggono, e per i punti in cui quella variante si costruisce.
//!
//! # La forma: un centro e degli anelli
//!
//! Il nodo richiesto sta al centro; i suoi vicini gli stanno attorno, su anelli
//! concentrici. È la forma che dice ciò che il vicinato è — **questo nodo, e ciò
//! che lo tocca** — e non suggerisce nulla su ciò che si tocca fra loro, perché
//! fra due vicini **non si disegna alcuna linea**: nessun arco li unisce nei
//! fatti, e disegnarne uno sarebbe l'affermazione che GRAPH-01 rifiuta
//! (DEC-288).
//!
//! # Le coordinate sono frazioni, non pixel
//!
//! Vanno da 0 a 1. Il disegno le moltiplica per lo spazio che ha, e la stessa
//! figura resta la stessa su uno schermo grande, su uno piccolo e dentro un
//! documento.

use crate::model::evidence_graph::{GraphNode, Neighbourhood};

/// Quanti vicini stanno sull'anello più interno.
///
/// # Perché non tutti sullo stesso cerchio
///
/// Perché sessanta pallini su un cerchio solo si sovrappongono, e una figura
/// illeggibile non è una figura: chi non riesce a leggerla la guarda e basta,
/// che è il modo peggiore di guardare un grafo.
const PER_RING: usize = 10;

/// Il raggio dell'anello più interno, quando gli anelli sono più d'uno.
const FIRST_RADIUS: f32 = 0.20;

/// Il raggio dell'anello più esterno, in frazioni dello spazio disponibile.
///
/// # Perché non arriva a mezzo
///
/// Perché un pallino non è un punto: ha un riquadro attorno, con dentro il
/// nome. Un anello a mezzo spazio metterebbe il centro di quel riquadro sul
/// bordo, e metà nome finirebbe fuori dallo schermo — dove si legge come un
/// nome che non c'è.
const MAX_RADIUS: f32 = 0.42;

/// Dove sta un nodo nella figura.
///
/// # Perché è un tipo a sé
///
/// Vedere la nota di modulo: una posizione è una proprietà della figura, non del
/// nodo, e tenerla fuori dal nodo è ciò che permette alla guardia di GRAPH-01 di
/// restare senza eccezioni.
#[derive(Debug, Clone, PartialEq)]
pub struct NodePlacement {
    /// Quale nodo.
    pub node: GraphNode,
    /// Ascissa, da 0 a 1.
    pub x: f32,
    /// Ordinata, da 0 a 1.
    pub y: f32,
}

/// La figura di un vicinato: un centro, e i suoi vicini attorno.
///
/// # Perché i vicini stanno nello stesso ordine degli archi
///
/// Perché ogni pallino deve poter dire **perché** è lì, e la ragione sta
/// nell'arco corrispondente. Due elenchi che non si corrispondono
/// posizione per posizione sono due elenchi che un giorno divergono, e la figura
/// mostrerebbe la ragione sbagliata accanto al nodo giusto.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphLayout {
    /// Il nodo richiesto, al centro.
    pub centre: NodePlacement,
    /// I vicini, **nello stesso ordine degli archi del vicinato**.
    pub neighbours: Vec<NodePlacement>,
}

/// Il nodo dall'altro capo di un arco, rispetto al centro.
///
/// Un arco tocca il centro da una parte o dall'altra: il vicino è quello che il
/// centro non è. Se l'arco parte e arriva sullo stesso nodo — cosa che le regole
/// non producono, ma che il tipo consente — il vicino è quel nodo stesso, e la
/// figura lo mostra su di sé invece di inventare.
fn altro_capo<'archi>(
    centre: &GraphNode,
    from: &'archi GraphNode,
    to: &'archi GraphNode,
) -> &'archi GraphNode {
    if from == centre { to } else { from }
}

/// Il raggio dell'anello indicato, quando gli anelli in tutto sono quelli dati.
///
/// # Perché il raggio dipende da quanti anelli ci sono
///
/// Perché un passo fisso porta l'anello più esterno **fuori dallo spazio** non
/// appena gli anelli sono quattro — ed è il difetto che la prova
/// `ogni_posizione_sta_dentro_lo_spazio` ha trovato prima che uscisse di qui.
///
/// Con il raggio ricavato dal numero di anelli, l'ultimo cade sempre su
/// [`MAX_RADIUS`] e i precedenti si distribuiscono fra quello e
/// [`FIRST_RADIUS`]: la figura usa lo spazio che ha, e non ne esce mai.
fn raggio(anello: usize, anelli_in_tutto: usize) -> f32 {
    if anelli_in_tutto <= 1 {
        return MAX_RADIUS;
    }
    let quota = anello_come_numero(anello) / anello_come_numero(anelli_in_tutto - 1);
    FIRST_RADIUS + (MAX_RADIUS - FIRST_RADIUS) * quota
}

/// Dispone il vicinato attorno al suo nodo.
///
/// # Perché è deterministica, e come
///
/// L'ordine dei vicini è quello del vicinato, che è già stabile. La posizione
/// discende **soltanto** dall'indice: nessun valore casuale, nessuna iterazione,
/// nessuna dipendenza dal tempo. Due chiamate sugli stessi archi danno la stessa
/// figura, e una prova lo verifica.
#[must_use]
pub fn layout_of(neighbourhood: &Neighbourhood) -> GraphLayout {
    let centre = NodePlacement {
        node: neighbourhood.node().clone(),
        x: 0.5,
        y: 0.5,
    };

    // QUANTI ANELLI SERVONO, prima di disporre: il raggio dipende da questo, e
    // senza saperlo l'anello piu' esterno finirebbe fuori dallo spazio.
    let anelli_in_tutto = neighbourhood.edges().len().div_ceil(PER_RING);

    let neighbours = neighbourhood
        .edges()
        .iter()
        .enumerate()
        .map(|(indice, arco)| {
            let nodo = altro_capo(neighbourhood.node(), arco.from(), arco.to());

            // L'ANELLO E IL POSTO SULL'ANELLO discendono soltanto dall'indice.
            let anello = indice / PER_RING;
            let posto = indice % PER_RING;

            // Quanti stanno su QUESTO anello: l'ultimo puo' essere parziale, e
            // distribuirne tre su dieci posizioni li ammucchierebbe da una parte.
            let primo_dell_anello = anello * PER_RING;
            let su_questo_anello = (neighbourhood.edges().len() - primo_dell_anello).min(PER_RING);

            let raggio = raggio(anello, anelli_in_tutto);

            // Ogni anello parte da un angolo diverso: due anelli che partissero
            // dallo stesso punto allineerebbero i pallini su un raggio solo, e
            // quell'allineamento si legge come un raggruppamento che non c'e'.
            let sfasamento = anello_come_numero(anello) * 0.5;
            let giro = core::f32::consts::PI * 2.0;
            let angolo = giro * (posto_come_numero(posto) + sfasamento)
                / posto_come_numero(su_questo_anello.max(1));

            NodePlacement {
                node: nodo.clone(),
                x: 0.5 + raggio * angolo.cos(),
                y: 0.5 + raggio * angolo.sin(),
            }
        })
        .collect();

    GraphLayout { centre, neighbours }
}

/// L'indice di un anello come numero con la virgola.
///
/// Sta in una funzione perché la conversione da `usize` non è esatta oltre i
/// sedici milioni, e un troncamento silenzioso in mezzo a un calcolo di
/// posizioni sarebbe difficile da vedere. Qui gli anelli sono pochi, e la
/// conversione è dichiarata invece che nascosta.
#[expect(
    clippy::cast_precision_loss,
    reason = "gli anelli sono pochi: il vicinato ha un tetto, e la perdita non si raggiunge"
)]
fn anello_come_numero(anello: usize) -> f32 {
    anello as f32
}

/// Il posto su un anello come numero con la virgola.
///
/// Vedere [`anello_come_numero`].
#[expect(
    clippy::cast_precision_loss,
    reason = "i posti su un anello sono al massimo PER_RING: la perdita non si raggiunge"
)]
fn posto_come_numero(posto: usize) -> f32 {
    posto as f32
}

#[cfg(test)]
mod tests {
    use super::{GraphLayout, NodePlacement, layout_of};
    use crate::model::evidence_graph::{
        ContentFacts, GraphNode, edges_of_content, neighbourhood_of,
    };
    use crate::model::indicator::IndicatorKind;
    use crate::time::Timestamp;
    use crate::{ContentId, SourceId};

    /// Il testo di questo modulo, per la guardia che guarda la forma del codice.
    const THIS_MODULE: &str = include_str!("graph_layout.rs");

    const ORA: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    /// Un vicinato attorno a un contenuto con il numero di vicini indicato.
    fn vicinato(quanti: usize) -> crate::model::evidence_graph::Neighbourhood {
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

    /// **Due letture degli stessi archi danno la stessa figura.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la stessa cosa, guardata due volte, si presenti in due modi diversi.
    /// Una figura che cambia fra due letture e' una figura di cui almeno una
    /// delle due mente, e chi consegna un documento non potrebbe dire che
    /// quella stampata e' quella che ha guardato.
    ///
    /// # Il controllo negativo
    ///
    /// Facendo dipendere la posizione da qualcosa che non sia l'indice — un
    /// valore casuale, l'istante, l'ordine di iterazione di una mappa — questa
    /// prova diventa rossa.
    #[test]
    fn due_letture_danno_la_stessa_figura() {
        let vicinato = vicinato(7);

        let primo = layout_of(&vicinato);
        let secondo = layout_of(&vicinato);

        assert_eq!(primo, secondo);
    }

    /// **Nessuna posizione viene da un valore casuale o dall'orologio.**
    #[test]
    fn la_disposizione_non_dipende_da_nulla_di_variabile() {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let codice = codice
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n")
            .to_lowercase();

        for vietata in ["rand", "random", "instant::now", "systemtime", "hashmap"] {
            assert!(
                !codice.contains(vietata),
                "la disposizione non deve dipendere da «{vietata}»: due letture darebbero due \
                 figure"
            );
        }
    }

    /// **Il nodo richiesto sta al centro.**
    #[test]
    fn il_nodo_richiesto_sta_al_centro() {
        let vicinato = vicinato(5);
        let figura = layout_of(&vicinato);

        assert_eq!(figura.centre.node, GraphNode::Content(ContentId::new(1)));
        assert!((figura.centre.x - 0.5).abs() < f32::EPSILON);
        assert!((figura.centre.y - 0.5).abs() < f32::EPSILON);
    }

    /// **A ogni arco corrisponde un vicino, nello stesso ordine.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la figura mostri la ragione sbagliata accanto al nodo giusto. Ogni
    /// pallino deve poter dire perche' e' li', e la ragione sta nell'arco che
    /// gli corrisponde: due elenchi che non si corrispondono posizione per
    /// posizione sono due elenchi che un giorno divergono.
    #[test]
    fn a_ogni_arco_corrisponde_un_vicino_nello_stesso_ordine() {
        let vicinato = vicinato(5);
        let figura = layout_of(&vicinato);

        assert_eq!(figura.neighbours.len(), vicinato.edges().len());

        for (posizione, arco) in vicinato.edges().iter().enumerate() {
            let vicino = &figura.neighbours[posizione].node;
            assert!(
                arco.from() == vicino || arco.to() == vicino,
                "il vicino in posizione {posizione} non e' un capo del suo arco"
            );
            assert_ne!(
                vicino,
                vicinato.node(),
                "il vicino non e' il centro: e' l'altro capo"
            );
        }
    }

    /// **Ogni posizione sta dentro lo spazio disponibile.**
    ///
    /// Una coordinata fuori da zero-uno finirebbe fuori dallo schermo, e un
    /// pallino che non si vede si legge come un pallino che non c'e'.
    #[test]
    fn ogni_posizione_sta_dentro_lo_spazio() {
        let figura = layout_of(&vicinato(40));

        for posto in &figura.neighbours {
            assert!(
                (0.0..=1.0).contains(&posto.x),
                "ascissa fuori dallo spazio: {}",
                posto.x
            );
            assert!(
                (0.0..=1.0).contains(&posto.y),
                "ordinata fuori dallo spazio: {}",
                posto.y
            );
        }
    }

    /// **Due vicini non finiscono nello stesso punto.**
    ///
    /// Due pallini sovrapposti si leggono come uno, e chi guarda conterebbe un
    /// vicino invece di due.
    #[test]
    fn due_vicini_non_si_sovrappongono() {
        let figura = layout_of(&vicinato(25));

        for (primo, uno) in figura.neighbours.iter().enumerate() {
            for altro in figura.neighbours.iter().skip(primo + 1) {
                let distanza = ((uno.x - altro.x).powi(2) + (uno.y - altro.y).powi(2)).sqrt();
                assert!(
                    distanza > 0.02,
                    "due vicini quasi nello stesso punto: distanza {distanza}"
                );
            }
        }
    }

    /// **Un vicinato vuoto non produce vicini, e il centro resta.**
    #[test]
    fn un_vicinato_vuoto_ha_solo_il_suo_centro() {
        let fatti = ContentFacts {
            content: ContentId::new(1),
            source: SourceId::new(7),
            at: ORA,
            identifier: None,
            indicators: Vec::new(),
        };
        let archi = edges_of_content(&fatti);
        let vicinato = neighbourhood_of(&GraphNode::Content(ContentId::new(99)), &archi, 60);

        let figura: GraphLayout = layout_of(&vicinato);
        assert!(figura.neighbours.is_empty());
        assert_eq!(figura.centre.node, GraphNode::Content(ContentId::new(99)));
    }

    /// **Le coordinate non stanno sul nodo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la guardia di GRAPH-01 sui campi numerici debba fare un'eccezione per
    /// le coordinate — e un'eccezione e' il posto da cui, un giorno, entra il
    /// numero che non c'entra.
    #[test]
    fn le_coordinate_non_stanno_sul_nodo() {
        let dominio = include_str!("evidence_graph.rs");
        let Some((codice, _)) = dominio.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il dominio del grafo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = codice.find("pub enum GraphNode {") else {
            panic!("l'enumerazione dei nodi deve esistere");
        };
        let Some(lunghezza) = codice[inizio..].find("\n}\n") else {
            panic!("l'enumerazione dei nodi deve chiudersi");
        };
        let nodi = &codice[inizio..inizio + lunghezza];

        for vietato in ["x:", "y:", "f32", "f64", "position", "coord"] {
            assert!(
                !nodi.contains(vietato),
                "un nodo non porta la propria posizione: trovato «{vietato}»"
            );
        }

        // E il posto esiste, in un tipo suo.
        let posto = NodePlacement {
            node: GraphNode::Content(ContentId::new(1)),
            x: 0.5,
            y: 0.5,
        };
        assert_eq!(posto.node, GraphNode::Content(ContentId::new(1)));
    }
}

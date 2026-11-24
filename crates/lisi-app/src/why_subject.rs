//! Tutta la provenienza sui soggetti che non sono un contenuto (PROV-02).
//!
//! # Da dove si apre
//!
//! Dalla porta «Provenienza, note e contesto» di «Perché vedo questo?» (PR-02,
//! ADR-0119), e da nessun'altra parte: la domanda ha un comando solo, e questo
//! pannello è la risposta lunga per cinque generi di elemento.
//!
//! # Perché un pannello solo per cinque schermate
//!
//! Perché la risposta deve avere **una voce sola**. Cinque pannelli separati
//! diventerebbero cinque voci, e la prima che qualcuno modifica direbbe una cosa
//! diversa dalle altre quattro — proprio sulla domanda che esiste per rendere
//! confrontabili cose diverse.
//!
//! # Perché il genere del soggetto arriva come numero
//!
//! Perché l'insieme dei soggetti è **chiuso**, e un nome che tornasse
//! dall'interfaccia andrebbe interpretato. Un numero fuori dall'insieme non si
//! indovina: il pannello non si apre, e chi ha premuto se ne accorge.
//!
//! È la stessa scelta del ricentramento del grafo, e per la stessa ragione.
//!
//! # La spiegazione arriva dalla schermata, e non si rilegge
//!
//! Chi chiede il perché ha la cosa davanti, e la sua frase è già sullo schermo:
//! rileggerla dall'archivio comporrebbe una **seconda verità** accanto a quella
//! che l'operatore sta guardando, e le due divergerebbero alla prima modifica.

use lisi_core::ContentId;
use lisi_core::model::indicator::IndicatorKind;
use lisi_core::model::why::{Origin, WhySubject};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// Il genere di soggetto, come l'interfaccia lo indica.
///
/// # Perché delle costanti con un nome e non dei numeri nudi
///
/// Perché un `3` dentro una chiamata non dice a nessuno di che cosa si stia
/// chiedendo il perché, e il giorno in cui l'insieme cambia i numeri nudi
/// restano dove sono senza che nessuno se ne accorga.
pub mod kind {
    /// Un grappolo di segnali.
    pub const CYBER_EVENT: i32 = 0;
    /// Un arco del grafo osservato nell'archivio.
    pub const GRAPH_EDGE_OBSERVED: i32 = 1;
    /// Un arco del grafo che una persona ha deciso.
    pub const GRAPH_EDGE_DECIDED: i32 = 2;
    /// Una cosa associata a un'identità osservata.
    pub const PERSON_ASSOCIATION: i32 = 3;
    /// Un valore dichiarato emergente.
    pub const TREND: i32 = 4;
    /// Due contenuti che si somigliano.
    pub const RESEMBLANCE: i32 = 5;
}

/// Collega il pannello ai servizi.
///
/// Soltanto la chiusura: il pannello si apre dalla porta «Vedi tutta la
/// provenienza» di «Perché vedo questo?» (PR-02), che chiama [`open`].
pub fn wire(window: &AppWindow) {
    {
        let handle = window.as_weak();
        window.on_close_why_subject(move || {
            if crate::lock::refuse_while_locked("close_why_subject") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close(&window);
            }
        });
    }
}

/// Chiude il pannello, svuotando ogni riga che lo riguarda.
///
/// # Perché si svuota tutto
///
/// Perché una natura o un metodo rimasti dietro un pannello chiuso tornerebbero
/// a comparire accanto a un soggetto diverso — e un metodo che parla di un altro
/// calcolo è peggio di nessun metodo.
fn close(window: &AppWindow) {
    window.set_why_subject_open(false);
    window.set_why_subject_label(SharedString::new());
    window.set_why_subject_nature(SharedString::new());
    window.set_why_subject_nature_note(SharedString::new());
    window.set_why_subject_explanation(SharedString::new());
    window.set_why_subject_method(SharedString::new());
    window.set_why_subject_method_detail(SharedString::new());
    window.set_why_subject_is_elaboration(false);
}

/// Apre il pannello sul soggetto indicato: la porta di «Perché vedo questo?».
pub fn open(window: &AppWindow, genere: i32, chiave: &str, spiegazione: &str) {
    close(window);

    // UN GENERE FUORI DALL'INSIEME NON SI INDOVINA: aprire il pannello sul
    // soggetto sbagliato mostrerebbe la natura sbagliata, e la natura e' la
    // cosa che questo pannello esiste per dire.
    let Some(soggetto) = subject_of(genere, chiave) else {
        return;
    };

    let Some(risposta) = lisi_services::why::answer_for(soggetto, spiegazione) else {
        return;
    };

    window.set_why_subject_open(true);
    window.set_why_subject_label(crate::lingua::schermo(risposta.subject().as_label()));
    window.set_why_subject_nature(crate::lingua::schermo(risposta.nature().label()));
    window.set_why_subject_nature_note(crate::lingua::schermo(risposta.nature().as_sentence()));
    window.set_why_subject_explanation(crate::lingua::schermo(risposta.explanation()));
    window.set_why_subject_method(SharedString::from(risposta.method()));
    // Il dettaglio tecnico del metodo sta dietro «Dettagli tecnici» (ADR-0117).
    window.set_why_subject_method_detail(SharedString::from(
        lisi_services::why::method_technical_detail(risposta.subject()).unwrap_or_default(),
    ));
    window.set_why_subject_is_elaboration(risposta.nature() == Origin::Computed);
}

/// Il soggetto, dal genere e dalla chiave che l'interfaccia indica.
///
/// Restituisce `None` per un genere che non esiste, o per una chiave che il
/// soggetto non ammette: una coppia di contenuti si scrive `primo-secondo`, e
/// una chiave che non ha quella forma indicherebbe un'altra coppia.
fn subject_of(genere: i32, chiave: &str) -> Option<WhySubject> {
    match genere {
        kind::CYBER_EVENT => Some(WhySubject::CyberEvent {
            // IL GENERE DELL'INDICATORE non entra nella chiave: la frase del
            // grappolo lo dice gia', e chiederlo all'interfaccia significherebbe
            // farselo dire da chi non lo sa. La CVE e' il caso ordinario, e
            // l'etichetta nomina il valore, che e' cio' che identifica il
            // gruppo dentro un monitoraggio.
            kind: IndicatorKind::Cve,
            value: chiave.to_owned(),
        }),
        kind::GRAPH_EDGE_OBSERVED => Some(WhySubject::GraphEdge {
            decided_by_a_person: false,
        }),
        kind::GRAPH_EDGE_DECIDED => Some(WhySubject::GraphEdge {
            decided_by_a_person: true,
        }),
        kind::PERSON_ASSOCIATION => Some(WhySubject::PersonAssociation {
            identifier: chiave.to_owned(),
        }),
        kind::TREND => Some(WhySubject::Trend {
            key: chiave.to_owned(),
        }),
        kind::RESEMBLANCE => {
            let (primo, secondo) = chiave.split_once('-')?;
            let (Ok(primo), Ok(secondo)) = (primo.parse::<i64>(), secondo.parse::<i64>()) else {
                return None;
            };
            if primo <= 0 || secondo <= 0 {
                return None;
            }
            Some(WhySubject::Resemblance {
                first: ContentId::new(primo),
                second: ContentId::new(secondo),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::why::{Origin, WhySubject};

    use super::{kind, subject_of};

    /// Interfaccia principale, letta a tempo di compilazione.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il blocco del pannello, dal suo marcatore alla schermata di blocco.
    fn pannello() -> &'static str {
        let Some(inizio) = UI.find("if root.why-subject-open:") else {
            panic!("il pannello deve esistere");
        };
        let resto = &UI[inizio..];
        let Some(fine) = resto.find("// Schermata di blocco") else {
            panic!("il pannello deve chiudersi prima della schermata di blocco");
        };
        &resto[..fine]
    }

    /// **La natura arriva prima della spiegazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una spiegazione convincente venga letta senza sapere che e' un
    /// calcolo. Letta cosi', si ricorda come un fatto — e in una relazione si
    /// scrive come un fatto.
    ///
    /// # Il controllo negativo
    ///
    /// Spostando la natura sotto la spiegazione, questa prova diventa rossa.
    #[test]
    fn la_natura_arriva_prima_della_spiegazione() {
        let testo = pannello();

        let Some(natura) = testo.find("root.why-subject-nature") else {
            panic!("il pannello deve mostrare la natura");
        };
        let Some(spiegazione) = testo.find("root.why-subject-explanation") else {
            panic!("il pannello deve mostrare la spiegazione");
        };

        assert!(
            natura < spiegazione,
            "la natura arriva DOPO la spiegazione: chi legge si e' gia' fatto un'idea \
             di che genere di cosa sta guardando"
        );
    }

    /// **Il metodo compare solo quando c'è.**
    ///
    /// Un metodo accanto a un fatto osservato direbbe che e' stato calcolato
    /// anche quello.
    #[test]
    fn il_metodo_compare_solo_quando_c_e() {
        let testo = pannello();
        assert!(
            testo.contains("if root.why-subject-method != \"\":"),
            "il metodo deve comparire solo quando non e' vuoto"
        );
    }

    /// **Il pannello si apre soltanto dalla porta di «Perché vedo questo?».**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che la stessa domanda torni ad avere due comandi: uno che apre la
    /// risposta in tre parti e uno che salta direttamente al metodo, senza la
    /// parte su che cosa l'elemento non significa (PR-02).
    #[test]
    fn il_pannello_si_apre_soltanto_dalla_porta() {
        assert!(
            !UI.contains("open-why-subject"),
            "la schermata non deve poter aprire il pannello da sola"
        );
        const PORTA: &str = include_str!("explain.rs");
        assert!(
            PORTA.contains("crate::why_subject::open(window, genere,"),
            "la porta di «Perché vedo questo?» deve aprire questo pannello"
        );
    }

    /// **Un genere fuori dall'insieme non produce un soggetto.**
    ///
    /// Aprire il pannello sul soggetto sbagliato mostrerebbe la natura
    /// sbagliata, e la natura e' la cosa che il pannello esiste per dire.
    #[test]
    fn un_genere_fuori_dall_insieme_non_produce_un_soggetto() {
        for fuori in [-1, 6, 99, i32::MAX] {
            assert!(
                subject_of(fuori, "qualcosa").is_none(),
                "il genere {fuori} non esiste e non si indovina"
            );
        }
    }

    /// **Ogni genere dell'interfaccia produce il soggetto giusto.**
    #[test]
    fn ogni_genere_produce_il_soggetto_giusto() {
        assert!(matches!(
            subject_of(kind::CYBER_EVENT, "CVE-2026-1234"),
            Some(WhySubject::CyberEvent { .. })
        ));
        assert_eq!(
            subject_of(kind::GRAPH_EDGE_OBSERVED, "x").map(|soggetto| soggetto.nature()),
            Some(Origin::Observed)
        );
        assert_eq!(
            subject_of(kind::GRAPH_EDGE_DECIDED, "x").map(|soggetto| soggetto.nature()),
            Some(Origin::Operator)
        );
        assert!(matches!(
            subject_of(kind::PERSON_ASSOCIATION, "111"),
            Some(WhySubject::PersonAssociation { .. })
        ));
        assert_eq!(
            subject_of(kind::TREND, "molotov").map(|soggetto| soggetto.nature()),
            Some(Origin::Computed)
        );
        assert!(matches!(
            subject_of(kind::RESEMBLANCE, "3-9"),
            Some(WhySubject::Resemblance { .. })
        ));
    }

    /// **Una coppia malformata non si indovina.**
    ///
    /// Indovinarla indicherebbe una coppia diversa da quella toccata, e chi
    /// guarda non avrebbe modo di accorgersene.
    #[test]
    fn una_coppia_malformata_non_si_indovina() {
        for storta in ["", "3", "3-", "-9", "a-b", "0-9", "3-0", "-3--9"] {
            assert!(
                subject_of(kind::RESEMBLANCE, storta).is_none(),
                "«{storta}» non e' una coppia di identificativi"
            );
        }
    }
}

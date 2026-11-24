//! Il registro del monitoraggio in **testo semplice**.
//!
//! # Perché esiste, accanto al registro Excel
//!
//! Un `.xlsx` si apre con un programma che non tutti hanno, non si legge da un
//! terminale, non si confronta con `diff`, non si cita in una comunicazione di
//! servizio senza allegarlo. Il testo semplice si legge ovunque e sopravvive a
//! qualunque cambio di formato: è la copia che resterà leggibile fra vent'anni.
//!
//! ADR-0031 lo prevedeva fra i cinque documenti del pacchetto; è stato l'ultimo
//! a essere costruito.
//!
//! # Perché è una SECONDA RESA e non una seconda composizione
//!
//! Questo modulo **non decide che cosa dire**. Riceve lo stesso [`Ledger`] che
//! `report_ledger::compose` produce per il foglio Excel, e lo scrive in testo.
//!
//! È la scelta che conta di tutto il modulo. Comporre il testo da sé avrebbe
//! significato due definizioni di «che cosa contiene il registro», e due
//! definizioni della stessa cosa prima o poi divergono — il registro Excel
//! direbbe novantatré contenuti e il registro in testo novantadue, e nessuno
//! saprebbe quale credere in un atto.
//!
//! È la stessa relazione che c'è fra la relazione `.docx` e la relazione
//! `.pdf`: una composizione, due rese.
//!
//! # La portata è «tutto il monitorato»
//!
//! Livello 0 compreso. Non è il documento delle risultanze scelte
//! dall'operatore — quello è la relazione — ma la rappresentazione completa di
//! ciò che il monitoraggio ha raccolto. La distinzione è di ADR-0031 e questo
//! modulo non la tocca: gli arriva già decisa nel [`Ledger`].
//!
//! # Il testo remoto resta testo
//!
//! Le celle possono contenere estratti di messaggi acquisiti. Qui non c'è alcun
//! formato che possa reinterpretarli — nessuna formula, nessun markup — ma i
//! caratteri di controllo vengono comunque appiattiti: un «a capo» dentro una
//! cella spezzerebbe la riga del registro e farebbe leggere due record dove ce
//! n'è uno.

use lisi_core::ATTRIBUTION;

use crate::error::ServiceResult;
use crate::report_ledger::{Cell, Ledger, Sheet};
use crate::report_narrative::NOT_AVAILABLE;

/// Larghezza massima del **corpo di un contenuto** prima del taglio.
///
/// Non serve alla resa — il testo non impagina — ma a impedire che un messaggio
/// molto lungo renda illeggibile la riga del record. Il taglio si dichiara, e
/// riguarda **solo** il corpo: ogni altra colonna si scrive per intero, perché
/// le altre portano motivazioni, decisioni e la frase che dice che cosa un
/// recupero non vede, e un testo probatorio interrotto nei puntini non si
/// ricostruisce (FINAL-PRODUCT-REVIEW-01, FPR-05). Il corpo si può accorciare
/// perché sta per intero nell'allegato tecnico e nel registro in Excel, e la
/// testata di questo file lo dichiara.
const MAX_BODY_CHARS: usize = 200;

/// Il separatore fra le colonne.
///
/// Una barra verticale spaziata, non una tabulazione: la tabulazione si rende
/// diversamente in ogni visualizzatore, e un registro che si legge storto in
/// metà dei programmi non è un registro leggibile ovunque.
const SEPARATOR: &str = " | ";

/// Scrive il registro in testo semplice, codificato UTF-8.
///
/// # Errori
///
/// Non ne restituisce: la composizione è già avvenuta e scrivere testo non può
/// fallire. Il tipo di ritorno resta uniforme agli altri generatori perché
/// chi lo chiama li tratta allo stesso modo.
pub fn render(ledger: &Ledger) -> ServiceResult<Vec<u8>> {
    let mut out = String::new();

    out.push_str("NEXUM/97 — registro del monitoraggio\n");
    out.push_str(
        "Rappresenta TUTTO il monitorato, livello 0 compreso, e non le sole\n\
         risultanze scelte dall'operatore: quelle sono nella relazione.\n",
    );
    out.push_str(&format!(
        "Generato il {}\n",
        ledger.generated_at.to_readable_utc()
    ));
    out.push_str(&format!("{ATTRIBUTION}\n"));
    // DOVE IL TESTO E' TAGLIATO, E DOVE STA PER INTERO. Senza questa riga il
    // taglio del corpo sarebbe un «…» che non rimanda a niente.
    out.push_str(&format!(
        "Il corpo dei contenuti è riportato fino a {MAX_BODY_CHARS} caratteri, con «…» dove è\n\
         tagliato, e le interruzioni di riga diventano spazi: il testo completo è\n\
         nell'allegato tecnico e nel registro in Excel. Ogni altra colonna è scritta\n\
         per intero.\n"
    ));

    for sheet in &ledger.sheets {
        out.push('\n');
        out.push_str(&rule('='));
        out.push('\n');
        out.push_str(&sheet.name);
        out.push('\n');
        out.push_str(&rule('='));
        out.push('\n');

        // Le intestazioni ci sono sempre: un foglio senza intestazioni e' una
        // tabella che nessuno sa rileggere fra sei mesi.
        out.push_str(&sheet.headers.join(SEPARATOR));
        out.push('\n');
        out.push_str(&rule('-'));
        out.push('\n');

        if let Some(frase) = empty_columns(sheet) {
            out.push_str(&frase);
            out.push('\n');
        }

        if sheet.rows.is_empty() {
            // **Un foglio vuoto si dichiara vuoto.** «Non ci sono stati
            // problemi» e «non ne sono stati registrati» sono due affermazioni
            // diverse, e un foglio che sparisse perche' non ha righe farebbe
            // credere la prima quando vale la seconda.
            out.push_str("(nessun record)\n");
            continue;
        }

        for row in &sheet.rows {
            let cells: Vec<String> = row.iter().map(cell_text).collect();
            out.push_str(&cells.join(SEPARATOR));
            out.push('\n');
        }
    }

    // In Esercitazione la frase di SIC-17 apre il file (PR-13, ADR-0129).
    Ok(crate::run_mode::marked_text(out).into_bytes())
}

/// Una riga di separazione.
fn rule(character: char) -> String {
    std::iter::repeat_n(character, 78).collect()
}

/// Le colonne che in questo foglio non portano **alcun** dato, dichiarate una
/// volta in testa alla tabella.
///
/// # Perché
///
/// Perché nel registro di una prova la frase «non disponibile» compariva
/// sessanta volte su centoquarantotto righe, e quasi tutte stavano in quattro
/// colonne vuote per ogni record (FINAL-PRODUCT-REVIEW-01, FPR-06). Saperlo
/// prima di scorrere la tabella è il genere di cosa che si dice una volta.
///
/// # Perché le celle restano
///
/// Perché «non disponibile» e «vuoto» sono due affermazioni diverse, e questa
/// riga non ne toglie nessuna: dichiara dove il dato non c'è per nessun
/// record, e lascia a ogni cella il compito di dirlo per la propria riga.
fn empty_columns(sheet: &Sheet) -> Option<String> {
    // Con un record solo non c'è nulla da riassumere: la riga si legge per
    // intero.
    if sheet.rows.len() < 2 {
        return None;
    }

    let vuote: Vec<&str> = sheet
        .headers
        .iter()
        .enumerate()
        .filter(|(column, _)| {
            sheet.rows.iter().all(|row| {
                row.get(*column)
                    .is_some_and(|cell| matches!(cell, Cell::Text(value) if value == NOT_AVAILABLE))
            })
        })
        .map(|(_, header)| header.as_str())
        .collect();

    if vuote.is_empty() {
        return None;
    }
    Some(format!(
        "Colonne senza alcun dato in questo foglio: {}.",
        vuote.join(", ")
    ))
}

/// Il testo di una cella: appiattito sempre, accorciato solo se è un corpo.
fn cell_text(cell: &Cell) -> String {
    match cell {
        Cell::Number(value) => value.to_string(),
        Cell::Text(value) => flatten(value),
        Cell::Body(value) => shorten(&flatten(value)),
    }
}

/// Appiattisce il testo di una cella.
///
/// I caratteri di controllo diventano spazi. In un registro a colonne un «a
/// capo» dentro una cella spezzerebbe la riga e farebbe leggere **due record
/// dove ce n'è uno**: è il modo più semplice per far sembrare il registro
/// diverso da com'è, e chi scrive i messaggi acquisiti potrebbe averlo scelto.
fn flatten(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Accorcia il corpo di un contenuto a [`MAX_BODY_CHARS`] caratteri.
///
/// Taglia per **caratteri** e non per byte: un taglio a metà di una sequenza
/// UTF-8 produrrebbe un file che non si apre.
fn shorten(flattened: &str) -> String {
    if flattened.chars().count() <= MAX_BODY_CHARS {
        return flattened.to_owned();
    }

    // Il taglio si dichiara: un testo troncato in silenzio farebbe credere
    // completo un record che non lo e'.
    let mut cut: String = flattened.chars().take(MAX_BODY_CHARS).collect();
    cut.push('\u{2026}');
    cut
}

#[cfg(test)]
mod tests {
    use super::{MAX_BODY_CHARS, SEPARATOR, empty_columns, render, shorten};
    use crate::report_ledger::{Cell, Ledger, Sheet};
    use crate::report_narrative::NOT_AVAILABLE;
    use lisi_core::Timestamp;

    fn istante() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    fn registro(sheets: Vec<Sheet>) -> Ledger {
        Ledger {
            generated_at: istante(),
            sheets,
        }
    }

    fn testo(ledger: &Ledger) -> String {
        let Ok(bytes) = render(ledger) else {
            panic!("la resa in testo non puo' fallire");
        };
        let Ok(text) = String::from_utf8(bytes) else {
            panic!("la resa deve essere UTF-8 valido");
        };
        text
    }

    #[test]
    fn la_resa_e_utf8_valido_anche_con_testo_non_latino() {
        // Un registro che perdesse i caratteri non latini renderebbe illeggibile
        // proprio il materiale che questo prodotto acquisisce piu' spesso.
        let ledger = registro(vec![Sheet {
            name: String::from("01 — Sessione"),
            headers: vec![String::from("campo"), String::from("valore")],
            rows: vec![vec![
                Cell::Text(String::from("etichetta")),
                Cell::Text(String::from("Ελληνικά · Кириллица · العربية · 日本語")),
            ]],
        }]);

        let text = testo(&ledger);
        assert!(text.contains("Кириллица"));
        assert!(text.contains("日本語"));
    }

    #[test]
    fn un_foglio_senza_righe_dichiara_di_essere_vuoto() {
        // «Non ci sono stati problemi» e «non ne sono stati registrati» sono due
        // affermazioni diverse. Un foglio che sparisse perche' vuoto farebbe
        // credere la prima quando vale la seconda.
        let ledger = registro(vec![Sheet {
            name: String::from("07_ANOMALIE"),
            headers: vec![String::from("quando"), String::from("che cosa")],
            rows: Vec::new(),
        }]);

        let text = testo(&ledger);
        assert!(text.contains("07_ANOMALIE"), "il foglio deve esserci");
        assert!(
            text.contains("(nessun record)"),
            "il foglio vuoto deve dichiararsi vuoto"
        );
    }

    #[test]
    fn un_a_capo_dentro_una_cella_non_spezza_la_riga() {
        // E' il modo piu' semplice per far leggere due record dove ce n'e' uno,
        // e chi scrive i messaggi acquisiti potrebbe averlo scelto.
        let ledger = registro(vec![Sheet {
            name: String::from("03 — Contenuti"),
            headers: vec![String::from("id"), String::from("testo")],
            rows: vec![vec![
                Cell::Number(7),
                Cell::Text(String::from("prima\nseconda\r\nterza")),
            ]],
        }]);

        let text = testo(&ledger);
        let righe_dati: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("7 |"))
            .collect();

        assert_eq!(
            righe_dati.len(),
            1,
            "il record deve occupare una riga sola:\n{text}"
        );
        assert!(righe_dati[0].contains("prima seconda"));
    }

    #[test]
    fn il_corpo_di_un_contenuto_si_accorcia_e_lo_dichiara() {
        let lungo = "a".repeat(MAX_BODY_CHARS * 3);
        let cut = shorten(&lungo);

        assert_eq!(cut.chars().count(), MAX_BODY_CHARS + 1);
        assert!(
            cut.ends_with('\u{2026}'),
            "un testo troncato in silenzio farebbe credere completo un record che non lo e'"
        );
    }

    #[test]
    fn il_corpo_si_accorcia_per_caratteri_e_non_per_byte() {
        // Un taglio a meta' di una sequenza UTF-8 produrrebbe un file che non si
        // apre, ed e' il caso normale per il materiale che questo prodotto
        // acquisisce.
        let lungo: String = "日本語の文章です。".repeat(60);
        assert!(lungo.chars().count() > MAX_BODY_CHARS);

        let ledger = registro(vec![Sheet {
            name: String::from("03 — Contenuti"),
            headers: vec![String::from("id"), String::from("Testo")],
            rows: vec![vec![Cell::Number(1), Cell::Body(lungo)]],
        }]);

        let text = testo(&ledger);
        let Some(riga) = text.lines().find(|line| line.starts_with("1 |")) else {
            panic!("il record deve esserci:\n{text}");
        };
        assert!(riga.ends_with('\u{2026}'));
        assert!(riga.contains("日本語"));
    }

    #[test]
    fn una_spiegazione_lunga_non_si_accorcia() {
        // E' il difetto di FINAL-PRODUCT-REVIEW-01 (FPR-05): la frase che
        // dichiara che cosa un recupero NON vede si interrompeva nei puntini, e
        // chi rilegge il documento fra sei mesi non ha modo di ricostruirla.
        // Ogni cella che non sia il corpo di un contenuto si scrive per intero.
        let spiegazione = format!(
            "Recuperato il 2026-10-09 13:22:58 UTC, per l'intervallo dal 2026-10-01 00:00:00 UTC \
             al 2026-10-09 00:00:00 UTC, da formatore.esercitazione. {}",
            lisi_core::model::RECOVERY_LIMITS
        );
        assert!(
            spiegazione.chars().count() > MAX_BODY_CHARS,
            "la prova non misurerebbe nulla con una frase corta"
        );

        let ledger = registro(vec![Sheet {
            name: String::from("03 — Contenuti"),
            headers: vec![String::from("id"), String::from("Modo di acquisizione")],
            rows: vec![vec![Cell::Number(1), Cell::Text(spiegazione.clone())]],
        }]);

        let text = testo(&ledger);
        assert!(
            text.contains(&spiegazione),
            "la spiegazione e' stata tagliata:\n{text}"
        );
        // Il «…» della testata c'e' e deve esserci: dichiara il taglio del
        // corpo. Quello che non deve esserci e' un taglio NELLA RIGA.
        let Some(riga) = text.lines().find(|line| line.starts_with("1 |")) else {
            panic!("il record deve esserci:\n{text}");
        };
        assert!(
            !riga.contains('\u{2026}'),
            "la riga porta un taglio dove la spiegazione doveva stare intera:\n{riga}"
        );
    }

    #[test]
    fn la_testata_dice_dove_sta_il_testo_completo() {
        // Un «…» che non rimanda a niente e' una perdita; un «…» che rimanda a
        // un documento raggiungibile e' un'abbreviazione.
        let ledger = registro(vec![Sheet {
            name: String::from("03 — Contenuti"),
            headers: vec![String::from("id")],
            rows: vec![vec![Cell::Number(1)]],
        }]);

        let text = testo(&ledger);
        assert!(text.contains("Il corpo dei contenuti è riportato fino a 200 caratteri"));
        assert!(text.contains("allegato tecnico"));
        assert!(text.contains("Ogni altra colonna è scritta"));
    }

    #[test]
    fn le_colonne_senza_alcun_dato_si_dichiarano_una_volta() {
        // Sessanta «non disponibile» su centoquarantotto righe, quasi tutti in
        // quattro colonne vuote per ogni record (FINAL-PRODUCT-REVIEW-01,
        // FPR-06). La riga lo dice una volta; le celle restano, perche' «non
        // disponibile» e «vuoto» sono due affermazioni diverse.
        let vuoto = || Cell::Text(String::from(NOT_AVAILABLE));
        let sheet = Sheet {
            name: String::from("03 — Contenuti"),
            headers: vec![
                String::from("ID"),
                String::from("Autore"),
                String::from("Collegamento"),
                String::from("Livello"),
            ],
            rows: vec![
                vec![Cell::Number(1), vuoto(), vuoto(), Cell::Number(0)],
                vec![Cell::Number(2), vuoto(), vuoto(), Cell::Number(2)],
            ],
        };

        let Some(frase) = empty_columns(&sheet) else {
            panic!("due colonne sono vuote per ogni record: la riga deve esserci");
        };
        assert!(frase.contains("Autore"));
        assert!(frase.contains("Collegamento"));
        assert!(!frase.contains("Livello"), "il livello ha un dato");
        assert!(!frase.contains("ID"), "l'identificativo ha un dato");

        // Le celle non sono state toccate.
        let text = testo(&registro(vec![sheet]));
        assert_eq!(
            text.matches(NOT_AVAILABLE).count(),
            4,
            "le celle devono restare come sono:\n{text}"
        );
    }

    #[test]
    fn una_colonna_con_un_solo_dato_non_si_dichiara_vuota() {
        // La prova negativa: basta un record che porti il dato perche' la
        // colonna NON sia vuota. Dichiararla vuota direbbe una cosa falsa, ed e'
        // il modo in cui una semplificazione perde un'informazione.
        let sheet = Sheet {
            name: String::from("02 — Fonti"),
            headers: vec![String::from("Fonte"), String::from("Identificativo")],
            rows: vec![
                vec![
                    Cell::Text(String::from("Canale X")),
                    Cell::Text(String::from(NOT_AVAILABLE)),
                ],
                vec![
                    Cell::Text(String::from("Canale Y")),
                    Cell::Text(String::from("@canale_y")),
                ],
            ],
        };

        assert_eq!(empty_columns(&sheet), None);
    }

    #[test]
    fn un_foglio_con_un_record_solo_non_riassume_niente() {
        // Con una riga sola la riga si legge per intero, e un riepilogo di una
        // riga e' rumore.
        let sheet = Sheet {
            name: String::from("02 — Fonti"),
            headers: vec![String::from("Fonte"), String::from("Identificativo")],
            rows: vec![vec![
                Cell::Text(String::from("Canale X")),
                Cell::Text(String::from(NOT_AVAILABLE)),
            ]],
        };

        assert_eq!(empty_columns(&sheet), None);
    }

    #[test]
    fn ogni_foglio_porta_nome_intestazioni_e_righe() {
        let ledger = registro(vec![
            Sheet {
                name: String::from("01 — Sessione"),
                headers: vec![String::from("campo"), String::from("valore")],
                rows: vec![vec![
                    Cell::Text(String::from("etichetta")),
                    Cell::Text(String::from("Prova")),
                ]],
            },
            Sheet {
                name: String::from("02 — Fonti"),
                headers: vec![String::from("fonte"), String::from("contenuti")],
                rows: vec![vec![Cell::Text(String::from("Canale X")), Cell::Number(93)]],
            },
        ]);

        let text = testo(&ledger);

        for atteso in [
            "01 — Sessione",
            "02 — Fonti",
            "campo",
            "valore",
            "Canale X",
            "93",
        ] {
            assert!(
                text.contains(atteso),
                "manca «{atteso}» nel registro:\n{text}"
            );
        }

        // Le colonne si separano con la barra spaziata, non con una tabulazione:
        // la tabulazione si rende diversamente in ogni visualizzatore.
        assert!(text.contains(SEPARATOR));
        assert!(!text.contains('\t'), "nessuna tabulazione nel registro");
    }

    #[test]
    fn il_registro_dichiara_la_propria_portata() {
        // La distinzione fra «tutto il monitorato» e «le risultanze scelte» e'
        // la piu' importante del pacchetto (ADR-0031). Un registro che non la
        // dichiarasse potrebbe essere letto come la relazione.
        let ledger = registro(vec![Sheet {
            name: String::from("01 — Sessione"),
            headers: vec![String::from("campo")],
            rows: vec![vec![Cell::Text(String::from("x"))]],
        }]);

        let text = testo(&ledger);
        assert!(text.contains("TUTTO il monitorato"));
        assert!(text.contains("livello 0 compreso"));
        assert!(text.contains("non le sole"));
    }
}

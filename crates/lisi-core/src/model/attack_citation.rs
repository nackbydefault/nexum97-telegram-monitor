//! Gli identificativi ATT&CK citati nel testo di un contenuto (ATTACK-03,
//! ADR-0185).
//!
//! # Una citazione non è un'associazione
//!
//! Chi scrive `T1059` in un messaggio **nomina** una tecnica. L'ufficio che
//! dichiara un'associazione (ADR-0059) **afferma** qualcosa, con un motivo.
//! Le due cose restano distinte: questo modulo trova le citazioni e compone la
//! loro frase, e nient'altro. Non alza un livello, non crea un'associazione,
//! non produce un avviso (decisione 3); una prova lo sorveglia.
//!
//! # Senza espressioni regolari
//!
//! Il riconoscitore è un automa scritto a mano, che guarda ogni carattere una
//! volta sola: il tempo cresce con il testo, qualunque testo (decisione 1).

use crate::model::attack::AttackTechniqueId;

/// Quante citazioni si riconoscono al più in un contenuto.
pub const MAX_CITATIONS: usize = 10;

/// Le tecniche citate nel testo, nell'ordine in cui compaiono, senza
/// ripetizioni, al più [`MAX_CITATIONS`].
///
/// Una citazione è `T` maiuscola, quattro cifre e, facoltativa, la
/// sotto-tecnica `.` più tre cifre; prima e dopo non c'è una lettera o una
/// cifra. `T10590`, `AT1059` e `T1059.01` non sono citazioni.
#[must_use]
pub fn cited_techniques(text: &str) -> Vec<AttackTechniqueId> {
    let caratteri: Vec<char> = text.chars().collect();
    let mut trovate: Vec<AttackTechniqueId> = Vec::new();
    let mut indice = 0;
    while indice < caratteri.len() && trovate.len() < MAX_CITATIONS {
        let prima_libera = indice == 0 || !caratteri[indice - 1].is_alphanumeric();
        if caratteri[indice] != 'T' || !prima_libera {
            indice += 1;
            continue;
        }
        let cifre = |da: usize, quante: usize| {
            caratteri.len() >= da + quante
                && caratteri[da..da + quante].iter().all(char::is_ascii_digit)
        };
        if !cifre(indice + 1, 4) {
            indice += 1;
            continue;
        }
        let mut fine = indice + 5;
        if caratteri.get(fine) == Some(&'.') && cifre(fine + 1, 3) {
            fine += 4;
        }
        if caratteri.get(fine).is_some_and(|c| c.is_alphanumeric()) {
            indice = fine;
            continue;
        }
        let testo: String = caratteri[indice..fine].iter().collect();
        if let Ok(id) = AttackTechniqueId::try_new(&testo)
            && !trovate.contains(&id)
        {
            trovate.push(id);
        }
        indice = fine;
    }
    trovate
}

/// La frase delle citazioni di un contenuto (decisione 2). Ogni tecnica porta
/// il nome che ha nella fotografia indicata, o dice che la fotografia non la
/// conosce; senza fotografia, si dice anche questo. Vuota se non c'è niente.
#[must_use]
pub fn citation_sentence(
    cited: &[(AttackTechniqueId, Option<String>)],
    snapshot: Option<&str>,
) -> String {
    if cited.is_empty() {
        return String::new();
    }
    let elenco = cited
        .iter()
        .map(|(id, nome)| match (nome, snapshot) {
            (Some(nome), _) => format!("{} ({nome})", id.as_str()),
            (None, Some(_)) => format!("{} (che la fotografia non conosce)", id.as_str()),
            (None, None) => id.as_str().to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let fonte = snapshot.map_or_else(
        || String::from(" Nessuna fotografia ATT&CK è stata importata."),
        |versione| format!(" Nomi dalla fotografia ATT&CK {versione}."),
    );
    format!(
        "Il testo cita {elenco}. È una citazione di chi ha scritto, non un'associazione \
         dell'ufficio.{fonte}"
    )
}

#[cfg(test)]
mod tests {
    use super::{MAX_CITATIONS, citation_sentence, cited_techniques};
    use crate::model::attack::AttackTechniqueId;

    fn ids(testo: &str) -> Vec<String> {
        cited_techniques(testo)
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    /// **Una citazione ha confini** (ADR-0185, decisione 1): la tecnica e la
    /// sotto-tecnica si riconoscono, una forma che continua no, una ripetuta
    /// una volta sola.
    #[test]
    fn una_citazione_ha_confini() {
        assert_eq!(
            ids("Usano T1059 e poi T1566.001, di nuovo T1059."),
            ["T1059", "T1566.001"]
        );
        assert_eq!(ids("(T1003)"), ["T1003"]);
        for niente in ["T10590", "AT1059", "t1059", "T105", "codiceT1059", "T1059a"] {
            assert!(ids(niente).is_empty(), "«{niente}» non è una citazione");
        }
        assert_eq!(
            ids("T1059.01 resta"),
            ["T1059"],
            "la sotto-tecnica a due cifre non c'è"
        );
    }

    /// **Un tetto, e un tempo che cresce con il testo** (decisione 1): un
    /// testo costruito per far lavorare il riconoscitore non lo rallenta più
    /// di quanto è lungo.
    #[test]
    fn un_tetto_e_un_tempo_lineare() {
        let molte: String = (1000..1100).map(|n| format!("T{n} ")).collect();
        assert_eq!(cited_techniques(&molte).len(), MAX_CITATIONS);

        let ostile = "T1".repeat(200_000);
        let inizio = std::time::Instant::now();
        assert!(cited_techniques(&ostile).is_empty());
        assert!(
            inizio.elapsed() < std::time::Duration::from_secs(2),
            "il riconoscitore non deve rallentare su un testo costruito apposta"
        );
    }

    /// **La frase dice che è una citazione** (decisione 2).
    #[test]
    fn la_frase_dice_che_e_una_citazione() {
        let (Ok(a), Ok(b)) = (
            AttackTechniqueId::try_new("T1059"),
            AttackTechniqueId::try_new("T9999"),
        ) else {
            panic!("identificativi validi");
        };
        let frase = citation_sentence(
            &[
                (
                    a.clone(),
                    Some(String::from("Command and Scripting Interpreter")),
                ),
                (b, None),
            ],
            Some("19.2"),
        );
        assert!(frase.contains("T1059 (Command and Scripting Interpreter)"));
        assert!(frase.contains("T9999 (che la fotografia non conosce)"));
        assert!(frase.contains("non un'associazione dell'ufficio"));
        assert!(citation_sentence(&[(a, None)], None).contains("Nessuna fotografia"));
        assert_eq!(citation_sentence(&[], Some("19.2")), "");
    }

    /// **Una citazione non cambia niente** (ADR-0185, decisione 3): il
    /// riconoscitore lo chiama soltanto lo Storico, per mostrare la frase.
    /// Il riscontro, i livelli, gli avvisi, le associazioni e i documenti non
    /// lo conoscono; se uno di loro lo chiamasse, questa prova diventerebbe
    /// rossa.
    #[test]
    fn una_citazione_non_cambia_niente() {
        const AMMESSI: [&str; 3] = [
            "lisi-core/src/model/attack_citation.rs",
            "lisi-core/src/model/mod.rs",
            "lisi-app/src/history.rs",
        ];
        let radice = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut da_vedere = vec![radice.clone()];
        let mut visti = 0;
        while let Some(cartella) = da_vedere.pop() {
            let Ok(voci) = std::fs::read_dir(&cartella) else {
                continue;
            };
            for voce in voci.flatten() {
                let percorso = voce.path();
                if percorso.is_dir() {
                    if !percorso.ends_with("target") && !percorso.ends_with("tests") {
                        da_vedere.push(percorso);
                    }
                    continue;
                }
                if percorso.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let Ok(testo) = std::fs::read_to_string(&percorso) else {
                    continue;
                };
                let produzione = testo
                    .split_once("\n#[cfg(test)]")
                    .map_or(testo.as_str(), |(prima, _)| prima);
                if !produzione.contains("attack_citation") {
                    continue;
                }
                let relativo = percorso
                    .strip_prefix(&radice)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                assert!(
                    AMMESSI.contains(&relativo.as_str()),
                    "{relativo} usa le citazioni ATT&CK: una citazione si mostra e basta"
                );
                visti += 1;
            }
        }
        assert!(
            visti >= 2,
            "la prova non trova più chi usa le citazioni: {visti}"
        );
    }
}

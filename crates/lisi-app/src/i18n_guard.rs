//! La guardia per lingua (I18N-01, ADR-0197, decisione 6).
//!
//! Le regole di ADR-0117 restano sull'italiano, in `plain_italian_guard.rs`.
//! Qui si prova ogni altra lingua, catalogo per catalogo:
//!
//! - ogni testo scritto `@tr("…")` nei file `.slint`, e ogni testo passato
//!   per esteso a `lingua::tr` o `lingua::tr_con` nel Rust, ha la sua voce;
//! - nessuna voce traduce un testo che non esiste più;
//! - ogni voce è tradotta, salvo le avvertenze di sicurezza in attesa di
//!   revisione;
//! - una traduzione porta gli stessi segnaposto della frase italiana, nessun
//!   `**`, nessuna frase oltre le venticinque parole;
//! - **un'avvertenza di sicurezza si traduce soltanto con una traduzione
//!   rivista da una persona, e identica** (`security_translations`).
//!
//! Una guardia che non guarda niente passa sempre (ADR-0111): ogni prova
//! dichiara un minimo di ciò che deve aver letto.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lisi_core::glossary::{MAX_SENTENCE_WORDS, long_sentences};
    use lisi_core::model::language::InterfaceLanguage;
    use lisi_core::security_messages::SECURITY_MESSAGES;
    use lisi_core::security_translations;

    use crate::lingua::CATALOGUES;
    use crate::surface_text::{SCHERMATE, sorgenti_del_prodotto};

    /// I testi del Rust che non si possono tradurre, con la ragione. Restano
    /// in italiano anche nell'interfaccia inglese; ciascuno deve esistere.
    const NON_TRADUCIBILI: &[(&str, &str)] = &[(
        "Fotografia presa da {} il {}, per questa ragione: «{}». Conserva ciò che Telegram \
         mostrava il {}: {} messagg{} attorno al contenuto {}. Non è una prova acquisita: è \
         un'osservazione documentata, e la prova resta il testo dell'archivio.",
        "compone una desinenza italiana dentro una parola, «messagg» più «io» o «i»: in \
         un'altra lingua il valore finirebbe a metà di una parola",
    )];

    /// I testi del Rust che la guardia dell'italiano misura come superficie:
    /// ciò che `lingua::schermo` può incontrare al confine (I18N-01, parte 3).
    fn testi_rust_di_superficie() -> Vec<String> {
        crate::plain_italian_guard::tests::superficie()
            .into_iter()
            .filter(|voce| {
                !voce.dove.contains(".slint:")
                    && !voce.dove.starts_with("glossario")
                    && !voce.dove.starts_with("SIC-")
            })
            .map(|voce| voce.testo)
            .collect()
    }

    /// **Ogni testo del Rust che arriva allo schermo ha la sua voce**, salvo
    /// le eccezioni dichiarate e le avvertenze di sicurezza.
    #[test]
    fn ogni_testo_del_rust_ha_la_sua_voce() {
        let rust = testi_rust_di_superficie();
        assert!(rust.len() >= 3000, "testi del Rust letti: {}", rust.len());
        for lingua in lingue() {
            let voci = voci(lingua);
            let mancanti: Vec<&String> = rust
                .iter()
                .filter(|testo| !voci.contains_key(testo.as_str()))
                .filter(|testo| !NON_TRADUCIBILI.iter().any(|(t, _)| t == testo))
                .filter(|testo| {
                    !SECURITY_MESSAGES.iter().any(|m| {
                        m.current.text == testo.as_str()
                            || m.current.technical_detail == testo.as_str()
                    })
                })
                .collect();
            assert!(
                mancanti.is_empty(),
                "{lingua}: {} testi del Rust senza voce nel catalogo:\n{mancanti:#?}",
                mancanti.len()
            );
        }
    }

    /// **Un'eccezione dichiarata esiste, e il catalogo non la traduce.**
    #[test]
    fn ogni_eccezione_esiste_e_resta_italiana() {
        let rust = testi_rust_di_superficie();
        for (testo, ragione) in NON_TRADUCIBILI {
            assert!(
                rust.iter().any(|t| t == testo),
                "l'eccezione «{ragione}» non trova più il suo testo: va tolta"
            );
            for lingua in lingue() {
                assert!(!voci(lingua).contains_key(testo), "{lingua}: {ragione}");
            }
        }
    }

    /// I testi che arrivano a `lingua::tr` attraverso una funzione e non per
    /// esteso: la guardia non li vede nella chiamata, e li elenca qui.
    fn tradotti_per_riferimento() -> Vec<&'static str> {
        InterfaceLanguage::all()
            .iter()
            .map(InterfaceLanguage::consequence)
            .collect()
    }

    /// Legge un letterale che comincia dopo le virgolette d'apertura.
    ///
    /// `rust`: la barra rovesciata a fine riga continua il testo saltando il
    /// rientro, come fa il compilatore.
    fn letterale(resto: &str, rust: bool) -> Option<String> {
        let mut testo = String::new();
        let mut caratteri = resto.chars().peekable();
        while let Some(carattere) = caratteri.next() {
            match carattere {
                '"' => return Some(testo),
                '\\' => match caratteri.next()? {
                    'n' => testo.push('\n'),
                    't' => testo.push('\t'),
                    'u' => {
                        if caratteri.next() != Some('{') {
                            return None;
                        }
                        let cifre: String = caratteri.by_ref().take_while(|c| *c != '}').collect();
                        testo.push(char::from_u32(u32::from_str_radix(&cifre, 16).ok()?)?);
                    }
                    '\n' if rust => {
                        while caratteri.peek().is_some_and(|c| c.is_whitespace()) {
                            caratteri.next();
                        }
                    }
                    '\r' if rust => {
                        caratteri.next();
                        while caratteri.peek().is_some_and(|c| c.is_whitespace()) {
                            caratteri.next();
                        }
                    }
                    altro => testo.push(altro),
                },
                altro => testo.push(altro),
            }
        }
        None
    }

    /// Ogni letterale che segue uno dei segni d'apertura, con il luogo.
    fn letterali_dopo(sorgente: &str, aperture: &[&str], rust: bool) -> Vec<String> {
        let mut trovati = Vec::new();
        for apertura in aperture {
            let mut da = 0;
            while let Some(posizione) = sorgente.get(da..).and_then(|resto| resto.find(apertura)) {
                let inizio = da + posizione + apertura.len();
                let dopo = sorgente.get(inizio..).unwrap_or("");
                // Il letterale può cominciare sulla riga dopo, come lo manda a
                // capo `rustfmt`.
                let senza_spazi = dopo.trim_start();
                if let Some(resto) = senza_spazi.strip_prefix('"')
                    && let Some(testo) = letterale(resto, rust)
                {
                    trovati.push(testo);
                }
                da = inizio;
            }
        }
        trovati
    }

    /// I testi che l'interfaccia Slint fa tradurre.
    fn testi_slint_tradotti() -> Vec<String> {
        SCHERMATE
            .iter()
            .flat_map(|(_, sorgente)| letterali_dopo(sorgente, &["@tr("], false))
            .collect()
    }

    /// I testi che il Rust fa tradurre per esteso.
    fn testi_rust_tradotti() -> Vec<String> {
        sorgenti_del_prodotto()
            .into_iter()
            .flat_map(|(_, sorgente)| {
                letterali_dopo(
                    &sorgente,
                    &["lingua::tr(", "lingua::tr_con(", "lingua::tr_in("],
                    true,
                )
            })
            .collect()
    }

    /// I segnaposto di un testo, come li legge Slint: `{}` e `{0}`, senza le
    /// graffe raddoppiate.
    fn segnaposto(testo: &str) -> Vec<String> {
        let mut trovati = Vec::new();
        let mut caratteri = testo.chars().peekable();
        while let Some(carattere) = caratteri.next() {
            match carattere {
                '{' if caratteri.peek() == Some(&'{') => {
                    caratteri.next();
                }
                '}' if caratteri.peek() == Some(&'}') => {
                    caratteri.next();
                }
                '{' => {
                    let dentro: String = caratteri.by_ref().take_while(|c| *c != '}').collect();
                    trovati.push(dentro);
                }
                _ => {}
            }
        }
        trovati.sort();
        trovati
    }

    /// Le voci di un catalogo, per testo italiano.
    fn voci(lingua: &str) -> BTreeMap<&'static str, (&'static str, bool)> {
        CATALOGUES
            .iter()
            .find(|(nome, _)| *nome == lingua)
            .map(|(_, voci)| {
                voci.iter()
                    .map(|(originale, traduzione, tradotta)| (*originale, (*traduzione, *tradotta)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Le lingue con un catalogo: tutte tranne l'italiano.
    fn lingue() -> Vec<&'static str> {
        let lingue: Vec<&'static str> = InterfaceLanguage::all()
            .iter()
            .filter(|lingua| lingua.translates())
            .map(InterfaceLanguage::as_str)
            .collect();
        assert!(!lingue.is_empty(), "nessuna lingua oltre l'italiano");
        lingue
    }

    /// **Ogni lingua offerta ha il suo catalogo, e il catalogo non è vuoto.**
    #[test]
    fn ogni_lingua_offerta_ha_il_suo_catalogo() {
        for lingua in lingue() {
            let voci = voci(lingua);
            let tradotte = voci.values().filter(|(_, tradotta)| *tradotta).count();
            assert!(
                tradotte >= 40,
                "{lingua}: {tradotte} voci tradotte; il catalogo non è stato incorporato"
            );
        }
    }

    /// **Ogni testo che l'interfaccia fa tradurre ha la sua voce.**
    #[test]
    fn ogni_testo_tradotto_ha_la_sua_voce() {
        let slint = testi_slint_tradotti();
        let rust = testi_rust_tradotti();
        assert!(slint.len() >= 70, "testi @tr letti: {}", slint.len());
        assert!(!rust.is_empty(), "testi lingua::tr letti: {}", rust.len());
        for lingua in lingue() {
            let voci = voci(lingua);
            let mancanti: Vec<&String> = slint
                .iter()
                .chain(rust.iter())
                .filter(|testo| !voci.contains_key(testo.as_str()))
                .collect();
            let per_riferimento: Vec<&str> = tradotti_per_riferimento()
                .into_iter()
                .filter(|testo| !voci.contains_key(testo))
                .collect();
            assert!(
                mancanti.is_empty() && per_riferimento.is_empty(),
                "{lingua}: testi senza voce nel catalogo:\n{mancanti:#?}\n{per_riferimento:#?}"
            );
        }
    }

    /// **Nessuna voce traduce un testo che non esiste più.**
    #[test]
    fn nessuna_voce_traduce_un_testo_che_non_esiste() {
        let mut esistenti: Vec<String> = testi_slint_tradotti();
        esistenti.extend(testi_rust_tradotti());
        esistenti.extend(testi_rust_di_superficie());
        esistenti.extend(tradotti_per_riferimento().into_iter().map(String::from));
        for messaggio in SECURITY_MESSAGES {
            esistenti.push(messaggio.current.text.to_owned());
            esistenti.push(messaggio.current.technical_detail.to_owned());
        }
        for lingua in lingue() {
            let orfane: Vec<&str> = voci(lingua)
                .into_keys()
                .filter(|originale| !originale.is_empty())
                .filter(|originale| !esistenti.iter().any(|testo| testo == originale))
                .collect();
            assert!(
                orfane.is_empty(),
                "{lingua}: voci che nessun testo usa più, da togliere:\n{orfane:#?}"
            );
        }
    }

    /// **Ogni voce è tradotta**, salvo le avvertenze in attesa di revisione.
    #[test]
    fn ogni_voce_e_tradotta_salvo_le_avvertenze_da_rivedere() {
        for lingua in lingue() {
            let da_tradurre: Vec<&str> = voci(lingua)
                .into_iter()
                .filter(|(originale, (_, tradotta))| !originale.is_empty() && !tradotta)
                .filter(|(originale, _)| {
                    !SECURITY_MESSAGES.iter().any(|messaggio| {
                        messaggio.current.text == *originale
                            || messaggio.current.technical_detail == *originale
                    })
                })
                .map(|(originale, _)| originale)
                .collect();
            assert!(
                da_tradurre.is_empty(),
                "{lingua}: voci senza traduzione:\n{da_tradurre:#?}"
            );
        }
    }

    /// **Una traduzione porta gli stessi segnaposto, nessun `**`, frasi brevi.**
    #[test]
    fn una_traduzione_rispetta_le_regole_della_superficie() {
        let mut difetti = Vec::new();
        let mut lette = 0usize;
        for lingua in lingue() {
            for (originale, (traduzione, tradotta)) in voci(lingua) {
                if !tradotta || originale.is_empty() {
                    continue;
                }
                lette += 1;
                if segnaposto(originale) != segnaposto(traduzione) {
                    difetti.push(format!("{lingua}: segnaposto diversi in «{traduzione}»"));
                }
                if traduzione.contains("**") {
                    difetti.push(format!("{lingua}: «**» in «{traduzione}»"));
                }
                for frase in long_sentences(traduzione) {
                    difetti.push(format!(
                        "{lingua}: frase oltre {MAX_SENTENCE_WORDS} parole: {frase}"
                    ));
                }
            }
        }
        assert!(lette >= 40, "traduzioni lette: {lette}");
        assert!(difetti.is_empty(), "{difetti:#?}");
    }

    /// **Un'avvertenza di sicurezza si traduce soltanto se una persona ha
    /// riletto la traduzione, così com'è.**
    ///
    /// È il criterio di F-212: una traduzione che cambia il senso di
    /// un'avvertenza è il rischio che questa milestone deve evitare.
    #[test]
    fn un_avvertenza_si_traduce_solo_dopo_la_revisione() {
        let mut controllate = 0usize;
        for lingua in lingue() {
            let voci = voci(lingua);
            for messaggio in SECURITY_MESSAGES {
                let rivista = security_translations::reviewed(messaggio.code, lingua);
                for (originale, atteso) in [
                    (messaggio.current.text, rivista.map(|t| t.text)),
                    (
                        messaggio.current.technical_detail,
                        rivista.map(|t| t.technical_detail),
                    ),
                ] {
                    let Some((traduzione, tradotta)) = voci.get(originale) else {
                        continue;
                    };
                    controllate += 1;
                    if !tradotta {
                        continue;
                    }
                    assert_eq!(
                        Some(*traduzione),
                        atteso,
                        "{lingua}, {}: il catalogo traduce un'avvertenza senza una traduzione \
                         rivista e identica in security_translations (HVQ-165)",
                        messaggio.code
                    );
                }
            }
        }
        assert!(
            controllate >= 30,
            "voci di avvertenze lette: {controllate}; le avvertenze scritte nell'interfaccia \
             devono passare da @tr"
        );
    }

    /// **Le regole si vedono rosse su un catalogo sbagliato.**
    #[test]
    fn le_regole_riconoscono_un_errore() {
        assert_eq!(segnaposto("{} di {}"), segnaposto("{} of {}"));
        assert_ne!(segnaposto("{} di {}"), segnaposto("{} of"));
        assert_eq!(segnaposto("{{non}} {0}"), vec![String::from("0")]);
        assert_eq!(
            letterali_dopo("x: @tr(\"Una \\\"prova\\\"\");", &["@tr("], false),
            vec![String::from("Una \"prova\"")]
        );
        assert_eq!(
            letterali_dopo("tr(\n    \"Uno \\\n     due\",\n)", &["tr("], true),
            vec![String::from("Uno due")]
        );
    }
}

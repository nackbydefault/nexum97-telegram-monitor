//! La lingua dell'interfaccia (I18N-01, ADR-0197).
//!
//! # Un catalogo solo, due lettori
//!
//! Il catalogo di una lingua sta in
//! `translations/<lingua>/LC_MESSAGES/lisi-telegram-monitor.po`. Slint lo
//! incorpora nell'interfaccia e traduce i testi scritti `@tr("…")`; per i testi
//! che nascono nel Rust, `build.rs` lo legge con lo stesso lettore e ne scrive
//! una tabella ordinata, che questo modulo consulta.
//!
//! La chiave è il testo italiano. Senza traduzione, o con l'italiano scelto,
//! [`tr`] restituisce il testo così com'è: tradurre non cambia niente per chi
//! non cambia lingua.
//!
//! # I segnaposto
//!
//! Nei testi dei file `.slint` sono quelli di Slint: `{}` prende il valore
//! successivo, `{0}` quello indicato, `{{` e `}}` scrivono una graffa. Nei
//! testi del Rust sono quelli di `format!`, anche con un nome: `{gesto}`. Una
//! traduzione può spostarli, non toglierli: la guardia per lingua lo verifica.
//!
//! # I testi del Rust si traducono al confine (I18N-01, parte 3)
//!
//! Le funzioni di `lisi-core` e `lisi-services` che compongono una frase per
//! lo schermo scrivono spesso la stessa frase nei documenti, che restano in
//! italiano. Per questo non traducono: traduce [`schermo`], qui, quando il
//! testo entra nella finestra. Una frase fissa si cerca per intero; una frase
//! composta si riconosce dal suo modello — i pezzi fissi nell'ordine, i
//! valori al posto dei segnaposto — e i valori passano nel modello tradotto.
//! Ciò che non si riconosce resta in italiano: si vede, e la guardia per
//! lingua conta i testi del Rust che il catalogo non ha.
//!
//! # Le avvertenze di sicurezza
//!
//! Il catalogo non traduce un messaggio di sicurezza senza una traduzione
//! rivista da una persona e identica (`lisi_core::security_translations`): la
//! guardia rende rosso il catalogo che lo fa. Questo modulo non deve saperlo,
//! e non lo sa.

use std::sync::atomic::{AtomicUsize, Ordering};

use lisi_core::model::language::InterfaceLanguage;

mod generato {
    /// Una voce del catalogo: testo italiano, traduzione, se è tradotta.
    pub(crate) type Voce = (&'static str, &'static str, bool);

    include!(concat!(env!("OUT_DIR"), "/catalogues.rs"));
}

pub(crate) use generato::CATALOGUES;

/// La lingua in vigore, come posizione in [`InterfaceLanguage::all`].
///
/// Atomica perché un testo si può comporre anche fuori dal filo
/// dell'interfaccia; la scelta la cambia soltanto [`applica`].
static IN_VIGORE: AtomicUsize = AtomicUsize::new(0);

/// La lingua in vigore.
pub fn corrente() -> InterfaceLanguage {
    InterfaceLanguage::all()
        .get(IN_VIGORE.load(Ordering::Relaxed))
        .copied()
        .unwrap_or_default()
}

/// Mette in vigore una lingua, per l'interfaccia e per il Rust.
///
/// Va chiamata dopo la creazione della finestra: Slint sceglie da solo la
/// lingua del sistema, se ne trova una incorporata, e la scelta della
/// postazione deve prevalere (ADR-0197, decisione 4).
pub fn applica(lingua: InterfaceLanguage) {
    let posizione = InterfaceLanguage::all()
        .iter()
        .position(|candidata| *candidata == lingua)
        .unwrap_or(0);
    IN_VIGORE.store(posizione, Ordering::Relaxed);

    // L'italiano è la lingua di partenza: per Slint è la stringa vuota.
    let codice = if lingua.translates() {
        lingua.as_str()
    } else {
        ""
    };
    if let Err(errore) = slint::select_bundled_translation(codice) {
        tracing::warn!(errore = %errore, lingua = codice, "lingua dell'interfaccia non applicata");
    }
}

/// La traduzione di un testo italiano nella lingua `lingua`, se il catalogo
/// ne ha una.
fn cerca(lingua: &str, testo: &str) -> Option<&'static str> {
    let (_, voci) = CATALOGUES.iter().find(|(nome, _)| *nome == lingua)?;
    let posizione = voci
        .binary_search_by(|(originale, _, _)| (*originale).cmp(testo))
        .ok()?;
    voci.get(posizione)
        .filter(|(_, _, tradotta)| *tradotta)
        .map(|(_, traduzione, _)| *traduzione)
}

/// Il testo nella lingua in vigore.
///
/// Senza traduzione resta il testo italiano.
pub fn tr(testo: &str) -> &str {
    tr_in(corrente(), testo)
}

/// Il testo in una lingua data. Serve alle prove, che non cambiano la lingua
/// del programma.
pub fn tr_in(lingua: InterfaceLanguage, testo: &str) -> &str {
    if !lingua.translates() {
        return testo;
    }
    cerca(lingua.as_str(), testo).unwrap_or(testo)
}

/// Un pezzo di un modello: testo fisso o segnaposto con il suo nome (vuoto
/// per `{}`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pezzo {
    Fisso(String),
    Valore(String),
}

/// Divide un modello nei suoi pezzi. `{{` e `}}` sono graffe scritte.
fn pezzi(modello: &str) -> Vec<Pezzo> {
    let mut pezzi = Vec::new();
    let mut fisso = String::new();
    let mut caratteri = modello.chars().peekable();
    while let Some(carattere) = caratteri.next() {
        match carattere {
            '{' if caratteri.peek() == Some(&'{') => {
                caratteri.next();
                fisso.push('{');
            }
            '}' if caratteri.peek() == Some(&'}') => {
                caratteri.next();
                fisso.push('}');
            }
            '{' => {
                let dentro: String = caratteri.by_ref().take_while(|c| *c != '}').collect();
                // `{nome:?}`, `{:>3}`: conta il nome, non il formato.
                let nome = dentro.split(':').next().unwrap_or_default().to_owned();
                if !fisso.is_empty() {
                    pezzi.push(Pezzo::Fisso(std::mem::take(&mut fisso)));
                }
                pezzi.push(Pezzo::Valore(nome));
            }
            altro => fisso.push(altro),
        }
    }
    if !fisso.is_empty() {
        pezzi.push(Pezzo::Fisso(fisso));
    }
    pezzi
}

/// I valori di `testo` se ha la forma del modello: i pezzi fissi nell'ordine,
/// ciascun valore il più corto possibile e mai vuoto.
fn valori<'a>(modello: &[Pezzo], testo: &'a str) -> Option<Vec<&'a str>> {
    let mut valori = Vec::new();
    let mut resto = testo;
    let mut iteratore = modello.iter().peekable();
    while let Some(pezzo) = iteratore.next() {
        match pezzo {
            Pezzo::Fisso(fisso) => resto = resto.strip_prefix(fisso.as_str())?,
            Pezzo::Valore(_) => match iteratore.peek() {
                // L'ultimo valore prende tutto ciò che resta.
                None => {
                    if resto.is_empty() {
                        return None;
                    }
                    valori.push(resto);
                    resto = "";
                }
                Some(Pezzo::Fisso(seguente)) => {
                    // Il più corto: la prima occorrenza dopo almeno un carattere.
                    let primo = resto.chars().next()?.len_utf8();
                    let dove = resto.get(primo..)?.find(seguente.as_str())? + primo;
                    valori.push(resto.get(..dove)?);
                    resto = resto.get(dove..)?;
                }
                // Due segnaposto attaccati non si separano: il modello non vale.
                Some(Pezzo::Valore(_)) => return None,
            },
        }
    }
    resto.is_empty().then_some(valori)
}

/// I modelli di una lingua: le voci tradotte con almeno un segnaposto e con
/// del testo fisso che contiene una lettera.
type Modelli = Vec<(Vec<Pezzo>, Vec<Pezzo>, usize)>;

fn modelli(lingua: &str) -> Option<&'static Modelli> {
    static TUTTI: std::sync::LazyLock<Vec<(&'static str, Modelli)>> =
        std::sync::LazyLock::new(|| {
            CATALOGUES
                .iter()
                .map(|(lingua, voci)| {
                    let modelli = voci
                        .iter()
                        .filter(|(_, _, tradotta)| *tradotta)
                        .filter_map(|(originale, traduzione, _)| {
                            let sorgente = pezzi(originale);
                            let fisso: usize = sorgente
                                .iter()
                                .map(|pezzo| match pezzo {
                                    Pezzo::Fisso(testo)
                                        if testo.chars().any(char::is_alphabetic) =>
                                    {
                                        testo.chars().count()
                                    }
                                    _ => 0,
                                })
                                .sum();
                            let con_valori = sorgente.iter().any(|p| matches!(p, Pezzo::Valore(_)));
                            (con_valori && fisso > 0).then(|| (sorgente, pezzi(traduzione), fisso))
                        })
                        .collect();
                    (*lingua, modelli)
                })
                .collect()
        });
    TUTTI
        .iter()
        .find(|(nome, _)| *nome == lingua)
        .map(|(_, modelli)| modelli)
}

/// Rimette i valori nel modello tradotto: per nome se il modello li nomina,
/// altrimenti nell'ordine. I valori non si traducono.
fn ricomponi(sorgente: &[Pezzo], traduzione: &[Pezzo], valori: &[&str]) -> String {
    let nomi: Vec<&str> = sorgente
        .iter()
        .filter_map(|pezzo| match pezzo {
            Pezzo::Valore(nome) => Some(nome.as_str()),
            Pezzo::Fisso(_) => None,
        })
        .collect();
    let mut risultato = String::new();
    let mut successivo = 0usize;
    for pezzo in traduzione {
        match pezzo {
            Pezzo::Fisso(testo) => risultato.push_str(testo),
            Pezzo::Valore(nome) => {
                let indice = if nome.is_empty() {
                    let indice = successivo;
                    successivo += 1;
                    Some(indice)
                } else if let Ok(numero) = nome.parse::<usize>() {
                    Some(numero)
                } else {
                    nomi.iter().position(|candidato| candidato == nome)
                };
                // Un valore resta com'è: può essere un dato — il nome di una
                // fonte, un estratto, un termine — e un dato non si traduce.
                let valore = indice
                    .and_then(|indice| valori.get(indice))
                    .copied()
                    .unwrap_or("");
                risultato.push_str(valore);
            }
        }
    }
    risultato
}

/// Il testo nella lingua `lingua`: per intero, oppure dal suo modello.
fn traduci(lingua: InterfaceLanguage, testo: &str) -> std::borrow::Cow<'_, str> {
    if !lingua.translates() || testo.is_empty() {
        return std::borrow::Cow::Borrowed(testo);
    }
    if let Some(intera) = cerca(lingua.as_str(), testo) {
        return std::borrow::Cow::Borrowed(intera);
    }
    let Some(modelli) = modelli(lingua.as_str()) else {
        return std::borrow::Cow::Borrowed(testo);
    };
    modelli
        .iter()
        .filter_map(|(sorgente, traduzione, fisso)| {
            valori(sorgente, testo).map(|valori| (sorgente, traduzione, *fisso, valori))
        })
        .max_by_key(|(_, _, fisso, _)| *fisso)
        .map_or(
            std::borrow::Cow::Borrowed(testo),
            |(sorgente, traduzione, _, valori)| {
                std::borrow::Cow::Owned(ricomponi(sorgente, traduzione, &valori))
            },
        )
}

/// Il testo che entra nella finestra, nella lingua in vigore.
///
/// È il confine (I18N-01, parte 3): ogni testo che `lisi-app` passa
/// all'interfaccia passa da qui. Con l'italiano è il testo così com'è.
pub fn schermo(testo: impl AsRef<str>) -> slint::SharedString {
    slint::SharedString::from(traduci(corrente(), testo.as_ref()).as_ref())
}

#[cfg(test)]
mod tests {
    use super::{CATALOGUES, Pezzo, pezzi, tr_in, traduci, valori};
    use lisi_core::model::language::InterfaceLanguage;

    #[test]
    fn l_italiano_non_traduce_niente() {
        assert_eq!(
            tr_in(InterfaceLanguage::Italian, "Impostazioni"),
            "Impostazioni"
        );
    }

    #[test]
    fn il_catalogo_inglese_e_incorporato_e_traduce() {
        assert!(
            CATALOGUES.iter().any(|(lingua, _)| *lingua == "en"),
            "il catalogo inglese non è stato incorporato"
        );
        assert_eq!(
            tr_in(InterfaceLanguage::English, "Impostazioni"),
            "Settings"
        );
    }

    #[test]
    fn un_testo_senza_voce_resta_italiano() {
        assert_eq!(
            tr_in(
                InterfaceLanguage::English,
                "Una frase che nessun catalogo contiene"
            ),
            "Una frase che nessun catalogo contiene"
        );
    }

    #[test]
    fn la_tabella_e_ordinata_per_la_ricerca() {
        for (lingua, voci) in CATALOGUES {
            assert!(
                voci.windows(2).all(|coppia| match coppia {
                    [prima, dopo] => prima.0 < dopo.0,
                    _ => true,
                }),
                "{lingua}: voci non ordinate o ripetute"
            );
        }
    }

    #[test]
    fn un_modello_si_divide_in_pezzi_fissi_e_valori() {
        assert_eq!(
            pezzi("{gesto} non si prova: {{x}} {n:?}"),
            vec![
                Pezzo::Valore(String::from("gesto")),
                Pezzo::Fisso(String::from(" non si prova: {x} ")),
                Pezzo::Valore(String::from("n")),
            ]
        );
    }

    #[test]
    fn i_valori_si_ritrovano_soltanto_se_la_forma_torna() {
        let modello = pezzi("{} di {} fonti");
        assert_eq!(valori(&modello, "3 di 10 fonti"), Some(vec!["3", "10"]));
        assert_eq!(valori(&modello, "3 di 10 contenuti"), None);
        assert_eq!(valori(&modello, " di 10 fonti"), None);
    }

    #[test]
    fn una_frase_composta_si_traduce_dal_suo_modello() {
        // «Stato: {}» è una voce dell'interfaccia. Il valore resta com'è,
        // anche quando coincide con un'altra voce: può essere un dato.
        assert_eq!(
            traduci(InterfaceLanguage::English, "Stato: In esame"),
            "State: In esame"
        );
        assert_eq!(
            traduci(InterfaceLanguage::English, "Stato: qualcosa di nuovo"),
            "State: qualcosa di nuovo"
        );
        assert_eq!(
            traduci(InterfaceLanguage::Italian, "Stato: In esame"),
            "Stato: In esame"
        );
    }

    #[test]
    fn una_frase_del_rust_si_riconosce_dal_modello_con_i_nomi() {
        // «{gesto} non parte. {perche}» è un modello del Rust, con i nomi di
        // `format!`: i valori passano nel modello tradotto, così come sono.
        assert_eq!(
            traduci(
                InterfaceLanguage::English,
                "Il pacchetto non parte. Manca la ragione."
            ),
            "Il pacchetto does not start. Manca la ragione."
        );
    }
}

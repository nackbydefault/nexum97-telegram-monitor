//! Chi ha prodotto un livello, e quando quel «chi» cambia.
//!
//! # Il problema, detto per bene
//!
//! I dizionari sono versionati dal primo giorno: un contenuto analizzato a
//! marzo porta il numero della versione con cui fu analizzato, e chi rilegge
//! sa **quali termini** furono usati.
//!
//! Il **motore** no. La formula che trasforma i riscontri in un livello da 0 a
//! 4 è cambiata due volte in questo progetto, e i contenuti analizzati prima e
//! dopo portano lo stesso livello scritto nello stesso modo. Chi rilegge un
//! atto non ha modo di sapere quale delle due formule lo ha prodotto.
//!
//! Il limite era già dichiarato in `lisi-services::analysis`: «se la formula
//! cambiasse, le spiegazioni dei contenuti di livello 0 racconterebbero la
//! regola nuova su fatti vecchi». Questo modulo lo rende visibile.
//!
//! # La trappola di una versione scritta a mano
//!
//! Un numero costante che qualcuno deve ricordarsi di alzare **non si alza**.
//! Si cambia la formula, si eseguono le prove, si vede verde, e la versione
//! resta quella di prima: da quel momento due formule diverse dichiarano lo
//! stesso numero, ed è peggio di non avere alcun numero — perché ora c'è
//! qualcosa che sembra affidabile.
//!
//! # La soluzione: l'impronta del motore vive accanto alla versione
//!
//! [`ENGINE_FINGERPRINT`] è l'impronta del **codice sorgente** delle due parti
//! che decidono un livello: il riscontro dei termini e il calcolo del
//! punteggio. Una prova la ricalcola e fallisce se non coincide.
//!
//! Chi cambia la formula vede diventare rossa una prova che dice, per esteso,
//! di alzare [`ENGINE_VERSION`] e aggiornare l'impronta. **Non può cambiarla di
//! nascosto**, e non deve ricordarsene: se ne accorge il cancello.

use crate::digest::Sha256Digest;

/// Versione del motore di analisi.
///
/// # Che cosa numera, e che cosa no
///
/// Numera **la formula**: come i riscontri diventano un livello da 0 a 4, e
/// come i termini vengono trovati nel testo. Non numera il prodotto, che ha una
/// versione propria, né i dizionari, che sono versionati ciascuno per conto
/// suo.
///
/// # Perché comincia da 1 e non dalla versione del pacchetto
///
/// Perché il pacchetto cambia versione a ogni consegna, anche quando il motore
/// non è stato toccato: legarli direbbe che il motore è cambiato ogni volta,
/// e un numero che cambia sempre non distingue nulla.
///
/// **1** è stato il motore fino al 2026-10-23.
///
/// **2** è il motore con il codice numerico (DICT-CODES-01, ADR-0170): un
/// quarto modo di riscontro, che trova un codice di sole cifre soltanto come
/// numero isolato e lo conta soltanto insieme a un altro termine positivo. Per
/// un contenuto senza codici numerici il livello è quello della versione 1.
///
/// **3** è il motore con le espressioni regolari (DICT-REGEX-01, ADR-0187): un
/// quinto modo di riscontro, cercato da un motore in tempo lineare. Per un
/// contenuto senza espressioni nella configurazione il livello è quello della
/// versione 2.
pub const ENGINE_VERSION: u32 = 3;

/// Il sorgente delle parti che decidono un livello.
///
/// Sono tre: chi trova i termini nel testo, chi trova le espressioni (dalla
/// versione 3) e chi trasforma i riscontri in un livello. Il resto del modulo
/// `analysis` compone e non decide.
const ENGINE_SOURCES: &[&str] = &[
    include_str!("matching.rs"),
    include_str!("expression.rs"),
    include_str!("scoring.rs"),
];

/// Impronta del motore alla versione [`ENGINE_VERSION`].
///
/// Si aggiorna **soltanto** insieme a [`ENGINE_VERSION`], e la prova
/// `l_impronta_del_motore_corrisponde_al_codice` impedisce di aggiornare l'una
/// senza l'altra.
pub const ENGINE_FINGERPRINT: &str =
    "bfc90e520f350c63fc531caed29c9563bae7287afb3285eef942799c7313c6cf";

/// Calcola l'impronta del motore dal proprio codice.
///
/// # Perché il sorgente e non un elenco di regole
///
/// Perché un elenco di regole è un secondo posto in cui la formula è scritta, e
/// due posti divergono. Il sorgente **è** la formula: se cambia di un carattere
/// che conti, l'impronta cambia.
///
/// Cambia anche per un commento riscritto, ed è il prezzo: un falso allarme
/// costa un minuto e la conferma che nessuno ha toccato la formula di nascosto.
#[must_use]
pub fn engine_fingerprint() -> String {
    Sha256Digest::of_text(&ENGINE_SOURCES.join("\n"))
        .as_str()
        .to_owned()
}

/// Come il motore si nomina in un documento e in una schermata.
///
/// # Perché una funzione e non una costante
///
/// Perché la frase compare nel Provenance Explorer, nei rapporti e nel replay,
/// e tre copie della stessa frase diventano tre frasi diverse alla prima
/// correzione.
#[must_use]
pub fn engine_label() -> String {
    format!("motore di analisi v{ENGINE_VERSION}")
}

/// Come si nomina il motore di un contenuto analizzato **prima** che il motore
/// avesse un numero.
///
/// # Perché non si scrive la versione corrente
///
/// Perché sarebbe falso. Quei contenuti furono analizzati da un motore di cui
/// non si sa quale fosse, e scrivere «v1» direbbe che qualcuno lo sa. È la
/// stessa disciplina della salute delle fonti: l'assenza di evidenza non è
/// evidenza.
#[must_use]
pub const fn unknown_engine_label() -> &'static str {
    "motore di analisi non registrato: questo contenuto fu analizzato prima che \
     il motore avesse un numero, e quale formula lo abbia prodotto non risulta"
}

#[cfg(test)]
mod tests {
    use super::{
        ENGINE_FINGERPRINT, ENGINE_VERSION, engine_fingerprint, engine_label, unknown_engine_label,
    };

    /// **L'impronta del motore corrisponde al codice del motore.**
    ///
    /// # Che cosa fare quando questa prova diventa rossa
    ///
    /// Vuol dire che il motore di analisi è cambiato. Due gesti, in
    /// quest'ordine:
    ///
    /// 1. **alzare `ENGINE_VERSION`** di uno;
    /// 2. sostituire `ENGINE_FINGERPRINT` con il valore che questa prova
    ///    stampa.
    ///
    /// Il secondo senza il primo è il difetto che questa prova esiste per
    /// impedire: due formule diverse che dichiarano lo stesso numero sono
    /// peggio di nessun numero, perché ora c'è qualcosa che sembra affidabile.
    ///
    /// Se il cambiamento era **solo** un commento o una formattazione, si alza
    /// comunque la versione: distinguere «un commento» da «una formula» è
    /// esattamente il giudizio che una guardia non può dare, e sbagliarlo dalla
    /// parte prudente costa un numero in più.
    #[test]
    fn l_impronta_del_motore_corrisponde_al_codice() {
        let calcolata = engine_fingerprint();

        assert_eq!(
            calcolata, ENGINE_FINGERPRINT,
            "\n\nIL MOTORE DI ANALISI E' CAMBIATO.\n\n\
             Alzare ENGINE_VERSION (oggi {ENGINE_VERSION}) e sostituire\n\
             ENGINE_FINGERPRINT con:\n\n  \"{calcolata}\"\n\n\
             Aggiornare l'impronta SENZA alzare la versione e' il difetto che\n\
             questa prova esiste per impedire: due formule diverse che\n\
             dichiarano lo stesso numero.\n"
        );
    }

    /// L'impronta è stabile: due calcoli danno lo stesso valore.
    #[test]
    fn l_impronta_e_stabile() {
        assert_eq!(engine_fingerprint(), engine_fingerprint());
        assert_eq!(engine_fingerprint().len(), 64);
    }

    /// Il motore si nomina allo stesso modo ovunque.
    #[test]
    fn il_motore_si_nomina_allo_stesso_modo() {
        assert_eq!(
            engine_label(),
            format!("motore di analisi v{ENGINE_VERSION}")
        );
    }

    /// **Un motore non registrato non si dichiara come quello corrente.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I contenuti analizzati prima di questa milestone non portano alcun
    /// numero di motore. Scrivere «v1» accanto a essi direbbe che qualcuno sa
    /// quale formula li ha prodotti, e nessuno lo sa.
    #[test]
    fn un_motore_non_registrato_non_si_spaccia_per_quello_corrente() {
        let frase = unknown_engine_label();

        assert!(
            frase.contains("non risulta"),
            "l'assenza va dichiarata: «{frase}»"
        );
        assert!(
            !frase.contains(&format!("v{ENGINE_VERSION}")),
            "un motore non registrato non deve nominare la versione corrente"
        );
        assert_ne!(frase, engine_label());
    }
}

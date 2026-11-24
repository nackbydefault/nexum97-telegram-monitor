//! Stato dei caratteri del prodotto.
//!
//! Il sistema grafico approvato prescrive due famiglie e due soltanto: **Sora**
//! porta la lingua, **IBM Plex Mono** porta tutto cio' che ha prodotto una
//! macchina — orologi, contatori, identificativi, codici di livello, versioni,
//! e ogni etichetta maiuscola spaziata.
//!
//! # Dove avviene davvero l'incorporamento
//!
//! **Non qui.** In Slint 1.17 un carattere si incorpora importando il `.ttf`
//! dentro un file `.slint`: il compilatore raccoglie i caratteri di tutti i
//! documenti e ne genera la registrazione. La registrazione a runtime esiste
//! solo dietro la feature `unstable-fontique-010`, e una feature instabile non
//! entra in un prodotto che fissa le proprie dipendenze.
//!
//! Il modulo `.slint` con le due righe di `import` lo genera `build.rs`, che le
//! scrive **solo se i file ci sono**. Questo modulo Rust non incorpora nulla:
//! serve a **dire quale dei due casi e' avvenuto**, perche' chi legge il
//! registro dopo aver visto una schermata diversa dal riferimento possa
//! capirlo senza aprire il binario.
//!
//! # Che cosa succede se i caratteri non ci sono
//!
//! I file **non sono versionati** (`fonts.lock.json` ne conserva l'impronta, e
//! `scripts/fetch-fonts.ps1` li scarica e la riverifica).
//!
//! - in **debug** il prodotto parte e il testo cade sulla catena di ripiego
//!   dichiarata dal sistema grafico (`Sora -> Segoe UI Variable Display ->
//!   Segoe UI`, `IBM Plex Mono -> Cascadia Mono -> Consolas`);
//! - in **release** la compilazione **fallisce**, in `build.rs`. Una release
//!   uscita con i caratteri di ripiego sembra giusta finche' qualcuno non la
//!   mette accanto al riferimento, ed e' il genere di difetto che questo
//!   progetto ha gia' incontrato piu' volte: costruito, collaudato, e non
//!   quello che doveva essere.

/// Quale dei due casi e' avvenuto alla compilazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fonts {
    /// Le due famiglie sono nel binario.
    Embedded,
    /// Il binario e' stato costruito senza: il testo usa la catena di ripiego.
    Fallback,
}

/// Riporta se i caratteri del prodotto sono nel binario.
pub fn status() -> Fonts {
    if cfg!(fonts_embedded) {
        Fonts::Embedded
    } else {
        Fonts::Fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lo stato e' uno dei due, e non fa cadere nulla.
    ///
    /// Non c'e' molto da provare qui, ed e' voluto: la verifica che conta sui
    /// caratteri **non e' un test di Rust**. E' l'impronta SHA-256 in
    /// `fonts.lock.json`, che `scripts/fetch-fonts.ps1` riconfronta a ogni
    /// esecuzione, e la resa a vista - un carattere sbagliato compila
    /// benissimo.
    #[test]
    fn the_state_is_one_of_the_two() {
        assert!(matches!(status(), Fonts::Embedded | Fonts::Fallback));
    }
}

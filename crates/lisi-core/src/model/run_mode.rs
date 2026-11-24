//! Il modo di esecuzione: operativo oppure esercitazione (PR-13, ADR-0129).
//!
//! # Due mondi che non si toccano
//!
//! In **Esercitazione** il prodotto lavora su un archivio separato, con dati
//! sintetici, e non contatta Telegram. Questo modulo dice soltanto **che cosa**
//! i due modi sono e **dove** vive ciascuno: stabilire il modo del processo, e
//! negare l'autorità di acquisizione in Esercitazione, è compito dei servizi.
//!
//! # Perché le cartelle non possono coincidere
//!
//! La cartella dell'Esercitazione sta **accanto** a quella operativa, mai
//! dentro: un archivio di esercitazione dentro quello operativo finirebbe nelle
//! sue copie di sicurezza, e un azzeramento dell'una potrebbe toccare l'altra.
//! Il controllo è a tempo di compilazione e, sui percorsi, in una prova.

use std::path::{Path, PathBuf};

use crate::branding::DATA_DIRECTORY;

/// La cartella dati dell'Esercitazione, sotto `%LOCALAPPDATA%`.
pub const EXERCISE_DATA_DIRECTORY: &str = "LISI Telegram Monitor - Esercitazione";

/// L'argomento della riga di comando che avvia l'Esercitazione.
pub const EXERCISE_ARGUMENT: &str = "--esercitazione";

/// Il prefisso del nome di ogni file prodotto in Esercitazione.
pub const EXERCISE_FILE_PREFIX: &str = "ESERCITAZIONE-";

/// Le due cartelle devono avere nomi diversi: lo verifica il compilatore.
const _: () = assert!(!same(EXERCISE_DATA_DIRECTORY, DATA_DIRECTORY));

/// Confronto di due testi utilizzabile a tempo di compilazione.
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut indice = 0;
    while indice < a.len() {
        if a[indice] != b[indice] {
            return false;
        }
        indice += 1;
    }
    true
}

/// Il modo in cui il processo lavora. **Si stabilisce all'avvio e non cambia.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunMode {
    /// Il lavoro vero: l'archivio dell'ufficio, Telegram se la postazione ne ha
    /// l'autorità.
    Operational,
    /// La formazione: un archivio separato con dati sintetici, nessun contatto
    /// con Telegram, ogni documento marcato.
    Exercise,
}

impl RunMode {
    /// Il modo indicato dagli argomenti della riga di comando: Esercitazione se
    /// compare [`EXERCISE_ARGUMENT`], altrimenti operativo.
    #[must_use]
    pub fn from_arguments<I, S>(argomenti: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if argomenti
            .into_iter()
            .any(|argomento| argomento.as_ref() == EXERCISE_ARGUMENT)
        {
            Self::Exercise
        } else {
            Self::Operational
        }
    }

    /// Se è l'Esercitazione.
    #[must_use]
    pub const fn is_exercise(self) -> bool {
        matches!(self, Self::Exercise)
    }

    /// Il nome della cartella dati di questo modo.
    #[must_use]
    pub const fn data_directory(self) -> &'static str {
        match self {
            Self::Operational => DATA_DIRECTORY,
            Self::Exercise => EXERCISE_DATA_DIRECTORY,
        }
    }

    /// La parola per l'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Operational => "operativo",
            Self::Exercise => "esercitazione",
        }
    }
}

/// La cartella dati del modo indicato, sotto la base indicata
/// (`%LOCALAPPDATA%`, o una cartella di prova).
#[must_use]
pub fn data_root_in(base: &Path, modo: RunMode) -> PathBuf {
    base.join(modo.data_directory())
}

/// Se due cartelle si toccano: coincidono, o l'una contiene l'altra.
///
/// Il confronto è per componenti del percorso, non per testo: «LISI Telegram
/// Monitor - Esercitazione» comincia con le stesse lettere di «LISI Telegram
/// Monitor», ma non sta dentro quella cartella.
#[must_use]
pub fn directories_overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        EXERCISE_ARGUMENT, EXERCISE_DATA_DIRECTORY, RunMode, data_root_in, directories_overlap,
    };
    use crate::branding::DATA_DIRECTORY;

    /// **Le due cartelle non si toccano**, sulla stessa base.
    #[test]
    fn le_cartelle_dei_due_modi_non_si_toccano() {
        let base = Path::new("C:\\Utenti\\prova\\AppData\\Local");
        let operativa = data_root_in(base, RunMode::Operational);
        let esercitazione = data_root_in(base, RunMode::Exercise);
        assert_ne!(operativa, esercitazione);
        assert!(!directories_overlap(&operativa, &esercitazione));
        assert!(operativa.ends_with(DATA_DIRECTORY));
        assert!(esercitazione.ends_with(EXERCISE_DATA_DIRECTORY));
    }

    /// Il confronto vede una cartella dentro l'altra, e la stessa cartella.
    #[test]
    fn il_confronto_vede_contenimento_e_coincidenza() {
        let a = Path::new("C:\\dati\\uno");
        assert!(directories_overlap(a, a));
        assert!(directories_overlap(a, &a.join("dentro")));
        assert!(!directories_overlap(a, Path::new("C:\\dati\\uno - altro")));
    }

    /// **Soltanto l'argomento esatto avvia l'Esercitazione.**
    #[test]
    fn soltanto_l_argomento_esatto_avvia_l_esercitazione() {
        assert_eq!(
            RunMode::from_arguments(["programma.exe", EXERCISE_ARGUMENT]),
            RunMode::Exercise
        );
        assert_eq!(
            RunMode::from_arguments(["programma.exe"]),
            RunMode::Operational
        );
        assert_eq!(
            RunMode::from_arguments(["programma.exe", "--esercitazione=no"]),
            RunMode::Operational
        );
    }
}

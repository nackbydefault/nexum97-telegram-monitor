//! Il modo di esecuzione del processo, stabilito una volta (PR-13, ADR-0129).
//!
//! # Un testimone, non un interruttore
//!
//! Stabilire il modo restituisce un **testimone**: [`OperationalMode`] oppure
//! [`ExerciseMode`]. Nessuno dei due ha un costruttore pubblico, e il modo di un
//! processo si stabilisce **una volta**: chiedere il modo operativo in un
//! processo di esercitazione è un errore, non una sostituzione.
//!
//! L'autorità di acquisizione vuole il testimone operativo
//! (`StationAuthorityService::acquisition_authority`). In Esercitazione quel
//! valore non esiste, e quindi non esiste un modo di costruire una richiesta
//! verso Telegram: non un `if`, non una configurazione — l'assenza del
//! costruttore, come per l'autorità stessa (ADR-0092).
//!
//! La prova qui sotto **deve non compilare**: il testimone dell'esercitazione
//! non apre l'autorità di acquisizione. È il controllo negativo 1 del piano.
//!
//! ```compile_fail
//! use lisi_services::acquisition_authority::StationAuthorityService;
//! use lisi_services::run_mode::{EstablishedMode, establish};
//! use lisi_core::model::run_mode::RunMode;
//! let Ok(EstablishedMode::Exercise(esercitazione)) = establish(RunMode::Exercise) else {
//!     return;
//! };
//! let stazione = StationAuthorityService::in_directory(std::path::Path::new("."));
//! let _ = stazione.acquisition_authority(&esercitazione);
//! ```
//!
//! E il testimone operativo non si fabbrica:
//!
//! ```compile_fail
//! use lisi_services::run_mode::OperationalMode;
//! let _finto = OperationalMode { _privato: () };
//! ```
//!
//! # La marcatura
//!
//! Ogni documento prodotto in Esercitazione porta il prefisso
//! [`EXERCISE_FILE_PREFIX`] nel nome e la frase di **SIC-17** in apertura; nel
//! documento Word e nel PDF anche nel piede di ogni pagina. La applicano i
//! punti che scrivono, leggendo il modo del processo: nessun chiamante la può
//! dimenticare.

use std::borrow::Cow;
use std::sync::OnceLock;

pub use lisi_core::model::run_mode::{EXERCISE_FILE_PREFIX, RunMode};

use crate::report_narrative::{Block, LetterheadLine, NarrativeReport};

/// La frase dell'Esercitazione: il testo corrente di **SIC-17**.
pub const EXERCISE_MARK: &str = lisi_core::security_messages::EXERCISE_NOTICE.current.text;

/// Il modo del processo, una volta stabilito.
static MODE: OnceLock<RunMode> = OnceLock::new();

/// La prova che il processo lavora in modo **operativo**.
///
/// Senza costruttore pubblico: la produce soltanto [`establish`].
#[derive(Debug)]
pub struct OperationalMode {
    /// Campo privato senza contenuto: rende il tipo non costruibile da fuori.
    _privato: (),
}

/// La prova che il processo lavora in **Esercitazione**.
///
/// Senza costruttore pubblico: la produce soltanto [`establish`].
#[derive(Debug)]
pub struct ExerciseMode {
    /// Campo privato senza contenuto: rende il tipo non costruibile da fuori.
    _privato: (),
}

/// Il modo stabilito, con il suo testimone.
#[derive(Debug)]
pub enum EstablishedMode {
    /// Operativo.
    Operational(OperationalMode),
    /// Esercitazione.
    Exercise(ExerciseMode),
}

impl EstablishedMode {
    /// Il modo, senza il testimone.
    #[must_use]
    pub const fn mode(&self) -> RunMode {
        match self {
            Self::Operational(_) => RunMode::Operational,
            Self::Exercise(_) => RunMode::Exercise,
        }
    }
}

/// Il processo è già stato stabilito in un altro modo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeConflict {
    /// Il modo già stabilito, che resta.
    pub established: RunMode,
}

impl std::fmt::Display for ModeConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "il processo lavora già in modo {}, e il modo non cambia",
            self.established.label()
        )
    }
}

impl std::error::Error for ModeConflict {}

/// Stabilisce il modo del processo, e ne restituisce il testimone.
///
/// La prima chiamata decide; le successive con lo **stesso** modo restituiscono
/// un altro testimone dello stesso modo, quelle con un modo **diverso**
/// falliscono.
///
/// # Errori
///
/// [`ModeConflict`] se il processo lavora già nell'altro modo.
pub fn establish(modo: RunMode) -> Result<EstablishedMode, ModeConflict> {
    let stabilito = *MODE.get_or_init(|| modo);
    if stabilito != modo {
        return Err(ModeConflict {
            established: stabilito,
        });
    }
    Ok(match stabilito {
        RunMode::Operational => EstablishedMode::Operational(OperationalMode { _privato: () }),
        RunMode::Exercise => EstablishedMode::Exercise(ExerciseMode { _privato: () }),
    })
}

/// Il testimone operativo, se il processo lavora (o comincia a lavorare) in
/// modo operativo.
///
/// # Errori
///
/// [`ModeConflict`] in un processo di esercitazione.
pub fn operational() -> Result<OperationalMode, ModeConflict> {
    match establish(RunMode::Operational)? {
        EstablishedMode::Operational(testimone) => Ok(testimone),
        EstablishedMode::Exercise(_) => Err(ModeConflict {
            established: RunMode::Exercise,
        }),
    }
}

/// Il testimone dell'esercitazione, se il processo lavora (o comincia a
/// lavorare) in Esercitazione.
///
/// # Errori
///
/// [`ModeConflict`] in un processo operativo.
pub fn exercise() -> Result<ExerciseMode, ModeConflict> {
    match establish(RunMode::Exercise)? {
        EstablishedMode::Exercise(testimone) => Ok(testimone),
        EstablishedMode::Operational(_) => Err(ModeConflict {
            established: RunMode::Operational,
        }),
    }
}

/// Il testimone operativo, per le prove di questa libreria, che lavorano tutte
/// in modo operativo. Fuori dalle prove non esiste.
#[cfg(test)]
pub(crate) fn operational_for_tests() -> OperationalMode {
    match operational() {
        Ok(testimone) => testimone,
        Err(conflitto) => panic!("le prove della libreria lavorano in modo operativo: {conflitto}"),
    }
}

/// Il modo del processo. Prima che sia stabilito, è quello operativo: il
/// programma lo stabilisce come prima cosa, e un processo di esercitazione lo
/// ha stabilito prima di aprire qualunque cosa.
#[must_use]
pub fn current() -> RunMode {
    MODE.get().copied().unwrap_or(RunMode::Operational)
}

/// Se il processo lavora in Esercitazione.
#[must_use]
pub fn is_exercise() -> bool {
    current().is_exercise()
}

/// Il nome di un file da produrre, con il prefisso in Esercitazione.
#[must_use]
pub fn file_name(nome: &str) -> String {
    if is_exercise() {
        format!("{EXERCISE_FILE_PREFIX}{nome}")
    } else {
        nome.to_owned()
    }
}

/// Un testo da scrivere in un file, con la frase dell'Esercitazione in
/// apertura.
#[must_use]
pub fn marked_text(testo: String) -> String {
    if is_exercise() {
        format!("{EXERCISE_MARK}\n\n{testo}")
    } else {
        testo
    }
}

/// Un documento Word o PDF, con la frase dell'Esercitazione come primo blocco e
/// nel piede di ogni pagina.
#[must_use]
pub fn marked_report(report: &NarrativeReport) -> Cow<'_, NarrativeReport> {
    if !is_exercise() {
        return Cow::Borrowed(report);
    }
    let mut marcato = report.clone();
    marcato
        .blocks
        .insert(0, Block::Heading(String::from(EXERCISE_MARK)));
    marcato
        .footer
        .insert(0, LetterheadLine::Configured(String::from(EXERCISE_MARK)));
    Cow::Owned(marcato)
}

#[cfg(test)]
mod tests {
    use super::{EXERCISE_MARK, file_name, marked_text};

    /// In un processo operativo — quello delle prove di questa libreria — nulla
    /// si marca: la marcatura è dell'Esercitazione soltanto. Le prove
    /// dell'Esercitazione stanno in un eseguibile di prova separato
    /// (`tests/esercitazione.rs`), perché il modo è del processo.
    #[test]
    fn in_modo_operativo_nulla_si_marca() {
        let Ok(_) = super::operational() else {
            panic!("le prove della libreria lavorano in modo operativo");
        };
        assert_eq!(file_name("relazione.docx"), "relazione.docx");
        assert_eq!(marked_text(String::from("testo")), "testo");
        assert!(EXERCISE_MARK.contains("ESERCITAZIONE"));
    }

    /// **Il modo non cambia**: in un processo operativo l'Esercitazione non si
    /// stabilisce.
    #[test]
    fn il_modo_non_cambia() {
        let Ok(_) = super::operational() else {
            panic!("le prove della libreria lavorano in modo operativo");
        };
        assert!(super::exercise().is_err());
        assert!(super::operational().is_ok(), "lo stesso modo si conferma");
    }
}

//! L'Esercitazione nella finestra (PR-13, ADR-0129).
//!
//! Prepara l'archivio all'avvio — ricominciare se è stato chiesto, caricare
//! l'insieme sintetico se l'archivio è vuoto — e mostra la fascia. **Non ha
//! logica propria**: che cosa si toglie, che cosa si carica e dove lo decidono
//! i servizi, e la fascia la disegna l'interfaccia con la sola condizione del
//! modo del processo.

use lisi_services::Database;
use lisi_services::run_mode::{EXERCISE_MARK, ExerciseMode};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// La cartella sotto cui stanno le cartelle dati: `%LOCALAPPDATA%`.
fn base() -> Option<std::path::PathBuf> {
    crate::account::data_root()?
        .parent()
        .map(std::path::Path::to_path_buf)
}

/// Mostra la fascia e, se è stato chiesto, ricomincia: **prima** che qualcuno
/// apra l'archivio, perché con l'archivio aperto i file non si tolgono.
pub fn prepare(window: &AppWindow, testimone: &ExerciseMode) {
    window.set_exercise_mode(true);
    window.set_exercise_notice(crate::lingua::schermo(EXERCISE_MARK));
    window.set_exercise_detail(SharedString::from(
        lisi_core::security_messages::EXERCISE_NOTICE
            .current
            .technical_detail,
    ));
    let Some(base) = base() else {
        tracing::warn!("esercitazione: cartella dati non determinabile");
        return;
    };
    match lisi_services::exercise::prepare(testimone, &base) {
        Ok(lisi_services::exercise::Prepared::Restarted) => {
            tracing::info!("esercitazione ricominciata da capo");
        }
        Ok(lisi_services::exercise::Prepared::Kept) => {}
        Err(errore) => {
            tracing::warn!(errore = %errore, "esercitazione: non si è potuto ricominciare");
            window.set_exercise_message(crate::lingua::schermo(errore.operator_message()));
        }
    }
}

/// Carica l'insieme sintetico se l'archivio dell'esercitazione è vuoto.
pub fn seed_if_empty(window: &AppWindow, testimone: &ExerciseMode, archivio: Option<Database>) {
    let Some(archivio) = archivio else {
        return;
    };
    if archivio.sources().is_ok_and(|fonti| !fonti.is_empty()) {
        return;
    }
    if let Err(errore) = lisi_services::exercise::seed(testimone, archivio, crate::account::now()) {
        tracing::warn!(errore = %errore, "esercitazione: l'insieme non si è caricato");
        window.set_exercise_message(crate::lingua::schermo(errore.operator_message()));
    }
}

/// Collega «Ricomincia l'esercitazione».
pub fn wire(window: &AppWindow) {
    let handle = window.as_weak();
    window.on_exercise_restart(move || {
        if crate::lock::refuse_while_locked("exercise_restart") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let frase = match (lisi_services::run_mode::exercise(), base()) {
            (Ok(testimone), Some(base)) => {
                match lisi_services::exercise::request_restart(&testimone, &base) {
                    Ok(()) => String::from(
                        "Al prossimo avvio l'esercitazione ricomincia da capo. Chiudere e \
                         riaprire il programma.",
                    ),
                    Err(errore) => errore.operator_message(),
                }
            }
            _ => String::from("Questa finestra non è un'esercitazione."),
        };
        window.set_exercise_message(crate::lingua::schermo(frase));
    });
}

/// Collega «Apri l'Esercitazione», nella finestra operativa (F-06).
///
/// # Un processo a parte, lo stesso programma
///
/// Il modo si stabilisce una volta per processo e non cambia (ADR-0129): una
/// finestra operativa non diventa un'esercitazione. Si apre quindi **un
/// secondo processo dello stesso eseguibile**, con il solo argomento
/// [`EXERCISE_ARGUMENT`](lisi_core::model::run_mode::EXERCISE_ARGUMENT), esattamente
/// come fa il collegamento del menu Start. Nessuna shell, nessun testo scritto
/// da qualcuno: il percorso è quello del programma in esecuzione. L'Esercitazione
/// ha la propria cartella e il proprio file d'istanza, quindi la seconda copia
/// non è rifiutata, e questa finestra resta com'era.
///
/// Prima di questa correzione l'Esercitazione esisteva solo dal menu Start: chi
/// usava il programma senza quel collegamento non la trovava, e provava sulla
/// modalità dimostrativa, che non ha contenuti.
pub fn wire_launcher(window: &AppWindow) {
    let handle = window.as_weak();
    window.on_open_exercise(move || {
        if crate::lock::refuse_while_locked("open_exercise") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let esito = std::env::current_exe().and_then(|programma| {
            std::process::Command::new(programma)
                .arg(lisi_core::model::run_mode::EXERCISE_ARGUMENT)
                .spawn()
        });
        let frase = match esito {
            Ok(_figlio) => {
                tracing::info!("esercitazione aperta in un processo a parte");
                "L'Esercitazione si apre in una finestra a parte, con «ESERCITAZIONE» nel titolo e \
                 nella fascia in cima. Questa finestra resta com'era."
            }
            Err(errore) => {
                tracing::warn!(errore = %errore, "esercitazione non aperta");
                "L'Esercitazione non si è aperta. Si apre anche dal collegamento «NEXUM97 \
                 Esercitazione» fra i programmi di Windows."
            }
        };
        window.set_open_exercise_message(crate::lingua::schermo(frase));
    });
}

#[cfg(test)]
mod tests {
    const SLINT: &str = include_str!("../ui/app-window.slint");
    const MAIN: &str = include_str!("main.rs");

    /// **La fascia non si sopprime** (controllo negativo 4): sta nel layout
    /// principale, fuori da ogni pagina; la sua sola condizione è il modo del
    /// processo; nessuna proprietà la nasconde; il titolo della finestra lo
    /// dice anch'esso.
    #[test]
    fn la_fascia_dell_esercitazione_non_si_sopprime() {
        // Dal 2026-10-16 la fascia sta in un `Rectangle` che ne prende
        // l'altezza (DEC-397), e ha un nome: la condizione è quella del
        // riquadro che la racchiude, senza nulla in mezzo.
        let fascia = "fascia-esercitazione := VerticalLayout {";
        assert_eq!(SLINT.matches(fascia).count(), 1, "la fascia è una sola");
        let Some(posizione) = SLINT.find(fascia) else {
            panic!("la fascia deve esserci");
        };
        let Some(condizione) = SLINT[..posizione].rfind("if root.exercise-mode: Rectangle {")
        else {
            panic!("la fascia deve dipendere dal modo del processo");
        };
        assert!(
            !SLINT[condizione..posizione].contains('}'),
            "fra la condizione e la fascia non c'è nient'altro"
        );
        // Fuori da ogni pagina: nella finestra principale, prima del corpo —
        // menu e contenuto — che contiene tutte le pagine. Fino a
        // UX-EXCELLENCE-02 l'ancora era la testata con il marchio, che stava
        // fra la fascia e il corpo ed è stata tolta (SIM3-04): la regola non
        // cambia, cambia il punto da cui la si misura.
        let (Some(finestra), Some(corpo)) = (
            SLINT.find("export component AppWindow inherits Window {"),
            SLINT.find("corpo-finestra := HorizontalLayout {"),
        ) else {
            panic!("la finestra e il suo corpo devono essere riconoscibili");
        };
        assert!(
            finestra < posizione && posizione < corpo,
            "la fascia sta nella finestra, sopra il corpo e quindi sopra ogni pagina"
        );
        // Una proprietà sola la governa, ed è in sola lettura per l'interfaccia.
        assert!(SLINT.contains("in property <bool> exercise-mode: false;"));
        assert!(!SLINT.contains("in-out property <bool> exercise-mode"));
        assert!(!SLINT.contains("exercise-mode = false"));
        assert!(
            !SLINT.contains("exercise-hidden"),
            "nessuna proprietà la nasconde"
        );
        assert!(SLINT.contains("(root.exercise-mode ? @tr(\"ESERCITAZIONE \\u{2014} \") : \"\")"));
        // Il modo si stabilisce prima di tutto, e la fascia si accende da qui.
        let Some(stabilito) = MAIN.find("lisi_services::run_mode::establish(") else {
            panic!("il programma deve stabilire il modo");
        };
        let Some(registro) = MAIN.find("let logging_guard = logging::initialize();") else {
            panic!("il registro si apre in un punto riconoscibile");
        };
        assert!(
            stabilito < registro,
            "il modo si stabilisce prima del registro"
        );
    }

    /// In Esercitazione non si collega nulla dell'Hub: un Hub di esercitazione
    /// sarebbe un passaggio di dati fra i due mondi.
    #[test]
    fn in_esercitazione_nessun_hub() {
        for servizio in [
            "team::create_service",
            "team_review::create_service",
            "team_shared::create_service",
            "team_live::create_service",
        ] {
            let Some(posizione) = MAIN.find(servizio) else {
                panic!("«{servizio}» deve essere collegato");
            };
            let prima = &MAIN[..posizione];
            let Some(ultima_riga) = prima.rfind("if esercitazione_attiva {") else {
                panic!("«{servizio}» non è escluso in Esercitazione");
            };
            assert!(
                posizione - ultima_riga < 400,
                "«{servizio}» non è escluso in Esercitazione"
            );
        }
    }
}

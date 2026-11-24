use std::{
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{Builder as RollingBuilder, Rotation};
use tracing_subscriber::fmt::SubscriberBuilder;

/// Prefisso del nome del file di log giornaliero.
const LOG_FILE_PREFIX: &str = "lisi-telegram-monitor.log";

/// Quanti file di log si conservano.
///
/// # Perche' un limite esiste
///
/// La rotazione giornaliera crea un file al giorno e non ne toglie nessuno.
/// Su una postazione d'ufficio accesa per anni la cartella cresce senza fine:
/// non e' un guasto che si manifesta, e' un guasto che si accumula, e quando
/// si nota e' perche' il disco e' pieno o perche' cercare la giornata giusta
/// fra millecinquecento file e' diventato impraticabile.
///
/// # Perche' NOVANTA e non trenta, e non mille
///
/// Un registro serve a ricostruire che cosa e' successo **dopo** che qualcuno
/// se ne e' accorto, e chi si accorge di un problema d'ufficio spesso lo fa
/// settimane dopo. Trenta giorni cancellerebbero la traccia proprio nel caso
/// che la rende utile.
///
/// Mille file non sarebbero piu' prudenza ma rinuncia a decidere: nessuno
/// aprira' mai il registro del terzo anno prima, e intanto la cartella pesa.
///
/// # Che cosa questo NON e'
///
/// Non e' la conservazione del materiale acquisito (DEC-206), che e'
/// configurabile e parte da «si conserva tutto». Qui si tratta della
/// diagnostica del programma: chi la legge sono gli sviluppatori, non
/// l'ufficio, e non e' materiale di servizio.
const MAX_LOG_FILES: usize = 90;

/// Mantiene attivo il writer asincrono per tutta la vita dell'applicazione.
pub struct LoggingGuard {
    _worker_guard: WorkerGuard,
    log_directory: PathBuf,
    /// Vero se il log persistente su file non era apribile all'avvio e si sta
    /// scrivendo altrove: chi chiama può avvisarne l'operatore o gli
    /// sviluppatori, senza che l'applicazione ne risenta.
    degraded: bool,
}

impl LoggingGuard {
    #[must_use]
    pub fn log_directory(&self) -> &Path {
        &self.log_directory
    }

    /// Vero se il log giornaliero su file non era disponibile a questo avvio.
    #[must_use]
    pub const fn degraded(&self) -> bool {
        self.degraded
    }
}

/// Inizializza il logging: un file giornaliero locale senza codici colore o
/// output sensibile, quando possibile.
///
/// Non impedisce mai l'avvio dell'applicazione: se il file di log non è
/// apribile (cartella non scrivibile, permessi alterati, guasto transitorio
/// del disco...) degrada a un writer non persistente invece di terminare.
/// [`LoggingGuard::degraded`] riporta la degradazione a chi chiama, che può
/// avvisarne l'operatore.
#[must_use]
pub fn initialize() -> LoggingGuard {
    initialize_in(resolve_log_directory())
}

fn initialize_in(log_directory: PathBuf) -> LoggingGuard {
    match open_daily_file_writer(&log_directory) {
        Ok((writer, worker_guard)) => {
            install_subscriber(writer);
            LoggingGuard {
                _worker_guard: worker_guard,
                log_directory,
                degraded: false,
            }
        }
        Err(_) => {
            // Il motivo resta diagnostica per sviluppatori: nessun
            // sottoscrittore era ancora attivo quando l'apertura e' fallita,
            // quindi non compare da nessuna parte visibile all'operatore.
            let (writer, worker_guard) = tracing_appender::non_blocking(io::stderr());
            install_subscriber(writer);
            tracing::error!(
                "registro persistente non disponibile: uso un ripiego non persistente per questa esecuzione"
            );
            LoggingGuard {
                _worker_guard: worker_guard,
                log_directory,
                degraded: true,
            }
        }
    }
}

/// Prova ad attivare il log giornaliero su file nella cartella indicata.
fn open_daily_file_writer(
    log_directory: &Path,
) -> Result<(NonBlocking, WorkerGuard), Box<dyn Error>> {
    fs::create_dir_all(log_directory)?;

    // `tracing_appender::rolling::daily` va in panic se il file non e'
    // apribile: il costruttore fallibile del builder e' l'unico modo di
    // trattare il guasto come un errore invece che come un arresto.
    let file_appender = RollingBuilder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        // Senza questo la cartella cresce di un file al giorno per sempre.
        .max_log_files(MAX_LOG_FILES)
        .build(log_directory)?;

    Ok(tracing_appender::non_blocking(file_appender))
}

/// Imposta il sottoscrittore globale sul writer indicato.
///
/// Il fallimento (in pratica solo nei test, che nello stesso processo ne
/// installano uno a testa) viene ignorato: le macro `tracing` restano no-op,
/// il che non è un guasto che deve impedire l'avvio.
fn install_subscriber(writer: NonBlocking) {
    let _ = SubscriberBuilder::default()
        .with_ansi(false)
        .with_target(false)
        .with_writer(writer)
        .try_init();
}

/// Cartella dei log, accanto agli altri dati locali dell'applicazione.
///
/// Il nome della cartella viene da `lisi-core`, lo stesso usato per l'archivio
/// e per la configurazione protetta. Scriverlo a mano qui aveva prodotto due
/// cartelle diverse — `LISI\Telegram Monitor\logs` accanto a
/// `LISI Telegram Monitor\monitor.sqlite` — e chi cerca i log dopo un guasto
/// non li trova dove sta tutto il resto.
fn resolve_log_directory() -> PathBuf {
    // La cartella del modo del processo: il registro dell'Esercitazione sta
    // nella sua cartella, non accanto a quello operativo (PR-13, ADR-0129).
    lisi_services::data_directory::mode_directory()
        .unwrap_or_else(|| {
            env::temp_dir().join(lisi_services::run_mode::current().data_directory())
        })
        .join("logs")
}

#[cfg(test)]
mod tests {
    use super::{
        LOG_FILE_PREFIX, MAX_LOG_FILES, initialize_in, open_daily_file_writer,
        resolve_log_directory,
    };

    #[test]
    fn log_directory_is_namespaced_for_the_application() {
        let path = resolve_log_directory();
        let rendered = path.to_string_lossy();

        assert!(rendered.contains(lisi_core::branding::DATA_DIRECTORY));
        assert!(rendered.ends_with("logs"));
    }

    #[test]
    fn the_logs_sit_beside_the_other_local_data() {
        // I log stavano in una cartella diversa dall'archivio e dalla
        // configurazione protetta: chi cerca un log dopo un guasto guarda dove
        // sta tutto il resto, non in una seconda cartella dal nome simile.
        let Some(parent) = resolve_log_directory()
            .parent()
            .map(std::path::Path::to_path_buf)
        else {
            panic!("la cartella dei log deve avere un livello superiore");
        };

        assert_eq!(
            parent.file_name().and_then(std::ffi::OsStr::to_str),
            Some(lisi_core::branding::DATA_DIRECTORY)
        );
    }

    #[test]
    fn a_writable_directory_yields_a_usable_daily_writer() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let target = directory.path().join("logs");

        assert!(open_daily_file_writer(&target).is_ok());
    }

    /// **La cartella dei registri non deve crescere per sempre.**
    ///
    /// La rotazione giornaliera crea un file al giorno e, senza un limite, non
    /// ne toglie nessuno. Non e' un guasto che si manifesta: e' un guasto che
    /// si accumula, e quando si nota e' perche' il disco e' pieno.
    ///
    /// La prova finge trecento giornate gia' passate e verifica che aprendo il
    /// registro ne restino al piu' MAX_LOG_FILES. Le giornate sono finte ma i
    /// file sono veri, e il potatore e' quello del prodotto.
    ///
    /// # Perche' conta quanti file ha creato davvero
    ///
    /// La prima stesura generava i nomi con un'aritmetica modulare che si
    /// ripeteva ogni ottantaquattro giorni: dei trecento file previsti ne
    /// esistevano ottantacinque, gia' sotto il limite, e la prova passava
    /// **senza che il potatore avesse fatto nulla**. Il controllo negativo l'ha
    /// scoperto. Ora il conteggio prima dell'apertura e' parte della prova: una
    /// prova che non verifica la propria premessa misura se stessa.
    #[test]
    fn i_registri_di_trecento_giorni_non_restano_tutti() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let target = directory.path().join("logs");
        let Ok(()) = std::fs::create_dir_all(&target) else {
            panic!("la cartella dei registri deve potersi creare");
        };

        // Trecento giornate DISTINTE, nella forma esatta che la rotazione
        // giornaliera produce: prefisso, punto, data. Un nome diverso non
        // verrebbe potato, e la prova misurerebbe qualcosa che il prodotto
        // non fa.
        let mut creati = 0_u32;
        'giornate: for anno in 2020..=2021_u32 {
            for mese in 1..=12_u32 {
                for numero in 1..=28_u32 {
                    let nome = format!("{LOG_FILE_PREFIX}.{anno:04}-{mese:02}-{numero:02}");
                    let Ok(()) = std::fs::write(target.join(nome), b"registro di prova\n") else {
                        panic!("il registro di prova deve potersi scrivere");
                    };
                    creati += 1;
                    if creati == 300 {
                        break 'giornate;
                    }
                }
            }
        }

        // La premessa della prova, verificata e non presunta.
        let prima = quanti_file(&target);
        assert_eq!(
            prima, 300,
            "la prova doveva creare trecento registri distinti e ne ha creati {prima}"
        );

        let Ok(_writer) = open_daily_file_writer(&target) else {
            panic!("il registro deve potersi aprire");
        };

        let dopo = quanti_file(&target);
        assert!(
            dopo <= MAX_LOG_FILES,
            "restano {dopo} registri su {prima}: la cartella cresce senza fine"
        );
    }

    /// Quanti file contiene una cartella.
    fn quanti_file(directory: &std::path::Path) -> usize {
        let Ok(voci) = std::fs::read_dir(directory) else {
            panic!("la cartella deve potersi leggere");
        };
        voci.filter_map(Result::ok).count()
    }

    #[test]
    fn a_path_blocked_by_a_file_cannot_become_a_log_directory() {
        // Il seam piu' piccolo per un guasto di filesystem: un file al posto
        // di una cartella fa fallire la creazione, senza toccare le ACL reali
        // dell'utente.
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let blocking_file = directory.path().join("logs");
        let Ok(()) = std::fs::write(&blocking_file, b"non e' una cartella") else {
            panic!("il file di blocco deve potersi scrivere");
        };

        assert!(open_daily_file_writer(&blocking_file).is_err());
    }

    #[test]
    fn an_unusable_log_directory_degrades_instead_of_terminating_the_application() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let blocking_file = directory.path().join("logs");
        let Ok(()) = std::fs::write(&blocking_file, b"non e' una cartella") else {
            panic!("il file di blocco deve potersi scrivere");
        };

        // Il solo fatto che questa chiamata ritorni, invece di andare in
        // panic, e' parte di quanto il test dimostra.
        let guard = initialize_in(blocking_file);

        assert!(guard.degraded());
    }

    #[test]
    fn a_writable_log_directory_does_not_degrade() {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let target = directory.path().join("logs");

        let guard = initialize_in(target);

        assert!(!guard.degraded());
    }
}

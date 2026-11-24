//! Collegamento fra la sezione «Copia di sicurezza» e il servizio omonimo.
//!
//! # Perché la cartella si sceglie e non si digita
//!
//! Una cartella scelta da una finestra di sistema esiste per costruzione, e non
//! c'è un testo da convalidare che possa contenere qualcosa di inatteso
//! (DEC-113). È la stessa regola della cartella dei documenti.
//!
//! # Perché l'avvertenza non sta qui
//!
//! Che cosa la copia **non** salva è scritto nella schermata come testo fisso,
//! non in questo modulo come messaggio di esito: chi lo legge dopo un guasto lo
//! legge troppo tardi.
//!
//! # La frase della copia cifrata (ENCRYPT-01, ADR-0175)
//!
//! Si legge dai campi al clic, e i campi si svuotano subito, prima della
//! finestra di scelta: una frase non resta scritta in schermata mentre
//! l'operatore sceglie una cartella, e non resta dopo un annullamento.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use lisi_services::backup::BackupService;
use lisi_services::sealed_backup::{MIN_PHRASE_CHARS, Opener, SEALED_EXTENSION};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;

/// Servizio della copia condiviso fra i gestori.
pub type SharedBackup = Rc<RefCell<BackupService>>;

/// Crea il servizio della copia sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedBackup> {
    Some(Rc::new(RefCell::new(BackupService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> lisi_services::ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// La finestra che chiede all'operatore dove scrivere la copia.
fn destination_dialog() -> rfd::AsyncFileDialog {
    rfd::AsyncFileDialog::new().set_title("Scegliere la cartella dove scrivere la copia")
}

/// Esegue la copia e restituisce il messaggio da mostrare, con l'esito.
///
/// # Perché una copia scritta ma non riletta è un fallimento
///
/// «Il comando è riuscito» e «esiste un archivio utilizzabile» sono due fatti
/// diversi, e solo il secondo serve a qualcosa. Se la rilettura non riesce, la
/// schermata lo dice in ambra: fidarsi di quella copia sarebbe peggio che non
/// averla, perché nessuno ne farebbe un'altra.
fn run(backup: &SharedBackup, destination: &std::path::Path) -> (String, bool) {
    let outcome = {
        let service = backup.borrow();
        actor().and_then(|actor| service.write_to(destination, &actor, now()))
    };

    match outcome {
        Ok(copia) => {
            let fallita = !copia.outcome.verified;
            if fallita {
                tracing::warn!("copia di sicurezza scritta ma non rileggibile");
            }
            (copia.operator_message(), fallita)
        }
        Err(error) => {
            tracing::warn!(kind = error.kind(), "copia di sicurezza non riuscita");
            (error.operator_message(), true)
        }
    }
}

/// Il rifiuto di una frase prima di scrivere, o niente se la frase va bene.
fn phrase_problem(phrase: &str, again: &str) -> Option<String> {
    if phrase.chars().count() < MIN_PHRASE_CHARS {
        return Some(format!(
            "La copia cifrata non è stata scritta: la frase deve avere almeno \
             {MIN_PHRASE_CHARS} caratteri."
        ));
    }
    if phrase != again {
        return Some(String::from(
            "La copia cifrata non è stata scritta: le due frasi non coincidono. \
             Scrivere di nuovo le due frasi.",
        ));
    }
    None
}

/// Scrive la copia cifrata e restituisce il messaggio da mostrare, con
/// l'esito.
///
/// `work` è la cartella dove nasce e muore la fotografia in chiaro: la
/// cartella dei dati, accanto all'archivio vivo.
fn run_sealed(
    backup: &SharedBackup,
    destination: &Path,
    work: &Path,
    phrase: &str,
    again: &str,
    with_user: bool,
) -> (String, bool) {
    if let Some(problema) = phrase_problem(phrase, again) {
        return (problema, true);
    }
    let outcome = {
        let service = backup.borrow();
        actor().and_then(|actor| {
            service.write_sealed_to(destination, work, phrase, with_user, &actor, now())
        })
    };
    match outcome {
        Ok(copia) => (copia.operator_message(), false),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "copia cifrata non riuscita");
            (error.operator_message(), true)
        }
    }
}

/// Apre una copia cifrata e restituisce il messaggio da mostrare, con
/// l'esito. Una frase vuota vuol dire «con questo utente Windows».
fn run_open(
    backup: &SharedBackup,
    sealed: &Path,
    phrase: &str,
    directory: &Path,
) -> (String, bool) {
    let opener = if phrase.is_empty() {
        Opener::User
    } else {
        Opener::Phrase(phrase)
    };
    let outcome = {
        let service = backup.borrow();
        actor().and_then(|actor| service.open_sealed_to(sealed, &opener, directory, &actor, now()))
    };
    match outcome {
        Ok(copia) => (copia.operator_message(), !copia.verified),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "copia cifrata non aperta");
            (error.operator_message(), true)
        }
    }
}

/// Legge le due frasi e svuota i campi.
fn take_phrases(window: &AppWindow) -> (String, String) {
    let frase = window.get_sealed_phrase().to_string();
    let di_nuovo = window.get_sealed_phrase_again().to_string();
    window.set_sealed_phrase(SharedString::new());
    window.set_sealed_phrase_again(SharedString::new());
    (frase, di_nuovo)
}

/// Mostra l'esito della copia cifrata.
fn show_sealed(window: &AppWindow, (messaggio, fallita): (String, bool)) {
    window.set_sealed_message(crate::lingua::schermo(messaggio));
    window.set_sealed_failed(fallita);
}

/// Collega i comandi della copia cifrata al servizio.
fn wire_sealed(window: &AppWindow, backup: &SharedBackup) {
    let handle = window.as_weak();
    let servizio = Rc::clone(backup);
    window.on_make_sealed_backup(move || {
        if crate::lock::refuse_while_locked("make_sealed_backup") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let (frase, di_nuovo) = take_phrases(&window);
        // Una frase che non va si dice subito: scegliere una cartella per
        // sentirsi dire poi che la frase era corta fa perdere tempo.
        if let Some(problema) = phrase_problem(&frase, &di_nuovo) {
            show_sealed(&window, (problema, true));
            return;
        }
        let con_utente = window.get_sealed_with_user();
        let servizio = Rc::clone(&servizio);
        crate::dialogs::ask(
            &window,
            rfd::AsyncFileDialog::new()
                .set_title("Scegliere la cartella dove scrivere la copia cifrata"),
            crate::dialogs::Pick::Folder,
            "make_sealed_backup",
            move |window, destinazione: PathBuf| {
                window.set_sealed_message(crate::lingua::schermo(
                    "Copia cifrata in corso: può richiedere qualche istante.",
                ));
                let esito = match lisi_services::data_directory::application_directory() {
                    Ok(lavoro) => run_sealed(
                        &servizio,
                        &destinazione,
                        &lavoro,
                        &frase,
                        &di_nuovo,
                        con_utente,
                    ),
                    Err(error) => (error.operator_message(), true),
                };
                show_sealed(window, esito);
            },
        );
    });

    let handle = window.as_weak();
    let servizio = Rc::clone(backup);
    window.on_open_sealed_backup(move || {
        if crate::lock::refuse_while_locked("open_sealed_backup") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };
        let (frase, _) = take_phrases(&window);
        let servizio = Rc::clone(&servizio);
        crate::dialogs::ask(
            &window,
            rfd::AsyncFileDialog::new()
                .set_title("Scegliere la copia cifrata da aprire")
                .add_filter("Copia cifrata NEXUM/97", &[SEALED_EXTENSION]),
            crate::dialogs::Pick::File,
            "open_sealed_backup",
            move |window, copia: PathBuf| {
                crate::dialogs::ask(
                    window,
                    rfd::AsyncFileDialog::new()
                        .set_title("Scegliere la cartella dove scrivere la copia aperta"),
                    crate::dialogs::Pick::Folder,
                    "open_sealed_backup",
                    move |window, cartella: PathBuf| {
                        window.set_sealed_message(crate::lingua::schermo(
                            "Apertura in corso: può richiedere qualche istante.",
                        ));
                        show_sealed(window, run_open(&servizio, &copia, &frase, &cartella));
                    },
                );
            },
        );
    });
}

/// Collega i comandi della sezione al servizio.
pub fn wire(window: &AppWindow, backup: &SharedBackup) {
    wire_sealed(window, backup);

    let handle = window.as_weak();
    let backup = Rc::clone(backup);
    window.on_make_backup(move || {
        if crate::lock::refuse_while_locked("make_backup") {
            return;
        }
        let Some(window) = handle.upgrade() else {
            return;
        };

        // Finestra chiusa senza scegliere: non e' un errore e non si annuncia
        // nulla. Un messaggio dopo un annullamento fa credere che sia successo
        // qualcosa.
        let backup = Rc::clone(&backup);
        crate::dialogs::ask(
            &window,
            destination_dialog(),
            crate::dialogs::Pick::Folder,
            "make_backup",
            move |window, destinazione: PathBuf| {
                window.set_backup_message(crate::lingua::schermo(
                    "Copia in corso: può richiedere qualche istante.",
                ));

                let (messaggio, fallita) = run(&backup, &destinazione);
                window.set_backup_message(crate::lingua::schermo(messaggio));
                window.set_backup_failed(fallita);
                // La copia e' un prerequisito della fascia di prontezza (F-08).
                crate::preflight::mark_stale();
            },
        );
    });
}

#[cfg(test)]
mod tests {
    use lisi_services::backup::BackupService;

    use super::{create_service, run};

    fn servizio() -> super::SharedBackup {
        let Ok(database) = lisi_services::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let Some(condiviso) = create_service(database) else {
            panic!("il servizio deve potersi creare");
        };
        condiviso
    }

    /// **Una copia riuscita non viene annunciata come fallita.**
    #[test]
    fn una_copia_riuscita_non_si_colora_di_ambra() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let (messaggio, fallita) = run(&servizio(), cartella.path());
        assert!(!fallita, "una copia riuscita non deve segnalare un guasto");
        assert!(
            messaggio.contains("credenziali"),
            "l'esito non ricorda che le credenziali restano qui: «{messaggio}»"
        );
    }

    /// **Una cartella che non esiste lo dice, e lo dice in ambra.**
    ///
    /// Il caso che conta non e' l'errore: e' che il messaggio NON assomigli a un
    /// successo. Un operatore che leggesse una frase neutra crederebbe di avere
    /// una copia che non ha.
    #[test]
    fn una_copia_non_riuscita_si_vede() {
        let inesistente = std::path::Path::new("C:/questa/cartella/non/esiste");
        let (messaggio, fallita) = run(&servizio(), inesistente);
        assert!(fallita, "un fallimento deve risultare tale");
        assert!(
            !messaggio.contains("scritta in"),
            "il messaggio di errore assomiglia a un esito positivo: «{messaggio}»"
        );
    }

    /// **Il servizio non tiene aperta una copia dell'archivio a vuoto.**
    #[test]
    fn il_servizio_espone_l_archivio_su_cui_lavora() {
        let Ok(database) = lisi_services::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let servizio = BackupService::new(database);
        let Ok(_) = servizio.database().audit_entries() else {
            panic!("l'archivio del servizio deve essere utilizzabile");
        };
    }

    /// Il sorgente della schermata, letto a tempo di compilazione.
    const SCHERMATA: &str = include_str!("../ui/app-window.slint");

    /// **Il testo fisso della sezione dice chi può aprire la copia, che dove
    /// i permessi non si restringono la copia non si scrive, e che i permessi
    /// non viaggiano** (SEC-01, criterio 9).
    ///
    /// Detto prima del clic: chi sceglie una chiavetta deve sapere in anticipo
    /// perché la copia potrebbe non scriversi, e chi la porta altrove deve
    /// sapere che la protezione resta qui.
    #[test]
    fn la_sezione_dice_chi_puo_aprire_la_copia_prima_del_clic() {
        let Some((_, dopo)) = SCHERMATA.split_once("text: @tr(\"COPIA DI SICUREZZA\")") else {
            panic!("la sezione della copia non c'e' piu'");
        };
        let Some((sezione, _)) = dopo.split_once("root.make-backup()") else {
            panic!("il pulsante della copia non c'e' piu'");
        };
        for frase in [
            "La copia nasce leggibile dal solo utente Windows che la scrive.",
            "la copia non si scrive.",
            "I permessi non viaggiano",
        ] {
            assert!(
                sezione.contains(frase),
                "prima del pulsante la sezione non dice «{frase}»"
            );
        }
    }

    /// Chiude una cartella come una chiavetta che non conserva i permessi, e
    /// ne controlla la premessa su un file testimone. È la forma di
    /// `permessi_di_prova::rifiuta_i_permessi` di `lisi-services`, che da qui
    /// non si vede: le ragioni (niente `icacls`, niente `PSModulePath`) stanno
    /// lì e in DEC-513.
    #[cfg(windows)]
    fn rifiuta_i_permessi(cartella: &std::path::Path) {
        const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
             $p = $env:NEXUM_PROVA_PERCORSO; \
             $ds = New-Object System.Security.AccessControl.DirectorySecurity; \
             $ds.SetAccessRuleProtection($true, $false); \
             foreach ($s in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, \
                 (New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')))) { \
               $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule( \
                 $s, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }; \
             [System.IO.Directory]::SetAccessControl($p, $ds); \
             $t = [System.IO.Path]::Combine($p, 'testimone.txt'); \
             [System.IO.File]::WriteAllText($t, 'testimone'); \
             $cambiati = $true; \
             try { $f = [System.IO.File]::GetAccessControl($t); \
                   $f.SetAccessRuleProtection($true, $true); \
                   [System.IO.File]::SetAccessControl($t, $f) } catch { $cambiati = $false }; \
             [System.IO.File]::Delete($t); \
             'TESTIMONE|' + $cambiati";
        let Ok(uscita) = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                SCRIPT,
            ])
            .env("NEXUM_PROVA_PERCORSO", cartella)
            .env_remove("PSModulePath")
            .output()
        else {
            panic!("PowerShell deve potersi avviare per chiudere la cartella");
        };
        let testo = String::from_utf8_lossy(&uscita.stdout);
        assert!(
            uscita.status.success() && testo.lines().any(|riga| riga.trim() == "TESTIMONE|False"),
            "la premessa non regge: la cartella che rifiuta i permessi li accetta ({testo} {})",
            String::from_utf8_lossy(&uscita.stderr)
        );
    }

    /// **Una copia rifiutata per i permessi si vede, in ambra, e dice che
    /// cosa fare** (SEC-01, criterio 6).
    ///
    /// La cartella toglie all'utente il diritto di cambiare i permessi di ciò
    /// che vi crea (voce `OWNER RIGHTS`), come una chiavetta che non li
    /// conserva.
    #[cfg(windows)]
    #[test]
    fn una_copia_rifiutata_per_i_permessi_si_vede_e_dice_che_cosa_fare() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        rifiuta_i_permessi(cartella.path());

        let (messaggio, fallita) = run(&servizio(), cartella.path());
        assert!(fallita, "un rifiuto deve comparire in ambra");
        assert!(messaggio.contains("NON è stata scritta"), "{messaggio}");
        assert!(messaggio.contains("Scegliere una cartella"), "{messaggio}");
        let Ok(voci) = std::fs::read_dir(cartella.path()) else {
            panic!("la cartella deve potersi elencare");
        };
        assert_eq!(voci.count(), 0, "un rifiuto ha lasciato qualcosa sul disco");
    }

    /// **L'avvertenza su cio' che la copia NON salva sta fissa in schermata.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// L'avvertenza non e' un messaggio di esito: appare PRIMA che qualcuno
    /// prema il pulsante, e resta anche dopo. Se finisse dentro il messaggio di
    /// esito - dove sembrerebbe piu' ordinata - la leggerebbe solo chi una copia
    /// l'ha gia' fatta, e la leggerebbe come una nota a margine di un successo.
    ///
    /// Chi la legge dopo un guasto la legge troppo tardi: e' il giorno in cui
    /// l'ufficio scopre che la copia rimette l'archivio e non l'accesso.
    ///
    /// Toglierla non romperebbe niente. Nessuna prova diventerebbe rossa.
    #[test]
    fn la_schermata_dice_sempre_che_cosa_la_copia_non_salva() {
        assert!(
            SCHERMATA.contains("COPIA DI SICUREZZA"),
            "la sezione della copia non c'e' piu': questa prova non sta piu' \
             guardando cio' che crede"
        );
        assert!(
            SCHERMATA.contains("rimette l'archivio, non l'accesso"),
            "la schermata non dice piu' che la copia NON rimette l'accesso: un \
             ufficio lo scoprirebbe il giorno del guasto"
        );
        assert!(
            SCHERMATA.contains("root.make-backup()"),
            "nessun comando invoca la copia: la capacita' esisterebbe senza che \
             nessuno possa usarla"
        );
    }

    /// **La schermata non promette un ripristino che il prodotto non fa.**
    ///
    /// Sovrascrivere l'archivio in uso con uno piu' vecchio cancellerebbe mesi
    /// di lavoro in un secondo (ADR-0043, decisione 4). Un pulsante che lo
    /// facesse per sbaglio sarebbe la cosa piu' distruttiva del prodotto.
    #[test]
    fn la_schermata_non_offre_un_pulsante_di_ripristino() {
        for proibito in ["Ripristina", "ripristina l'archivio", "restore-backup"] {
            assert!(
                !SCHERMATA.contains(proibito),
                "la schermata offre «{proibito}»: il prodotto non ripristina, e un \
                 comando che sovrascrivesse l'archivio in uso cancellerebbe mesi \
                 di lavoro in un secondo"
            );
        }
        assert!(
            SCHERMATA.contains("non ripristina da solo"),
            "la schermata non dichiara che il ripristino e' a mano: chi cerca quel \
             pulsante e non lo trova crederebbe a un difetto"
        );
    }

    /// Una frase di prova, lunga abbastanza.
    const FRASE: &str = "una frase di prova abbastanza lunga";

    /// **Una frase corta o due frasi diverse si dicono prima della cartella,
    /// in ambra** (ENCRYPT-01 parte 3, criterio 2).
    #[test]
    fn una_frase_che_non_va_si_dice_prima_di_scrivere() {
        let Some(corta) = super::phrase_problem("corta", "corta") else {
            panic!("una frase corta deve essere rifiutata");
        };
        assert!(corta.contains("almeno 16 caratteri"), "{corta}");
        let Some(diverse) = super::phrase_problem(FRASE, "un'altra frase abbastanza lunga") else {
            panic!("due frasi diverse devono essere rifiutate");
        };
        assert!(diverse.contains("non coincidono"), "{diverse}");
        assert!(super::phrase_problem(FRASE, FRASE).is_none());

        let (Ok(destinazione), Ok(lavoro)) = (tempfile::tempdir(), tempfile::tempdir()) else {
            panic!("le cartelle temporanee devono potersi creare");
        };
        let (messaggio, fallita) = super::run_sealed(
            &servizio(),
            destinazione.path(),
            lavoro.path(),
            FRASE,
            "un'altra frase abbastanza lunga",
            false,
        );
        assert!(fallita, "{messaggio}");
        let Ok(voci) = std::fs::read_dir(destinazione.path()) else {
            panic!("la cartella deve potersi elencare");
        };
        assert_eq!(voci.count(), 0, "un rifiuto ha lasciato qualcosa sul disco");
    }

    /// **Dalla schermata, la copia cifrata si scrive e si riapre; l'esito non
    /// è in ambra e non contiene la frase** (criteri 1 e 3).
    #[test]
    fn la_copia_cifrata_si_scrive_e_si_riapre_dalla_schermata() {
        let (Ok(destinazione), Ok(lavoro), Ok(aperta)) = (
            tempfile::tempdir(),
            tempfile::tempdir(),
            tempfile::tempdir(),
        ) else {
            panic!("le cartelle temporanee devono potersi creare");
        };
        let backup = servizio();
        let (scritta, fallita) = super::run_sealed(
            &backup,
            destinazione.path(),
            lavoro.path(),
            FRASE,
            FRASE,
            false,
        );
        assert!(!fallita, "{scritta}");
        assert!(scritta.contains("Copia cifrata scritta"), "{scritta}");
        assert!(!scritta.contains(FRASE), "{scritta}");

        let Ok(voci) = std::fs::read_dir(destinazione.path()) else {
            panic!("la cartella deve potersi elencare");
        };
        let Some(copia) = voci
            .filter_map(Result::ok)
            .map(|voce| voce.path())
            .find(|percorso| {
                percorso
                    .extension()
                    .is_some_and(|estensione| estensione == super::SEALED_EXTENSION)
            })
        else {
            panic!("la copia cifrata deve essere nella cartella scelta");
        };

        let (aperto, fallita) = super::run_open(&backup, &copia, FRASE, aperta.path());
        assert!(!fallita, "{aperto}");
        assert!(aperto.contains("leggibile dal solo utente"), "{aperto}");
        assert!(
            aperto.contains("L'archivio in uso non è cambiato"),
            "{aperto}"
        );

        let (sbagliata, fallita) = super::run_open(
            &backup,
            &copia,
            "un'altra frase abbastanza lunga",
            destinazione.path(),
        );
        assert!(
            fallita,
            "una frase sbagliata deve comparire in ambra: {sbagliata}"
        );
    }

    /// **La sezione della copia cifrata dice, prima del clic, che chi perde la
    /// frase perde la copia, e che aprire non tocca l'archivio in uso**
    /// (criteri 4 e 5).
    #[test]
    fn la_sezione_della_copia_cifrata_dice_che_cosa_costa_la_frase() {
        let Some((_, dopo)) = SCHERMATA.split_once("text: @tr(\"COPIA CIFRATA\")") else {
            panic!("la sezione della copia cifrata non c'e'");
        };
        let Some((prima_del_clic, dopo_il_clic)) = dopo.split_once("root.make-sealed-backup()")
        else {
            panic!("il pulsante della copia cifrata non c'e'");
        };
        for frase in [
            "almeno sedici caratteri",
            "chi perde la frase perde la copia",
            "anche su una chiavetta",
        ] {
            assert!(
                prima_del_clic.contains(frase),
                "prima del pulsante la sezione non dice «{frase}»"
            );
        }
        assert!(dopo_il_clic.contains("root.open-sealed-backup()"));
        assert!(dopo_il_clic.contains("l'archivio in uso"));
    }
}

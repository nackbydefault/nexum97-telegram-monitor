//! Se il prodotto può davvero scrivere nella propria cartella dati.
//!
//! # Il difetto che questo modulo esiste per impedire
//!
//! Il 2026-08-18, sulla prima installazione reale, l'archivio dell'operatore
//! **non si è aperto**: ventidue fallimenti per avvio, e il programma ha
//! ripiegato su un'archiviazione in memoria perdendo tutto alla chiusura.
//!
//! La causa non era il codice, non erano le migrazioni, non era la concorrenza:
//! erano i **permessi sui file**. La cartella dati apparteneva a
//! `BUILTIN\Administrators` e l'utente non vi poteva scrivere.
//!
//! Ci sono volute ore per arrivarci, e la ragione è che il prodotto non lo
//! diceva: falliva ventidue volte, ognuna con un messaggio tecnico diverso, e
//! nessuno di quei messaggi diceva «non posso scrivere qui».
//!
//! # Perché si prova a scrivere invece di leggere i permessi
//!
//! Su Windows i permessi effettivi di una cartella sono il risultato di ACL
//! ereditate, negazioni esplicite, appartenenze a gruppi e virtualizzazione.
//! Leggerli e dedurne la risposta è complicato **e sbagliato**: la deduzione può
//! divergere da ciò che il sistema decide davvero al momento della scrittura.
//!
//! L'unico modo affidabile di sapere se si può scrivere è **scrivere**. Questo
//! modulo crea un file di prova, lo rilegge, e lo cancella.
//!
//! # Che cosa questo modulo NON fa
//!
//! **Non allarga i permessi.** Se la cartella non è scrivibile, lo dice; non
//! tenta di prendersi diritti che non ha. Un programma che si concede da sé
//! l'accesso a una cartella protetta è un programma di cui non ci si può fidare,
//! e la correzione — quando serve — la fa chi amministra la postazione.
//!
//! **Non tocca i dati.** Il file di prova ha un nome dichiarato, un contenuto
//! che non dice nulla, e viene rimosso subito. Se restasse, sarebbe un file
//! misterioso in una cartella di servizio.

use std::path::{Path, PathBuf};

use crate::error::{ServiceError, ServiceResult};

/// Nome del file con cui si verifica la scrittura.
///
/// Comincia con un punto e **dice di se stesso che cos'è**: se un giorno
/// restasse per un arresto improvviso, chi lo trova deve capire in due secondi
/// che non è un dato e si può cancellare.
const PROBE_FILE: &str = ".nexum97-verifica-scrittura";

/// Il nome del file di verifica **deve** cominciare con un punto.
///
/// E' una convenzione, e come tale si dimentica. Verificarla a tempo di
/// COMPILAZIONE e' piu' forte di una prova: chi la violasse non riuscirebbe
/// nemmeno a costruire il prodotto, invece di scoprirlo eseguendo le prove.
const _: () = assert!(PROBE_FILE.as_bytes()[0] == b'.');

/// Contenuto del file di prova.
///
/// Non è vuoto perché un file di zero byte può essere creato anche dove la
/// scrittura effettiva fallisce; ed è una frase innocua perché quella cartella
/// può finire in una copia di sicurezza o sotto gli occhi di chi amministra.
const PROBE_CONTENT: &[u8] = b"verifica di scrittura di NEXUM/97; questo file si puo' cancellare\n";

/// Che cosa il prodotto può fare con la propria cartella dati.
///
/// # Perché un tipo e non un booleano
///
/// «Non posso scrivere» e «non so nemmeno dove scrivere» sono due situazioni
/// diverse, con due cause diverse e due rimedi diversi. Un booleano le
/// confonderebbe, e chi legge il registro si troverebbe davanti allo stesso
/// messaggio per due problemi che non si risolvono allo stesso modo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDirectoryState {
    /// La cartella esiste e vi si può scrivere. È il caso normale.
    Writable {
        /// Dove.
        path: PathBuf,
    },
    /// La cartella dati non è determinabile su questa postazione.
    Undeterminable {
        /// Che cosa è mancato.
        reason: String,
    },
    /// La cartella non esiste e non si è potuta creare.
    NotCreatable {
        /// Dove si è tentato.
        path: PathBuf,
        /// Che cosa ha risposto il sistema.
        reason: String,
    },
    /// La cartella esiste ma non vi si può scrivere.
    NotWritable {
        /// Dove.
        path: PathBuf,
        /// Che cosa ha risposto il sistema.
        reason: String,
    },
}

impl DataDirectoryState {
    /// Se il prodotto può conservare ciò che acquisisce.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::Writable { .. })
    }

    /// La frase da mostrare all'operatore.
    ///
    /// Dice **che cosa succederà** e **che cosa fare**, in quest'ordine. Un
    /// avviso che descrive un guaio senza indicare un gesto lascia chi lo riceve
    /// nella stessa posizione di prima, con in più l'ansia.
    ///
    /// Il percorso compare: senza, chi deve correggere i permessi non sa su
    /// quale cartella intervenire.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Writable { .. } => String::new(),
            Self::Undeterminable { .. } => String::from(
                "Non è stato possibile stabilire dove conservare i dati su questa \
                 postazione. Tutto ciò che si inserisce ora SARÀ PERDUTO alla \
                 chiusura. Segnalarlo a chi amministra la postazione.",
            ),
            Self::NotCreatable { path, .. } => format!(
                "La cartella dei dati non si è potuta creare: {}. Tutto ciò che si \
                 inserisce ora SARÀ PERDUTO alla chiusura. Serve che chi amministra \
                 la postazione consenta la scrittura in quella posizione.",
                path.display()
            ),
            Self::NotWritable { path, .. } => format!(
                "La cartella dei dati esiste ma non vi si può scrivere: {}. Tutto ciò \
                 che si inserisce ora SARÀ PERDUTO alla chiusura. Serve che chi \
                 amministra la postazione conceda a questo utente il permesso di \
                 scrittura su quella cartella.",
                path.display()
            ),
        }
    }

    /// La causa tecnica, per il registro.
    ///
    /// Separata dal messaggio all'operatore perché servono a due persone
    /// diverse: questa la legge chi può intervenire sul sistema.
    #[must_use]
    pub fn technical_reason(&self) -> &str {
        match self {
            Self::Writable { .. } => "",
            Self::Undeterminable { reason }
            | Self::NotCreatable { reason, .. }
            | Self::NotWritable { reason, .. } => reason,
        }
    }
}

/// Verifica la cartella dati predefinita dell'applicazione.
///
/// # Errori
///
/// Non ne restituisce: ogni esito è un valore, compreso il fallimento. Una
/// verifica che potesse *fallire* invece di *rispondere* costringerebbe ogni
/// chiamante a distinguere due generi di guasto dove ce n'è uno solo.
#[must_use]
pub fn check() -> DataDirectoryState {
    match application_directory() {
        Ok(path) => check_at(&path),
        Err(error) => DataDirectoryState::Undeterminable {
            reason: error.to_string(),
        },
    }
}

/// La cartella dati dell'applicazione, senza il file di configurazione.
///
/// È quella **del modo del processo** (PR-13, ADR-0129): in Esercitazione una
/// cartella accanto a quella operativa, mai dentro. È l'unica composizione del
/// percorso: archivio, file protetti, blocco, registro e configurazione la
/// usano tutti, così che l'Esercitazione non possa scrivere un solo file nella
/// cartella operativa.
///
/// # Errori
///
/// Se `%LOCALAPPDATA%` non è leggibile.
pub fn application_directory() -> ServiceResult<PathBuf> {
    mode_directory().ok_or_else(|| ServiceError::SessionUnavailable {
        reason: String::from("cartella dati locale non determinabile"),
    })
}

/// La cartella dati del modo del processo, se `%LOCALAPPDATA%` è leggibile.
///
/// Per chi deve tradurre l'assenza in un errore suo.
#[must_use]
pub fn mode_directory() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(lisi_core::model::run_mode::data_root_in(
        Path::new(&base),
        crate::run_mode::current(),
    ))
}

/// Verifica una cartella indicata.
///
/// È il **seam** che le prove usano: verificare la cartella vera significherebbe
/// scrivere nella cartella dell'operatore per provare che si può scrivere nella
/// cartella dell'operatore.
#[must_use]
pub fn check_at(path: &Path) -> DataDirectoryState {
    if !path.exists()
        && let Err(error) = std::fs::create_dir_all(path)
    {
        return DataDirectoryState::NotCreatable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        };
    }

    let probe = path.join(PROBE_FILE);

    if let Err(error) = std::fs::write(&probe, PROBE_CONTENT) {
        return DataDirectoryState::NotWritable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        };
    }

    // **Si rilegge.** Su alcune configurazioni una scrittura riesce e il
    // contenuto non arriva: virtualizzazione, quote, filtri. Scrivere e non
    // rileggere proverebbe che la chiamata non ha dato errore, non che il dato
    // c'e'.
    let riletto = std::fs::read(&probe);

    // Il file si toglie **sempre**, anche se la rilettura e' fallita: lasciarlo
    // significherebbe abbandonare un file di servizio in una cartella di dati.
    let rimozione = std::fs::remove_file(&probe);

    match riletto {
        Ok(bytes) if bytes == PROBE_CONTENT => {
            if let Err(error) = rimozione {
                // Si scrive ma non si cancella: la cartella e' utilizzabile per
                // conservare, e non per fare pulizia. E' un caso che va detto.
                return DataDirectoryState::NotWritable {
                    path: path.to_path_buf(),
                    reason: format!("scrittura riuscita, rimozione no: {error}"),
                };
            }
            DataDirectoryState::Writable {
                path: path.to_path_buf(),
            }
        }
        Ok(_) => DataDirectoryState::NotWritable {
            path: path.to_path_buf(),
            reason: String::from(
                "il file di prova è stato riletto diverso da come è stato scritto",
            ),
        },
        Err(error) => DataDirectoryState::NotWritable {
            path: path.to_path_buf(),
            reason: format!("scrittura riuscita, rilettura no: {error}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{DataDirectoryState, PROBE_CONTENT, PROBE_FILE, check_at};

    #[test]
    fn una_cartella_nuova_risulta_scrivibile_e_non_lascia_tracce() {
        let temporanea = tempfile::tempdir().expect("cartella temporanea");
        let percorso = temporanea.path().join("dati");

        let stato = check_at(&percorso);

        assert!(
            stato.is_writable(),
            "una cartella nuova deve essere scrivibile: {stato:?}"
        );
        assert!(percorso.exists(), "la cartella deve essere stata creata");

        // **Il file di prova non deve restare.** Un file misterioso in una
        // cartella di servizio e' un file che qualcuno prima o poi apre.
        assert!(
            !percorso.join(PROBE_FILE).exists(),
            "il file di verifica e' rimasto sul disco"
        );
        let Ok(contenuto) = std::fs::read_dir(&percorso) else {
            panic!("la cartella deve potersi leggere");
        };
        assert_eq!(contenuto.count(), 0, "la verifica non deve lasciare nulla");
    }

    #[test]
    fn una_cartella_che_non_si_puo_creare_lo_dice_invece_di_fingere() {
        let temporanea = tempfile::tempdir().expect("cartella temporanea");

        // Un FILE al posto della cartella padre: creare qualcosa dentro un file
        // non e' possibile su nessun sistema, ed e' il modo piu' semplice di
        // ottenere un fallimento vero invece di simularlo.
        let ostacolo = temporanea.path().join("ostacolo");
        std::fs::write(&ostacolo, b"non sono una cartella").expect("il file di prova deve nascere");

        let stato = check_at(&ostacolo.join("dati"));

        assert!(!stato.is_writable());
        assert!(
            matches!(stato, DataDirectoryState::NotCreatable { .. }),
            "atteso NotCreatable, ottenuto {stato:?}"
        );
        assert!(
            !stato.technical_reason().is_empty(),
            "la causa tecnica deve esserci"
        );
    }

    #[test]
    fn ogni_stato_di_guasto_dice_che_cosa_accadra_e_che_cosa_fare() {
        // Un avviso che descrive un guaio senza indicare un gesto lascia chi lo
        // riceve nella stessa posizione di prima, con in piu' l'ansia.
        let guasti = [
            DataDirectoryState::Undeterminable {
                reason: String::from("x"),
            },
            DataDirectoryState::NotCreatable {
                path: std::path::PathBuf::from("C:\\prova"),
                reason: String::from("x"),
            },
            DataDirectoryState::NotWritable {
                path: std::path::PathBuf::from("C:\\prova"),
                reason: String::from("x"),
            },
        ];

        for stato in guasti {
            let messaggio = stato.operator_message();
            assert!(
                messaggio.contains("SARÀ PERDUTO"),
                "lo stato {stato:?} non dice al certo che cosa accadra': «{messaggio}»"
            );
            assert!(
                messaggio.contains("amministra") || messaggio.contains("Segnalarlo"),
                "lo stato {stato:?} non dice a chi rivolgersi: «{messaggio}»"
            );
        }
    }

    #[test]
    fn lo_stato_normale_non_ha_nulla_da_dire() {
        // Un avviso che compare anche quando va tutto bene smette di essere un
        // avviso.
        let stato = DataDirectoryState::Writable {
            path: std::path::PathBuf::from("C:\\prova"),
        };
        assert!(stato.operator_message().is_empty());
        assert!(stato.technical_reason().is_empty());
    }

    #[test]
    fn il_file_di_prova_non_contiene_dati_e_dice_di_se_che_si_puo_cancellare() {
        // Quella cartella puo' finire in una copia di sicurezza o sotto gli
        // occhi di chi amministra: il file di prova non deve far pensare a un
        // dato, e chi lo trovasse deve capire in due secondi che si cancella.
        let testo = String::from_utf8(PROBE_CONTENT.to_vec()).expect("il contenuto e' testo");
        assert!(testo.contains("cancellare"));
        assert!(testo.contains("NEXUM/97"));
        // Che il nome cominci con un punto e' garantito a tempo di
        // compilazione, piu' sopra: qui sarebbe un'asserzione su una costante.
    }

    /// **La cartella dell'applicazione deve stare sotto `%LOCALAPPDATA%`.**
    ///
    /// E' l'unica cosa che la protegge: quella cartella porta gia', per
    /// impostazione di Windows, un elenco di permessi ristretto — controllo
    /// completo all'utente proprietario, a SYSTEM e agli amministratori locali —
    /// e una cartella creata li' lo **eredita** (ADR-0041).
    ///
    /// Se un giorno qualcuno la spostasse — una configurazione, una variabile
    /// manomessa, una svista in un refactoring — l'eredita' sparirebbe **in
    /// silenzio**, perche' niente smetterebbe di funzionare.
    #[test]
    fn la_cartella_dell_applicazione_eredita_i_permessi_del_profilo() {
        let Ok(base) = std::env::var("LOCALAPPDATA") else {
            // Senza la variabile non si sa dove guardare. Si dichiara e si
            // passa: inventare un percorso renderebbe la prova rossa su
            // configurazioni legittime.
            return;
        };

        let Ok(cartella) = super::application_directory() else {
            panic!("la cartella dell'applicazione deve essere determinabile");
        };

        assert!(
            cartella.starts_with(&base),
            "la cartella dati e' fuori da %LOCALAPPDATA%: perderebbe l'eredita' \
             dei permessi che la protegge, senza che nulla smetta di funzionare. \
             Attesa sotto «{base}», trovata «{}»",
            cartella.display()
        );
    }

    // L'installer e gli script di verifica stanno soltanto nell'archivio
    // (ADR-0210): le prove che li leggono non sono nella copia pubblica.
}

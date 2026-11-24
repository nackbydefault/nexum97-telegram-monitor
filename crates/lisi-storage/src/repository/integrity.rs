//! Se l'archivio è ancora sano.
//!
//! # Perché serve, e perché non basta che il prodotto «funzioni»
//!
//! Un archivio SQLite si danneggia in modi che non impediscono di aprirlo: una
//! caduta di corrente durante una scrittura, un settore che sta morendo, un
//! programma di backup che copia il file mentre viene scritto. Il prodotto
//! continua a partire, le schermate si riempiono, e il guasto si manifesta molto
//! più tardi — come un record che non si legge, o come un record che **non c'è
//! più e nessuno se ne accorge**.
//!
//! Per un archivio di monitoraggio d'ufficio la seconda è la peggiore: un
//! documento prodotto da un archivio danneggiato è un atto che nessuno può più
//! verificare, e nulla lo segnala.
//!
//! # Perché non si verifica a ogni avvio
//!
//! `PRAGMA quick_check` legge l'intero file. Su un archivio di qualche gigabyte
//! sono secondi a ogni avvio, tutti i giorni, per un guasto che è raro. Un
//! controllo che rallenta ogni avvio è un controllo che qualcuno prima o poi
//! spegne, e un controllo spento non protegge nulla.
//!
//! Si verifica **quando qualcuno lo chiede**, e l'esito è scritto in modo che
//! una persona lo capisca senza sapere che cos'è una pagina di database.

use crate::Database;
use crate::error::StorageResult;

/// L'esito di una verifica dell'archivio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    /// I problemi strutturali trovati, nelle parole di SQLite.
    ///
    /// Vuoto significa che il file è coerente. Non significa che il **contenuto**
    /// sia giusto: nessun controllo può dire questo.
    pub structural: Vec<String>,
    /// Quanti collegamenti fra tabelle risultano rotti.
    ///
    /// Un contenuto che punta a una fonte che non esiste più è un dato che
    /// nessuna schermata sa mostrare e nessun documento sa citare.
    pub broken_links: u64,
    /// La dimensione del file, in byte, quando è misurabile.
    ///
    /// Un archivio in memoria non ha un file: qui è `None`, e dirlo è più onesto
    /// che dichiarare zero.
    pub size_bytes: Option<u64>,
}

impl IntegrityReport {
    /// Vero se non è stato trovato nulla di rotto.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.structural.is_empty() && self.broken_links == 0
    }

    /// L'esito, in una frase che una persona legge.
    ///
    /// # Perché il messaggio dice che cosa fare
    ///
    /// «`database disk image is malformed`» è vero e inutile: chi lo legge in un
    /// ufficio non sa se deve chiamare qualcuno, spegnere il computer o
    /// continuare a lavorare. Un guasto che non si sa come affrontare produce o
    /// panico o indifferenza, e nessuna delle due è la reazione giusta.
    #[must_use]
    pub fn operator_message(&self) -> String {
        if self.is_healthy() {
            return String::from(
                "L'archivio è integro. Il controllo verifica che il file sia coerente; \
                 non può dire se ciò che contiene sia stato acquisito correttamente.",
            );
        }

        let mut testo = String::from("L'archivio risulta DANNEGGIATO. ");

        if !self.structural.is_empty() {
            testo.push_str(&format!(
                "Sono stati trovati {} problemi nella struttura del file. ",
                self.structural.len()
            ));
        }
        if self.broken_links > 0 {
            testo.push_str(&format!(
                "Ci sono {} collegamenti rotti fra le tabelle. ",
                self.broken_links
            ));
        }

        testo.push_str(
            "Non produrre documenti da questo archivio: un atto tratto da un archivio \
             danneggiato è un atto che nessuno può più verificare. Fermare il \
             monitoraggio, conservare una copia del file così com'è, e far esaminare \
             la postazione.",
        );
        testo
    }
}

impl Database {
    /// Verifica che l'archivio sia ancora sano.
    ///
    /// Esegue `PRAGMA quick_check` — che legge l'intero file — e il controllo dei
    /// collegamenti fra tabelle. È un'operazione **di sola lettura**: non ripara
    /// nulla e non tocca nulla.
    ///
    /// # Perché non ripara
    ///
    /// Riparare un archivio danneggiato significa decidere quali dati buttare, e
    /// non è una decisione che un programma di monitoraggio possa prendere da
    /// solo su materiale d'ufficio. Il prodotto dice che cosa ha trovato; che
    /// farne è di chi risponde dell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la verifica non è eseguibile. Un archivio così
    /// rotto da non lasciarsi nemmeno interrogare è esso stesso la risposta, e
    /// chi chiama deve trattare l'errore come un esito, non come un imprevisto.
    pub fn verify_integrity(&self) -> StorageResult<IntegrityReport> {
        // `quick_check` invece di `integrity_check`: trova gli stessi
        // danneggiamenti strutturali senza il controllo degli indici, che su un
        // archivio grande moltiplica il tempo per poco in più.
        let mut statement = self.connection.prepare("PRAGMA quick_check")?;
        let righe = statement.query_map([], |row| row.get::<_, String>(0))?;

        let mut structural = Vec::new();
        for riga in righe {
            let riga = riga?;
            // SQLite risponde con la sola parola «ok» quando va tutto bene.
            if riga.trim() != "ok" {
                structural.push(riga);
            }
        }
        drop(statement);

        let broken: i64 = self.connection.query_row(
            "SELECT count(*) FROM pragma_foreign_key_check",
            [],
            |row| row.get(0),
        )?;

        Ok(IntegrityReport {
            structural,
            broken_links: u64::try_from(broken).unwrap_or(0),
            size_bytes: self.file_size(),
        })
    }

    /// La dimensione dell'archivio, **senza** verificarne l'integrità.
    ///
    /// # Perché esiste accanto a [`Self::verify_integrity`]
    ///
    /// Perché sono due domande di costo diverso. La verifica legge **tutte** le
    /// pagine del file; la dimensione sono due `PRAGMA`. La diagnostica ha
    /// bisogno della seconda a ogni composizione, e farle pagare la prima
    /// significherebbe un controllo che rallenta l'apertura di una schermata —
    /// cioè un controllo che qualcuno prima o poi spegne.
    #[must_use]
    pub fn archive_size(&self) -> Option<u64> {
        self.file_size()
    }

    /// La dimensione del file dell'archivio, quando esiste un file.
    ///
    /// Si calcola da `page_count × page_size` e non dal filesystem: la
    /// connessione conosce il proprio database, mentre il percorso potrebbe
    /// essere stato spostato sotto i piedi, e i file del giornale WAL vivono
    /// accanto e falserebbero il conto in modi che cambiano da un istante
    /// all'altro.
    fn file_size(&self) -> Option<u64> {
        let pages: i64 = self
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .ok()?;
        let page_size: i64 = self
            .connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .ok()?;
        u64::try_from(pages.checked_mul(page_size)?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::IntegrityReport;

    #[test]
    fn un_archivio_appena_creato_e_integro() {
        let Ok(database) = crate::Database::open_in_memory() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let Ok(esito) = database.verify_integrity() else {
            panic!("la verifica deve riuscire");
        };
        assert!(esito.is_healthy(), "un archivio nuovo non e' danneggiato");
        assert!(esito.structural.is_empty());
        assert_eq!(esito.broken_links, 0);
    }

    #[test]
    fn la_verifica_misura_anche_quanto_pesa() {
        // Chi guarda lo stato dell'archivio vuole sapere anche quanto occupa:
        // e' l'altra meta' della domanda «devo fare qualcosa?».
        let Ok(database) = crate::Database::open_in_memory() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let Ok(esito) = database.verify_integrity() else {
            panic!("la verifica deve riuscire");
        };
        let Some(byte) = esito.size_bytes else {
            panic!("la dimensione deve essere misurabile");
        };
        assert!(byte > 0);
    }

    /// **Un archivio davvero danneggiato deve risultare danneggiato.**
    ///
    /// La prova rovina un file vero, scrivendo byte casuali in mezzo alle pagine
    /// di un archivio con dentro delle migrazioni applicate. Non simula un
    /// esito: fa il danno e chiede al prodotto di accorgersene.
    ///
    /// # Quale strada prende davvero
    ///
    /// Verificato eseguendola: il file **si apre senza problemi** ed e'
    /// `verify_integrity` a scoprire il danno, segnalandolo come *errore*
    /// (`database disk image is malformed`) e non come un rapporto con un
    /// elenco di problemi.
    ///
    /// Questo dice due cose. La prima e' che la verifica serve: senza,
    /// l'archivio si sarebbe aperto e il prodotto avrebbe continuato a girarci
    /// sopra. La seconda e' che **chi chiama deve trattare l'errore come un
    /// esito**, perche' e' la strada che il danneggiamento reale prende: un
    /// servizio che lo riferisse come «controllo non riuscito» direbbe
    /// all'operatore di riprovare invece di fermarlo.
    ///
    /// L'elenco `structural` resta esercitato dalle sole prove costruite a
    /// mano, ed e' giusto dirlo invece di lasciar credere il contrario.
    #[test]
    fn un_archivio_rovinato_non_passa_per_integro() {
        use std::io::{Seek, SeekFrom, Write};

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("archivio.sqlite3");

        {
            let Ok(database) = crate::Database::open(&percorso) else {
                panic!("l'archivio di prova deve potersi aprire");
            };
            // Si chiude subito: il danno va fatto a file fermo, altrimenti si
            // starebbe misurando che cosa succede a scrivere sotto una
            // connessione aperta, che e' un'altra domanda.
            drop(database);
        }

        // Il giornale WAL va assorbito nel file principale, altrimenti il danno
        // colpirebbe pagine che SQLite riscrive comunque e la prova
        // misurerebbe la fortuna.
        {
            let Ok(connessione) = rusqlite::Connection::open(&percorso) else {
                panic!("la connessione di servizio deve potersi aprire");
            };
            let _ = connessione.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }

        let Ok(dati) = std::fs::metadata(&percorso) else {
            panic!("il file deve esistere");
        };
        let dimensione = dati.len();
        assert!(
            dimensione > 8_192,
            "l'archivio deve avere almeno due pagine da rovinare: {dimensione} byte"
        );

        {
            let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&percorso) else {
                panic!("il file deve potersi aprire in scrittura");
            };
            // Si salta la prima pagina: rovinare l'intestazione renderebbe il
            // file non apribile, e la prova verificherebbe che SQLite rifiuta un
            // file che non e' un database — non che il prodotto si accorge di un
            // danneggiamento.
            let Ok(_) = file.seek(SeekFrom::Start(4_096)) else {
                panic!("il posizionamento deve riuscire");
            };
            let spazzatura = vec![0x5A_u8; 3_000];
            let Ok(()) = file.write_all(&spazzatura) else {
                panic!("la scrittura del danno deve riuscire");
            };
        }

        // Un archivio cosi' rotto da non lasciarsi nemmeno interrogare e' esso
        // stesso la risposta: l'errore vale quanto un esito negativo.
        let danneggiato = match crate::Database::open(&percorso) {
            Err(_) => true,
            Ok(database) => match database.verify_integrity() {
                Err(_) => true,
                Ok(esito) => !esito.is_healthy(),
            },
        };

        assert!(
            danneggiato,
            "il prodotto ha dichiarato integro un archivio con tremila byte di \
             spazzatura dentro"
        );
    }

    #[test]
    fn il_messaggio_di_un_archivio_rotto_dice_che_cosa_fare() {
        // «database disk image is malformed» e' vero e inutile: chi lo legge in
        // un ufficio non sa se chiamare qualcuno, spegnere o continuare.
        let rotto = IntegrityReport {
            structural: vec![String::from("* in database main *")],
            broken_links: 2,
            size_bytes: Some(4_096),
        };
        assert!(!rotto.is_healthy());

        let messaggio = rotto.operator_message();
        assert!(
            messaggio.contains("DANNEGGIATO"),
            "l'esito deve essere leggibile a colpo d'occhio: «{messaggio}»"
        );
        assert!(
            messaggio.contains("Non produrre documenti"),
            "chi legge deve sapere la cosa piu' importante da NON fare: «{messaggio}»"
        );
        assert!(
            messaggio.contains("copia"),
            "conservare il file com'e' viene prima di qualunque tentativo di \
             riparazione: «{messaggio}»"
        );
    }

    #[test]
    fn il_messaggio_di_un_archivio_sano_non_promette_piu_di_quanto_verifica() {
        // Un controllo strutturale non dice nulla sulla CORRETTEZZA di cio' che
        // l'archivio contiene, e lasciarlo credere sarebbe la bugia piu' comoda.
        let sano = IntegrityReport {
            structural: Vec::new(),
            broken_links: 0,
            size_bytes: Some(4_096),
        };
        let messaggio = sano.operator_message();
        assert!(messaggio.contains("integro"));
        assert!(
            messaggio.contains("non può dire"),
            "il messaggio deve dichiarare il proprio limite: «{messaggio}»"
        );
    }

    #[test]
    fn un_collegamento_rotto_basta_a_dichiararlo_danneggiato() {
        // Un contenuto che punta a una fonte che non esiste piu' e' un dato che
        // nessuna schermata sa mostrare e nessun documento sa citare.
        let esito = IntegrityReport {
            structural: Vec::new(),
            broken_links: 1,
            size_bytes: None,
        };
        assert!(!esito.is_healthy());
        assert!(esito.operator_message().contains("collegamenti rotti"));
    }
}

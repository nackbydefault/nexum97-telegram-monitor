//! La copia di sicurezza, e il foglio che la accompagna.
//!
//! # Perché il foglio non è un di più
//!
//! Nell'archivio **non ci sono** le credenziali dell'account Telegram né la
//! parola di sblocco: vivono in file protetti da DPAPI, legati a *quel* profilo
//! Windows su *quella* macchina (ADR-0025). Sono irrecuperabili altrove **per
//! costruzione**, ed è la protezione che si è scelta.
//!
//! Ma significa che una copia di sicurezza **non basta a rimettere in piedi una
//! postazione**: rimette l'archivio, non l'accesso.
//!
//! Un prodotto che dicesse «copia completata» senza dirlo lascerebbe credere
//! all'ufficio di essere coperto. Lo scoprirebbe il giorno del guasto, che è il
//! giorno peggiore.
//!
//! # Chi può aprirla (SEC-01, ADR-0157)
//!
//! La copia è l'archivio intero, non cifrato, e finisce in una cartella scelta
//! dall'operatore. Fino al 2026-10-21 ne ereditava i permessi: nel collaudo era
//! leggibile da `BUILTIN\Users` e modificabile da `Authenticated Users`, mentre
//! l'archivio vivo è del solo utente. Ora la copia **nasce** del solo utente:
//! si scrive in una cartella di lavoro privata, ristretta prima del primo byte,
//! e arriva nella cartella scelta con un rinomino; i permessi si rileggono
//! prima e dopo l'arrivo. **Se la protezione non si può applicare e
//! verificare, la copia non si scrive** e non resta nulla sul disco: lo ha
//! deciso il committente il 2026-10-22 (ADR-0157, integrazione), al posto
//! della copia scritta comunque con un'avvertenza.
//!
//! # Che cosa questo modulo non fa
//!
//! Non ripristina. Sovrascrivere un archivio con uno più vecchio è la cosa più
//! distruttiva che questo prodotto potrebbe fare, e non è un pulsante.

use std::path::{Path, PathBuf};

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
pub use lisi_security::owner_only::{CurrentUser, current_user};
use lisi_storage::Database;
pub use lisi_storage::repository::backup::BackupOutcome;

use crate::error::{ServiceError, ServiceResult};
use crate::protected_output::{Delivery, Existing, record_refusal};

/// Estensione della copia.
const BACKUP_EXTENSION: &str = "sqlite3";

/// Estensione del foglio che la accompagna.
const NOTE_EXTENSION: &str = "txt";

/// I file che `SQLite` può lasciare accanto a una copia mentre la rilegge.
const JOURNAL_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Ciò che si dice quando la copia non si scrive per i permessi.
const NOT_WRITTEN: &str = "La copia di sicurezza NON è stata scritta";

/// Azione dell'audit di una copia rifiutata.
///
/// È distinta da [`crate::diagnostics::BACKUP_AUDIT_ACTION`] di proposito: la
/// fascia di prontezza legge quella per dire quando è stata fatta l'ultima
/// copia, e una copia rifiutata non è una copia.
pub const REFUSED_AUDIT_ACTION: &str = "copia_di_sicurezza_rifiutata";

/// Che cosa è stato prodotto, e dove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    /// La copia.
    pub archive: PathBuf,
    /// Il foglio che dice che cosa c'è e che cosa no.
    pub note: PathBuf,
    /// L'esito della scrittura.
    pub outcome: BackupOutcome,
    /// L'utente Windows che solo può aprire copia e foglio: i permessi sono
    /// stati applicati e riletti (SEC-01, ADR-0157). Una copia che non lo è
    /// non esiste, perché non si scrive.
    pub owner: CurrentUser,
    /// L'istante della copia: è quello scritto nel nome, in UTC.
    pub made_at: Timestamp,
}

impl Backup {
    /// Se l'esito chiede attenzione: la copia non si rilegge.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        !self.outcome.verified
    }

    /// L'esito, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let mega = self.outcome.bytes as f64 / (1024.0 * 1024.0);
        let mut testo = format!(
            "Copia dell'archivio scritta in «{}» ({mega:.0} MB) e riletta con esito \
             positivo.",
            self.archive.display()
        );
        if !self.outcome.verified {
            testo = format!(
                "Copia dell'archivio scritta in «{}» ({mega:.0} MB), ma la RILETTURA \
                 NON è riuscita: non fidarsi di questa copia e rifarla.",
                self.archive.display()
            );
        }
        // IL NOME E' IN UTC, E LO SI DICE (FULL-OPERATIONAL-VALIDATION-01). Il
        // nome resta in UTC perche' l'ordine alfabetico sia l'ordine degli
        // istanti anche a cavallo dell'ora legale (E2E01-13); chi lo leggeva
        // con due ore di differenza dal proprio orologio non sapeva perche'.
        testo.push_str(&format!(
            " Il nome porta l'ora UTC, con la «Z» finale: la copia è del {}.",
            self.made_at.to_readable_local()
        ));
        testo.push_str(&format!(
            " Copia e foglio si aprono soltanto con l'utente Windows «{}»: gli altri \
             utenti di questa postazione non possono aprirli. I permessi non viaggiano: \
             copiata su una chiavetta o in una cartella condivisa, la copia prende quelli \
             del posto in cui arriva.",
            self.owner.name
        ));
        testo.push_str(
            " Accanto c'è un foglio che dice che cosa la copia NON contiene: le \
             credenziali dell'account restano su questa postazione e non si \
             possono spostare.",
        );
        testo
    }
}

/// Servizio della copia di sicurezza.
#[derive(Debug)]
pub struct BackupService {
    database: Database,
}

impl BackupService {
    /// Crea il servizio attorno all'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Archivio sottostante in scrittura: le copie pianificate registrano i loro
    /// tentativi sullo stesso archivio (BACKUP-SCHEDULE-01).
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Scrive la copia e il proprio foglio nella cartella indicata.
    ///
    /// # Perché il foglio ha lo stesso nome della copia
    ///
    /// Deve essere **impossibile separarli per distrazione**. Stessa cartella,
    /// stesso nome, estensione diversa: chi copia l'uno si porta dietro l'altro,
    /// e chi trova la copia fra un anno trova accanto la spiegazione.
    ///
    /// # Perché nasce in una cartella di lavoro (SEC-01, ADR-0157)
    ///
    /// Windows controlla i permessi quando un file si **apre**. Una copia
    /// scritta direttamente nella cartella scelta ne avrebbe i permessi mentre
    /// `VACUUM INTO` la scrive, e chi la aprisse in quell'istante terrebbe in
    /// mano un handle valido anche dopo. Per questo copia, rilettura e foglio
    /// avvengono in una cartella privata, ristretta al solo utente prima del
    /// primo byte, e arrivano nella cartella scelta con un rinomino, che sullo
    /// stesso volume porta con sé i permessi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cartella non è utilizzabile, se una copia con
    /// lo stesso nome esiste già, o se la scrittura non riesce.
    ///
    /// Restituisce [`ServiceError::ProtectionNotGuaranteed`] se la copia non si
    /// può rendere del solo utente **e verificare rileggendo**: in una cartella
    /// che non conserva i permessi (alcune chiavette, alcune cartelle di rete)
    /// la copia non si scrive, il rifiuto si registra nell'audit e nella
    /// cartella scelta non resta nulla (ADR-0157, integrazione del
    /// 2026-10-22).
    pub fn write_to(
        &self,
        directory: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<Backup> {
        if !directory.is_dir() {
            return Err(ServiceError::ExportNotWritten {
                reason: format!("«{}» non è una cartella", directory.display()),
            });
        }

        let radice = file_stem(now);
        let nome_copia = format!("{radice}.{BACKUP_EXTENSION}");
        let nome_foglio = format!("{radice}.{NOTE_EXTENSION}");
        let archivio = directory.join(&nome_copia);
        let foglio = directory.join(&nome_foglio);

        // UNA COPIA NON NE SOVRASCRIVE UN'ALTRA (ADR-0043). Fino a SEC-01 lo
        // garantiva `VACUUM INTO` sul nome definitivo; ora la copia nasce
        // altrove, e il controllo si fa qui, prima di scrivere qualunque cosa.
        // La consegna lo rifa' all'arrivo.
        for definitivo in [&archivio, &foglio] {
            if definitivo.exists() {
                return Err(ServiceError::ExportNotWritten {
                    reason: format!(
                        "«{}» esiste già: una copia non ne sovrascrive un'altra",
                        definitivo.display()
                    ),
                });
            }
        }

        // LA PROTEZIONE PRIMA DEL PRIMO BYTE, O NIENTE, e dopo l'arrivo si
        // rilegge: lo fa la consegna (`protected_output`), che toglie tutto
        // se un passo non regge.
        let prodotta = Delivery::begin(directory, &radice, NOT_WRITTEN).and_then(|mut consegna| {
            let outcome = self.produce(&mut consegna, &nome_copia, &nome_foglio, now)?;
            // La copia arriva PRIMA del foglio: un foglio senza copia
            // descriverebbe qualcosa che non c'e', ed e' piu' ingannevole di
            // una copia senza foglio.
            let arrivati = consegna.deliver(Existing::Refuse)?;
            Ok((outcome, arrivati.owner))
        });
        let (outcome, utente) = match prodotta {
            Ok(prodotta) => prodotta,
            Err(errore) => {
                record_refusal(
                    &self.database,
                    actor,
                    now,
                    REFUSED_AUDIT_ACTION,
                    "archivio",
                    &errore,
                );
                return Err(errore);
            }
        };

        // Nell'audit finisce il FATTO e la cartella, mai il contenuto.
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("copia_di_sicurezza_prodotta")?,
            entity: AuditEntity::try_new("archivio")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{} byte, rilettura {}, permessi del solo utente",
                outcome.bytes,
                if outcome.verified {
                    "riuscita"
                } else {
                    "FALLITA"
                },
            ))?),
            recorded_at: now,
        })?;

        Ok(Backup {
            archive: archivio,
            note: foglio,
            outcome,
            owner: utente,
            made_at: now,
        })
    }

    /// Scrive copia e foglio nella cartella di lavoro della consegna, e li
    /// prende in carico: ciascuno riceve un DACL esplicito e protetto del
    /// solo utente, riletto.
    fn produce(
        &self,
        consegna: &mut Delivery,
        nome_copia: &str,
        nome_foglio: &str,
        now: Timestamp,
    ) -> ServiceResult<BackupOutcome> {
        // La rilettura della copia puo' lasciare il giornale di SQLite accanto
        // a lei: se la consegna non arriva in fondo, si toglie con il resto.
        for coda in JOURNAL_SUFFIXES {
            consegna.clean_also(&format!("{nome_copia}{coda}"));
        }

        let copia = consegna.staging_path(nome_copia);
        let outcome = self.database.backup_to(&copia)?;
        consegna.adopt(nome_copia)?;

        // In Esercitazione il foglio si apre con la frase di SIC-17 (PR-13).
        let utente = consegna.owner().clone();
        let testo = crate::run_mode::marked_text(note_text(&copia, &outcome, now, &utente));
        consegna.write(nome_foglio, testo.as_bytes())?;
        Ok(outcome)
    }
}

/// Il nome della copia, dall'istante in cui è stata prodotta.
///
/// # Perché la data è nel nome e non solo nel filesystem
///
/// La data di modifica di un file cambia copiandolo, comprimendolo, mettendolo
/// su una chiavetta. Il nome no. Chi trova tre copie in una cartella deve poter
/// dire quale è la più recente **guardandole**.
fn file_stem(now: Timestamp) -> String {
    // UNA DATA CHE SI LEGGE, E CHE ORDINA (E2E01-13). Prima erano i soli
    // millisecondi: ordinabili, e illeggibili. Ora data e ora UTC, con la Z e i
    // millisecondi: l'ordine alfabetico resta l'ordine degli istanti, e il nome
    // non dipende dal fuso della postazione.
    // In Esercitazione il nome porta il prefisso (PR-13, ADR-0129).
    crate::run_mode::file_name(&format!("nexum97-copia-{}", now.to_file_stamp_utc()))
}

/// Il testo del foglio.
///
/// # Perché elenca prima ciò che NON c'è
///
/// Chi legge un foglio di copia di sicurezza cerca rassicurazione. Se la parte
/// che manca stesse in fondo, la leggerebbe dopo aver già concluso di essere
/// coperto.
fn note_text(
    archive: &Path,
    outcome: &BackupOutcome,
    now: Timestamp,
    owner: &CurrentUser,
) -> String {
    let nome = archive
        .file_name()
        .and_then(|nome| nome.to_str())
        .unwrap_or("(nome non leggibile)");

    // CHI PUO' APRIRLA (SEC-01, ADR-0157). Una riga in testa, accanto alla
    // rilettura, e la spiegazione in fondo, accanto a «non è cifrata»: e' la
    // stessa domanda, chi puo' leggere questo archivio. Un foglio che dica
    // «non ristretta» non esiste piu': una copia non protetta non si scrive.
    let riga_accesso = format!("solo l'utente Windows «{}»", owner.name);
    let chi_puo_aprirla = format!(
        "Alla scrittura, il programma ha reso questa copia e questo foglio\n\
         accessibili al solo utente Windows «{}»\n\
         (identificativo {}), senza ereditare i permessi della cartella, e\n\
         li ha riletti per verificarlo: gli altri utenti di questa postazione\n\
         non li aprono. Un amministratore della postazione può comunque\n\
         prenderne possesso.\n\
         \n\
         I permessi NON viaggiano con il file. Copiata su una chiavetta, in\n\
         una cartella condivisa o in un messaggio, la copia prende i permessi\n\
         del posto in cui arriva.\n",
        owner.name, owner.sid
    );

    // Il nome dell'archivio vivo non si scrive qui: viene dalla costante con
    // cui il prodotto lo apre. Una procedura che nomina un file a mano smette
    // di essere vera senza che nulla lo segnali (ADR-0115).
    let vivo = crate::sources::DATABASE_FILE;
    // La cartella del modo del processo: in Esercitazione la sua (PR-13).
    let cartella_dati = crate::run_mode::current().data_directory();

    format!(
        "NEXUM/97 Telegram Monitor - copia di sicurezza dell'archivio\n\
         Ideazione e progettazione: Giuseppe LISI\n\
         \n\
         File:      {nome}\n\
         Dimensione: {} byte\n\
         Prodotta:  {}\n\
         Rilettura: {}\n\
         Accesso:   {riga_accesso}\n\
         \n\
         =================================================================\n\
         CHE COSA QUESTA COPIA NON CONTIENE\n\
         =================================================================\n\
         \n\
         Le credenziali dell'account Telegram e la parola di sblocco della\n\
         postazione NON sono qui dentro, e non possono esserci.\n\
         \n\
         Vivono in file protetti dal sistema (DPAPI), legati a QUESTO profilo\n\
         Windows su QUESTA macchina. È la protezione che il prodotto ha\n\
         scelto: renderli copiabili significherebbe renderli leggibili altrove.\n\
         \n\
         Conseguenza pratica, da sapere PRIMA e non dopo un guasto:\n\
         \n\
           questa copia rimette l'ARCHIVIO, non l'ACCESSO.\n\
         \n\
         Su una macchina nuova occorrerà rifare l'accesso a Telegram da capo,\n\
         con il numero dell'ufficio. Il codice arriva sul telefono di chi ha\n\
         l'autorizzazione: senza quella persona non si riparte, e non è una\n\
         scelta di questo prodotto ma del modo in cui Telegram autentica.\n\
         \n\
         Allo stesso modo il nome di chi firma, la sua qualifica e la riga\n\
         con sede, indirizzo e recapiti sono nella copia CIFRATI per questo\n\
         utente Windows (ADR-0160): ripristinati con un altro utente o su\n\
         un'altra macchina non si aprono, e vanno reinseriti nel profilo\n\
         della relazione.\n\
         \n\
         =================================================================\n\
         CHE COSA CONTIENE\n\
         =================================================================\n\
         \n\
         Tutto ciò che l'archivio conserva: i monitoraggi condotti, i\n\
         contenuti acquisiti e analizzati, le corrispondenze, gli avvisi, le\n\
         revisioni, le fonti configurate, i dizionari, il profilo documentale,\n\
         le fotografie dei rapporti prodotti e l'audit.\n\
         \n\
         =================================================================\n\
         COME SI RIPRISTINA\n\
         =================================================================\n\
         \n\
         Il prodotto NON ripristina da solo, ed è voluto: sovrascrivere un\n\
         archivio con uno più vecchio è la cosa più distruttiva che potrebbe\n\
         fare, e nessun messaggio di conferma vale quel rischio.\n\
         \n\
         PRIMA DI TUTTO: l'archivio NON è un file, sono TRE.\n\
         \n\
         Accanto a «{vivo}» il sistema tiene «{vivo}-wal» - il giornale delle\n\
         ultime scritture - e «{vivo}-shm». Chi mette da parte solo il primo si\n\
         ritrova, riaprendo, il giornale rimasto RIVERSATO sull'archivio appena\n\
         ripristinato: torna a leggere quello di prima.\n\
         \n\
         E non se ne accorge: l'archivio si apre, la verifica lo dichiara\n\
         integro, e il ripristino non è avvenuto.\n\
         \n\
           1. chiudere NEXUM/97;\n\
           2. andare in %LOCALAPPDATA%\\{cartella_dati};\n\
           3. spostare in un'altra cartella TUTTI E TRE i file - «{vivo}»,\n\
              «{vivo}-wal» e «{vivo}-shm», quelli che ci sono.\n\
              NON cancellarli;\n\
           4. copiare questo file al loro posto, rinominandolo esattamente\n\
              «{vivo}»;\n\
           5. riaprire NEXUM/97.\n\
         \n\
         COME SI CONTROLLA CHE SIA ANDATA\n\
         \n\
         «Impostazioni > Stato dell'archivio > Verifica l'archivio» dice se\n\
         l'archivio è INTEGRO, non se è QUELLO GIUSTO: un archivio vecchio è\n\
         integro anche lui, e risponderebbe di sì.\n\
         \n\
         Guardare invece la data dell'ultimo monitoraggio: deve essere quella\n\
         della copia, non quella di prima.\n\
         \n\
         =================================================================\n\
         QUESTA COPIA NON È CIFRATA\n\
         =================================================================\n\
         \n\
         Contiene materiale monitorato. Va trattata come l'archivio: su un\n\
         volume cifrato, in un luogo che l'ufficio controlla.\n\
         \n\
         Da quando esce dalla postazione, la sua protezione è quella del luogo\n\
         in cui sta, e il prodotto non ne ha più alcuna.\n\
         \n\
         =================================================================\n\
         CHI PUÒ APRIRE QUESTA COPIA\n\
         =================================================================\n\
         \n\
         {chi_puo_aprirla}",
        outcome.bytes,
        now.to_readable_utc(),
        if outcome.verified {
            "riuscita - la copia si riapre ed è integra"
        } else {
            "FALLITA - non fidarsi di questa copia, rifarla"
        }
    )
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::text::Actor;

    use super::BackupService;
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    fn servizio() -> BackupService {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        BackupService::new(database)
    }

    fn attore() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Il foglio, scritto su una copia vera: rileggerlo dal file e' l'unico
    /// modo di provare cio' che l'operatore ha davanti.
    fn foglio_di_prova() -> String {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(copia) = servizio().write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la copia deve potersi scrivere");
        };
        let Ok(testo) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi rileggere");
        };
        testo
    }

    /// **Il foglio nomina l'archivio vivo e i due file che gli stanno accanto.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La procedura di ripristino diceva «copiare questo file al suo posto, con
    /// lo stesso nome», e l'archivio **non è un file: sono tre**. Chi mette da
    /// parte solo il primo si ritrova, riaprendo, il giornale rimasto riversato
    /// sull'archivio appena ripristinato — e torna a leggere quello di prima,
    /// senza che niente lo segnali (ADR-0115).
    ///
    /// Il nome viene dalla costante con cui il prodotto apre l'archivio: se un
    /// giorno cambiasse, una procedura scritta a mano continuerebbe a nominare
    /// un file che non esiste più, e sembrerebbe giusta.
    #[test]
    fn il_foglio_nomina_i_tre_file_dell_archivio() {
        let foglio = foglio_di_prova();
        let vivo = crate::sources::DATABASE_FILE;

        for atteso in [
            vivo.to_owned(),
            format!("{vivo}-wal"),
            format!("{vivo}-shm"),
        ] {
            assert!(
                foglio.contains(&atteso),
                "il foglio non nomina «{atteso}»: chi segue la procedura mette da parte \
                 meno file di quanti ne abbia l'archivio, e il ripristino non avviene \
                 senza che nulla lo segnali (ADR-0115)"
            );
        }
    }

    /// **Il foglio non manda a cercare nella verifica una risposta che la
    /// verifica non ha.**
    ///
    /// `quick_check` dice se l'archivio è **integro**, non se è **quello
    /// giusto**: un archivio vecchio è integro anche lui, e risponderebbe di sì.
    /// La procedura chiudeva mandando l'operatore proprio lì, cioè **dava il
    /// semaforo verde su un ripristino mai avvenuto**.
    #[test]
    fn il_foglio_dice_che_la_verifica_non_riconosce_un_ripristino_mancato() {
        let foglio = foglio_di_prova();

        assert!(
            foglio.contains("INTEGRO, non se è QUELLO GIUSTO"),
            "il foglio non distingue piu' fra archivio integro e archivio giusto: \
             un controllo che risponde a una domanda diversa da quella che si sta \
             facendo e' peggio di nessun controllo, perche' rassicura (ADR-0115)"
        );
        assert!(
            foglio.contains("data dell'ultimo monitoraggio"),
            "il foglio non dice piu' che cosa guardare per sapere se il ripristino \
             e' avvenuto davvero (ADR-0115)"
        );
    }

    #[test]
    fn la_copia_e_il_suo_foglio_escono_insieme() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(copia) = servizio().write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la copia deve potersi scrivere");
        };

        assert!(copia.archive.is_file());
        assert!(copia.note.is_file());
        assert_eq!(
            copia.archive.file_stem(),
            copia.note.file_stem(),
            "il foglio deve avere lo stesso nome della copia: deve essere \
             impossibile separarli per distrazione"
        );
    }

    /// **Il foglio dice che cosa la copia NON contiene, e lo dice PRIMA.**
    ///
    /// Chi legge un foglio di copia di sicurezza cerca rassicurazione. Se la
    /// parte che manca stesse in fondo, la leggerebbe dopo aver gia' concluso di
    /// essere coperto.
    /// **Il foglio dice che i dati di chi firma sono cifrati per questo
    /// utente, e che altrove vanno reinseriti** (ADR-0160, decisione 6).
    #[test]
    fn il_foglio_dice_che_i_dati_di_chi_firma_sono_cifrati() {
        let foglio = foglio_di_prova();
        assert!(foglio.contains("CIFRATI per questo"), "{foglio}");
        assert!(foglio.contains("vanno reinseriti"), "{foglio}");
    }

    #[test]
    fn il_foglio_dice_prima_cio_che_manca() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(copia) = servizio().write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la copia deve potersi scrivere");
        };
        let Ok(testo) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi leggere");
        };

        let Some(posizione_manca) = testo.find("COPIA NON CONTIENE") else {
            panic!("il foglio non dichiara che cosa manca");
        };
        let Some(posizione_contiene) = testo.find("CHE COSA CONTIENE") else {
            panic!("il foglio non dichiara che cosa contiene");
        };
        assert!(
            posizione_manca < posizione_contiene,
            "cio' che manca deve stare PRIMA di cio' che c'e'"
        );

        assert!(
            testo.contains("rimette l'ARCHIVIO, non l'ACCESSO"),
            "il foglio non dice la conseguenza pratica"
        );
        assert!(
            testo.contains("NON È CIFRATA"),
            "il foglio non dichiara che la copia non e' cifrata"
        );
        // Plurale: la procedura non mette da parte «l'archivio» ma i TRE file
        // che lo compongono. Questa guardia e' stata vista rossa al cambio, ed e'
        // stata stretta su cio' che ora deve dire (ADR-0115).
        assert!(
            testo.contains("NON cancellarli"),
            "la procedura di ripristino deve dire di mettere da parte i file \
             esistenti invece di toglierli"
        );
    }

    /// **Nel foglio non finisce alcun segreto.**
    #[test]
    fn il_foglio_non_contiene_segreti() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(copia) = servizio().write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la copia deve potersi scrivere");
        };
        let Ok(testo) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi leggere");
        };
        let minuscolo = testo.to_lowercase();

        for proibito in ["api_hash", "api_id", "password:", "token", "otp"] {
            assert!(
                !minuscolo.contains(proibito),
                "il foglio contiene «{proibito}»"
            );
        }
    }

    /// **La copia lascia traccia nell'audit, senza il contenuto.**
    #[test]
    fn la_copia_lascia_traccia_del_fatto_e_non_del_contenuto() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let servizio = servizio();
        let Ok(_) = servizio.write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la copia deve potersi scrivere");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == "copia_di_sicurezza_prodotta")
        else {
            panic!("la copia deve lasciare traccia");
        };
        assert!(voce.detail.is_some());
    }

    /// I nomi presenti in una cartella, ordinati.
    #[cfg(windows)]
    fn nomi_in(cartella: &std::path::Path) -> Vec<String> {
        let Ok(voci) = std::fs::read_dir(cartella) else {
            panic!("la cartella deve potersi elencare");
        };
        let mut nomi: Vec<String> = voci
            .filter_map(Result::ok)
            .map(|voce| voce.file_name().to_string_lossy().into_owned())
            .collect();
        nomi.sort();
        nomi
    }

    /// Le azioni registrate nell'audit dell'archivio di prova.
    fn azioni(servizio: &BackupService) -> Vec<String> {
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        voci.iter()
            .map(|voce| voce.action.as_str().to_owned())
            .collect()
    }

    /// **SEC-01: la copia e il foglio sono del solo utente, anche in una
    /// cartella che concede a tutti** (BAK-03, ADR-0157; criteri 1 e 2).
    ///
    /// La cartella e' aperta come quella del collaudo: lettura per `Users`,
    /// modifica per `Authenticated Users`, ereditabili. Fino al 2026-10-21 la
    /// copia — l'archivio intero, non cifrato — ne ereditava i permessi. I
    /// permessi si leggono con .NET, non con lo strumento che li applica.
    ///
    /// Vista rossa il 2026-10-22 sul codice di prima di SEC-01: copia e foglio
    /// concedevano l'accesso a `Users` e ad `Authenticated Users`.
    #[cfg(windows)]
    #[test]
    fn la_copia_e_il_foglio_sono_del_solo_utente_anche_in_una_cartella_aperta() {
        use crate::permessi_di_prova::{afferma_del_solo_utente, apri_come_nel_collaudo};

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        apri_come_nel_collaudo(cartella.path());

        let Ok(copia) = servizio().write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la copia deve potersi scrivere");
        };

        afferma_del_solo_utente(&copia.archive);
        afferma_del_solo_utente(&copia.note);

        // Nella cartella scelta restano la copia e il foglio, e nient'altro:
        // ne' la cartella di lavoro, ne' i file di giornale della rilettura.
        let mut attesi: Vec<String> = [&copia.archive, &copia.note]
            .iter()
            .filter_map(|percorso| percorso.file_name())
            .map(|nome| nome.to_string_lossy().into_owned())
            .collect();
        attesi.sort();
        assert_eq!(
            nomi_in(cartella.path()),
            attesi,
            "nella cartella scelta e' rimasto altro"
        );
    }

    /// **Il foglio e la frase dicono chi può aprire la copia, e che i permessi
    /// non viaggiano** (SEC-01, criterio 5).
    #[cfg(windows)]
    #[test]
    fn il_foglio_e_la_frase_dicono_chi_puo_aprire_la_copia() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let servizio = servizio();
        let Ok(copia) = servizio.write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la copia deve potersi scrivere");
        };
        let utente = &copia.owner;
        assert!(!copia.needs_attention());

        let Ok(foglio) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi leggere");
        };
        assert!(
            foglio.contains(&format!(
                "Accesso:   solo l'utente Windows «{}»",
                utente.name
            )),
            "{foglio}"
        );
        assert!(foglio.contains(&utente.sid), "{foglio}");
        assert!(foglio.contains("I permessi NON viaggiano"), "{foglio}");
        assert!(
            !foglio.contains("NON RISTRETT"),
            "un foglio non deve piu' descrivere una copia non protetta: {foglio}"
        );

        let frase = copia.operator_message();
        assert!(
            frase.contains(&format!("soltanto con l'utente Windows «{}»", utente.name)),
            "{frase}"
        );
        assert!(
            frase.contains("gli altri utenti di questa postazione"),
            "{frase}"
        );
        assert!(frase.contains("I permessi non viaggiano"), "{frase}");
        // Il nome è in UTC, e la frase lo dice con l'istante della copia.
        assert!(frase.contains("Il nome porta l'ora UTC"), "{frase}");
        assert!(
            frase.contains(&copia.made_at.to_readable_local()),
            "{frase}"
        );

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            voci.iter().any(|voce| voce
                .detail
                .as_ref()
                .is_some_and(|d| d.as_str().contains("permessi del solo utente"))),
            "l'audit non registra chi puo' aprire la copia"
        );
    }

    /// **Permessi che Windows non accetta: la copia NON si scrive, nella
    /// cartella non resta nulla, e il programma lo dice** (SEC-01, criterio 6;
    /// ADR-0157 integrato il 2026-10-22).
    ///
    /// La cartella concede all'utente la sola modifica e porta una voce
    /// `OWNER RIGHTS` (S-1-3-4) che sostituisce i diritti impliciti del
    /// proprietario: chi crea qualcosa li dentro non puo' piu' cambiarne i
    /// permessi. E' il rifiuto di una chiavetta FAT32, ottenuto su NTFS.
    ///
    /// Vista rossa il 2026-10-22 sul codice recuperato dalla sessione SEC-01,
    /// che in questo caso scriveva la copia con un'avvertenza.
    #[cfg(windows)]
    #[test]
    fn una_copia_che_non_si_puo_proteggere_non_si_scrive_e_non_lascia_nulla() {
        let cartella = crate::permessi_di_prova::cartella_che_rifiuta_i_permessi();

        let servizio = servizio();
        let esito = servizio.write_to(cartella.path(), &attore(), adesso());
        let Err(errore) = esito else {
            panic!("una copia che non si puo' proteggere e' stata scritta");
        };
        let ServiceError::ProtectionNotGuaranteed { reason, .. } = &errore else {
            panic!("l'esito doveva essere il rifiuto per i permessi: {errore:?}");
        };

        // NIENTE SUL DISCO: ne' copia, ne' foglio, ne' cartella di lavoro.
        assert!(
            nomi_in(cartella.path()).is_empty(),
            "nella cartella e' rimasto qualcosa: {:?}",
            nomi_in(cartella.path())
        );

        let frase = errore.operator_message();
        assert!(frase.contains("NON è stata scritta"), "{frase}");
        assert!(frase.contains("non è rimasto nulla"), "{frase}");
        assert!(frase.contains(reason.as_str()), "{frase}");
        assert!(frase.contains("Scegliere una cartella"), "{frase}");

        // L'AUDIT REGISTRA IL RIFIUTO, e non una copia: la fascia di
        // prontezza legge «copia prodotta» per dire quando e' stata l'ultima.
        let azioni = azioni(&servizio);
        assert!(
            azioni
                .iter()
                .any(|azione| azione == super::REFUSED_AUDIT_ACTION),
            "l'audit non registra il rifiuto: {azioni:?}"
        );
        assert!(
            !azioni
                .iter()
                .any(|azione| azione == crate::diagnostics::BACKUP_AUDIT_ACTION),
            "un rifiuto e' stato registrato come copia prodotta: {azioni:?}"
        );
    }

    /// **La verifica dopo l'arrivo rifiuta un file che eredita i permessi**:
    /// il rinomino li porta, e lo si rilegge invece di presumerlo.
    #[cfg(windows)]
    #[test]
    fn la_verifica_dopo_l_arrivo_rifiuta_un_file_che_eredita() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let file = cartella.path().join("arrivato.sqlite3");
        if std::fs::write(&file, b"copia").is_err() {
            panic!("il file deve potersi scrivere");
        }
        assert!(
            matches!(
                crate::protected_output::confirm(&file, super::NOT_WRITTEN),
                Err(ServiceError::ProtectionNotGuaranteed { .. })
            ),
            "un file che eredita i permessi della cartella e' stato accettato"
        );
        assert!(lisi_security::owner_only::restrict_to_current_user(&file).is_owner_only());
        assert!(crate::protected_output::confirm(&file, super::NOT_WRITTEN).is_ok());
    }

    /// **Una cartella di lavoro già presente, o un collegamento al suo posto,
    /// fermano la copia** (SEC-01, criterio 4).
    ///
    /// Chi scrive nella cartella scelta potrebbe preparare in anticipo il nome
    /// della cartella di lavoro — una cartella sua, o un collegamento verso
    /// un'altra cartella — perché la copia finisca dove vuole lui.
    #[cfg(windows)]
    #[test]
    fn una_cartella_di_lavoro_gia_presente_o_collegata_ferma_la_copia() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let lavoro = cartella.path().join(format!(
            ".{}.{}",
            super::file_stem(adesso()),
            crate::protected_output::WORK_EXTENSION
        ));

        // Una cartella gia' presente con quel nome: non si riusa.
        if std::fs::create_dir(&lavoro).is_err() {
            panic!("la cartella di prova deve potersi creare");
        }
        assert!(
            servizio()
                .write_to(cartella.path(), &attore(), adesso())
                .is_err()
        );
        assert_eq!(
            nomi_in(&lavoro),
            Vec::<String>::new(),
            "la copia e' entrata in una cartella che non aveva creato"
        );
        if std::fs::remove_dir(&lavoro).is_err() {
            panic!("la cartella di prova deve potersi togliere");
        }

        // Un collegamento al suo posto, verso un'altra cartella.
        let Ok(altrove) = tempfile::tempdir() else {
            panic!("la seconda cartella temporanea deve potersi creare");
        };
        let Ok(uscita) = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&lavoro)
            .arg(altrove.path())
            .output()
        else {
            panic!("mklink deve potersi avviare");
        };
        assert!(
            uscita.status.success(),
            "il collegamento di prova non si e' creato"
        );
        assert!(
            servizio()
                .write_to(cartella.path(), &attore(), adesso())
                .is_err()
        );
        assert!(
            nomi_in(altrove.path()).is_empty(),
            "la copia e' finita dove puntava il collegamento"
        );
        let _ = std::fs::remove_dir(&lavoro);
    }

    /// **Una copia non ne sovrascrive un'altra, e il rifiuto non lascia
    /// nulla** (ADR-0043, ADR-0157 decisione 7; criterio 7).
    #[test]
    fn una_copia_con_lo_stesso_nome_e_rifiutata_senza_lasciare_nulla() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(prima) = servizio().write_to(cartella.path(), &attore(), adesso()) else {
            panic!("la prima copia deve potersi scrivere");
        };
        let Ok(byte_di_prima) = std::fs::read(&prima.archive) else {
            panic!("la prima copia deve potersi leggere");
        };

        assert!(
            servizio()
                .write_to(cartella.path(), &attore(), adesso())
                .is_err(),
            "la seconda copia con lo stesso nome ha sovrascritto la prima"
        );
        assert_eq!(std::fs::read(&prima.archive).ok(), Some(byte_di_prima));

        let Ok(voci) = std::fs::read_dir(cartella.path()) else {
            panic!("la cartella deve potersi elencare");
        };
        assert_eq!(
            voci.count(),
            2,
            "il rifiuto ha lasciato una cartella di lavoro o un file"
        );
    }

    #[test]
    fn una_cartella_che_non_esiste_lo_dice() {
        let inesistente = std::path::Path::new("C:/questa/non/esiste");
        assert!(
            servizio()
                .write_to(inesistente, &attore(), adesso())
                .is_err(),
            "una cartella inesistente non deve produrre una copia"
        );
    }

    /// **La data si legge** (E2E01-13): il foglio scrive data e ora UTC, non un
    /// numero di millisecondi, e il nome della copia porta la stessa data.
    #[test]
    fn la_data_della_copia_si_legge() {
        let foglio = foglio_di_prova();
        assert!(!foglio.contains("millisecondi"), "{foglio}");
        assert!(foglio.contains(&adesso().to_readable_utc()), "{foglio}");
        let nome = super::file_stem(Timestamp::from_millis(1_700_000_000_123));
        assert!(nome.ends_with("2023-11-14_22-13-20-123Z"), "{nome}");
    }

    /// **I nomi ordinano correttamente.**
    ///
    /// Chi trova tre copie in una cartella deve poter dire quale e' la piu'
    /// recente guardandole: la data di modifica cambia copiandole, il nome no.
    #[test]
    fn i_nomi_delle_copie_ordinano_per_data() {
        let primo = super::file_stem(Timestamp::from_millis(1_700_000_000_000));
        let secondo = super::file_stem(Timestamp::from_millis(1_800_000_000_000));
        assert!(
            primo < secondo,
            "«{primo}» dovrebbe ordinare prima di «{secondo}»"
        );
    }
}

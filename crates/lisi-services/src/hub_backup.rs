//! La copia di sicurezza dell'ufficio (TEAM-BACKUP-01, ADR-0101).
//!
//! # Perché non basta quella di una postazione sola
//!
//! La copia di [`crate::backup`] scrive `VACUUM INTO` nella cartella scelta e
//! rilegge. Va bene lì: l'archivio è di chi lo copia, la cartella è un disco
//! locale, e nessun altro sta scrivendo.
//!
//! Su un Hub tre cose sono diverse: l'archivio è **vivo**, la destinazione è
//! quasi sempre una **condivisione di rete**, e l'Hub è **più del suo
//! archivio** — ha una chiave, dei dispositivi e delle persone.
//!
//! # Si scrive in casa, si verifica, e solo allora si parte
//!
//! Una scrittura interrotta su una condivisione lascia un file che **sembra**
//! una copia: ha il nome giusto, la data giusta, e si apre solo fino a dove è
//! arrivata. Per questo la copia nasce in una cartella locale, si rilegge e si
//! impronta lì, e arriva a destinazione con un nome **provvisorio** che si
//! rinomina alla fine: il rinomino è l'atto che la rende visibile.
//!
//! # Che cosa non porta
//!
//! Le chiavi. Sono legate a quell'utente e a quella macchina: fuori non si
//! aprono, e portarle via sarebbe spostare una credenziale che nemmeno
//! funziona. Il foglio lo dice **in cima**, perché chi lo legge dopo un guasto
//! lo legge troppo tardi.

use std::path::{Path, PathBuf};

use lisi_core::Sha256Digest;
use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};

use crate::Database;
use crate::acquisition_authority::StationAuthorityService;
use crate::error::{ServiceError, ServiceResult};
use crate::protected_output::{
    CurrentUser, Delivered, Delivery, Existing, ProtectedFolder, REFUSED_AUDIT_ACTION,
    WORK_EXTENSION, record_refusal,
};

/// Estensione della copia.
const BACKUP_EXTENSION: &str = "sqlite3";

/// Estensione del foglio che la accompagna.
const NOTE_EXTENSION: &str = "txt";

/// I file che `SQLite` può lasciare accanto alla copia in casa mentre la
/// rilegge.
const JOURNAL_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Ciò che si dice quando la copia non si scrive per i permessi.
const HUB_NOT_WRITTEN: &str = "La copia dell'ufficio NON è stata scritta";

/// Che cosa è stato prodotto, e dove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubBackup {
    /// La copia, a destinazione.
    pub archive: PathBuf,
    /// Il foglio che dice che cosa c'è e che cosa no.
    pub note: PathBuf,
    /// Quanto è grande.
    pub bytes: u64,
    /// L'impronta, calcolata **in casa** sulla copia verificata.
    pub sha256: String,
    /// L'ultimo evento della sequenza autorevole contenuto nella copia.
    pub last_event: u64,
    /// Se il file provvisorio locale è stato tolto.
    ///
    /// Quando non lo è, l'esito lo dice invece di lasciarlo lì in silenzio.
    pub staging_removed: bool,
    /// L'utente Windows che solo può aprire copia e foglio a destinazione
    /// (ADR-0159).
    pub owner: CurrentUser,
}

impl HubBackup {
    /// L'esito, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let mega = self.bytes as f64 / (1024.0 * 1024.0);
        let mut testo = format!(
            "Copia dell'ufficio scritta in «{}» ({mega:.0} MB), verificata in locale e portata a \
             destinazione. Contiene la storia fino all'evento numero {}.",
            self.archive.display(),
            self.last_event
        );
        if !self.staging_removed {
            testo.push_str(
                " Il file provvisorio in locale NON è stato tolto: va cancellato a mano.",
            );
        }
        testo.push_str(
            " Accanto c'è un foglio che dice che cosa la copia NON contiene. Le chiavi dell'Hub \
             restano su questo computer. Ripristinare l'archivio non ripristina l'identità \
             dell'Hub.",
        );
        testo
    }
}

/// La copia di sicurezza dell'ufficio.
#[derive(Debug)]
pub struct HubBackupService {
    database: Database,
    authority: StationAuthorityService,
}

impl HubBackupService {
    /// Costruisce il servizio sull'archivio dell'Hub.
    #[must_use]
    pub fn new(database: Database, base: &Path) -> Self {
        Self {
            database,
            authority: StationAuthorityService::in_directory(base),
        }
    }

    /// L'archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Scrive la copia dell'ufficio.
    ///
    /// `staging` è la cartella **locale** in cui la copia nasce e viene
    /// verificata; `destination` è dove arriva.
    ///
    /// # Errori
    ///
    /// Un errore se questa postazione **segue** un Hub invece di esserlo, se
    /// una delle due cartelle non è utilizzabile, se la rilettura non riesce,
    /// o se il trasferimento non riesce.
    pub fn write_to(
        &self,
        destination: &Path,
        staging: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<HubBackup> {
        // LA COPIA DELL'UFFICIO LA FA L'HUB (ADR-0101, decisione 1): su una
        // postazione che segue, l'archivio e' una proiezione potata e non
        // contiene i fatti. Si rifiuta invece di produrre un file parziale:
        // un file parziale non si riconosce dal file.
        if !self.authority.role().may_acquire() {
            return Err(ServiceError::HubServer {
                reason: String::from(
                    "questa postazione segue un Hub: la copia dell'ufficio la fa l'Hub, perché \
                     qui l'archivio è una proiezione e non contiene i fatti. La copia di questa \
                     postazione si fa dalla sezione «Copia di sicurezza».",
                ),
            });
        }
        for cartella in [destination, staging] {
            if !cartella.is_dir() {
                return Err(ServiceError::ExportNotWritten {
                    reason: format!("«{}» non è una cartella", cartella.display()),
                });
            }
        }

        let radice = file_stem(now);
        let nome_copia = format!("{radice}.{BACKUP_EXTENSION}");
        let nome_foglio = format!("{radice}.{NOTE_EXTENSION}");
        let definitivo = destination.join(&nome_copia);
        if definitivo.exists() {
            return Err(ServiceError::ExportNotWritten {
                reason: format!(
                    "«{}» esiste già: una copia non ne sovrascrive un'altra",
                    definitivo.display()
                ),
            });
        }

        // PASSO 1: si scrive in casa, in una cartella di lavoro DEL SOLO
        // UTENTE (ADR-0159, decisione 1): e' l'archivio intero, e nemmeno per
        // il tempo della copia resta leggibile da altri.
        let in_casa = ProtectedFolder::create(
            &staging.join(format!(".{radice}.{WORK_EXTENSION}")),
            HUB_NOT_WRITTEN,
            |errore| ServiceError::ExportNotWritten {
                reason: format!("la cartella locale della copia non si prepara: {errore}"),
            },
        )
        .inspect_err(|errore| {
            record_refusal(
                &self.database,
                actor,
                now,
                REFUSED_AUDIT_ACTION,
                "copia_ufficio",
                errore,
            );
        })?;
        let copia_locale = in_casa.path().join(&nome_copia);
        let esito = self.produce_and_deliver(
            &copia_locale,
            destination,
            &radice,
            &nome_copia,
            &nome_foglio,
            now,
        );

        // La copia in casa si toglie sempre, riuscita o no: e' un temporaneo
        // con l'archivio intero. Se non si toglie, l'esito lo dice.
        for nome in std::iter::once(nome_copia.clone()).chain(
            JOURNAL_SUFFIXES
                .iter()
                .map(|coda| format!("{nome_copia}{coda}")),
        ) {
            let _ = std::fs::remove_file(in_casa.path().join(nome));
        }
        let tolto = in_casa.remove().is_ok();

        let (bytes, impronta, ultimo_evento, consegnati) = match esito {
            Ok(prodotta) => prodotta,
            Err(errore) => {
                record_refusal(
                    &self.database,
                    actor,
                    now,
                    REFUSED_AUDIT_ACTION,
                    "copia_ufficio",
                    &errore,
                );
                return Err(errore);
            }
        };
        let mut arrivati = consegnati.files.into_iter();
        let (Some(archive), Some(note)) = (arrivati.next(), arrivati.next()) else {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from("la copia è arrivata senza il suo foglio"),
            });
        };

        // Nell'audit finisce il FATTO, la destinazione e l'impronta: mai il
        // contenuto.
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("copia_ufficio_prodotta")?,
            entity: AuditEntity::try_new("archivio_hub")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{bytes} byte, fino all'evento {ultimo_evento}, sha256 {impronta}, permessi del \
                 solo utente"
            ))?),
            recorded_at: now,
        })?;

        Ok(HubBackup {
            archive,
            note,
            bytes,
            sha256: impronta,
            last_event: ultimo_evento,
            staging_removed: tolto,
            owner: consegnati.owner,
        })
    }

    /// Scrive la copia in casa, la verifica, e la porta a destinazione con il
    /// suo foglio, del solo utente (ADR-0101 decisione 2, ADR-0159 decisione 2).
    ///
    /// Restituisce i byte, l'impronta, l'ultimo evento e ciò che è arrivato.
    fn produce_and_deliver(
        &self,
        copia_locale: &Path,
        destination: &Path,
        radice: &str,
        nome_copia: &str,
        nome_foglio: &str,
        now: Timestamp,
    ) -> ServiceResult<(u64, String, u64, Delivered)> {
        // `VACUUM INTO` legge attraverso una transazione e vede uno stato
        // coerente anche mentre l'Hub serve.
        let esito = self.database.backup_to(copia_locale)?;

        // PASSO 2: si verifica in casa, e si impronta. Una copia scritta ma
        // non rileggibile e' un fallimento, non un successo con una riserva.
        if !esito.verified {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from(
                    "la copia è stata scritta ma non si rilegge. Non è stata portata a \
                     destinazione: una copia di cui non ci si fida è peggio di nessuna",
                ),
            });
        }
        let impronta = impronta_del_file(copia_locale)?;
        let ultimo_evento = self.database.latest_hub_sequence()?;

        // PASSO 3: si porta a destinazione attraverso la cartella di lavoro
        // privata della consegna, e il rinomino la rende visibile: prima si
        // vede soltanto una cartella che dice «interrotta». Se la destinazione
        // non accetta i permessi, non riceve nulla (ADR-0159, decisione 4).
        let mut consegna = Delivery::begin(destination, radice, HUB_NOT_WRITTEN)?;
        consegna.clean_also(nome_copia);
        std::fs::copy(copia_locale, consegna.staging_path(nome_copia)).map_err(|errore| {
            ServiceError::ExportNotWritten {
                reason: format!("la copia non è arrivata a destinazione: {}", errore.kind()),
            }
        })?;
        consegna.adopt(nome_copia)?;

        // Il foglio arriva DOPO la copia: un foglio senza copia descrive
        // qualcosa che non c'e', ed e' piu' ingannevole di una copia senza
        // foglio.
        let testo = testo_del_foglio(
            &destination.join(nome_copia),
            esito.bytes,
            &impronta,
            ultimo_evento,
            now,
            consegna.owner(),
        );
        consegna.write(nome_foglio, testo.as_bytes())?;
        let consegnati = consegna.deliver(Existing::Refuse)?;
        Ok((esito.bytes, impronta, ultimo_evento, consegnati))
    }
}

/// L'impronta di un file, letta a blocchi.
fn impronta_del_file(path: &Path) -> ServiceResult<String> {
    let file = std::fs::File::open(path).map_err(|errore| ServiceError::ExportNotWritten {
        reason: format!("la copia appena scritta non si riapre: {errore}"),
    })?;
    let impronta =
        Sha256Digest::of_reader(file).map_err(|errore| ServiceError::ExportNotWritten {
            reason: format!("l'impronta della copia non si è calcolata: {errore}"),
        })?;
    Ok(String::from(impronta.as_str()))
}

/// Il nome della copia, dall'istante in cui è stata prodotta.
///
/// Ordina per data guardandolo: la data di modifica cambia copiando un file,
/// il nome no.
fn file_stem(now: Timestamp) -> String {
    // Data leggibile e ordinabile, in UTC, come la copia della postazione (E2E01-13).
    format!("NEXUM97-ufficio-{}", now.to_file_stamp_utc())
}

/// Il foglio che accompagna la copia.
///
/// **Ciò che manca sta in cima.** Chi legge un foglio di copia di sicurezza
/// cerca rassicurazione: se la parte che manca stesse in fondo, la leggerebbe
/// dopo aver già concluso di essere coperto.
fn testo_del_foglio(
    archive: &Path,
    bytes: u64,
    sha256: &str,
    last_event: u64,
    now: Timestamp,
    owner: &CurrentUser,
) -> String {
    let nome = archive
        .file_name()
        .and_then(|nome| nome.to_str())
        .unwrap_or("(nome non leggibile)");

    // Il nome dell'archivio vivo viene dalla costante con cui il prodotto lo
    // apre, non dalla prosa di questo foglio (ADR-0115).
    let vivo = crate::sources::DATABASE_FILE;

    format!(
        "NEXUM/97 Telegram Monitor - copia di sicurezza dell'UFFICIO (Hub)\n\
         Ideazione e progettazione: Giuseppe LISI\n\
         \n\
         CHE COSA QUESTA COPIA NON CONTIENE\n\
         \n\
         - Le chiavi dell'Hub e i file protetti restano sulla macchina che ha\n\
           prodotto la copia: sono legati a quell'utente e a quel computer, e\n\
           altrove non si aprono.\n\
         - Ripristinare questo archivio NON ripristina l'identità dell'Hub. Un\n\
           Hub ricostruito ha una chiave nuova, e quindi un'IMPRONTA NUOVA, che\n\
           va riportata alle postazioni sul foglietto dell'arruolamento.\n\
         - Le postazioni arruolate restano nell'archivio, e i loro gettoni\n\
           restano validi: cambia l'identità dell'Hub, non la loro.\n\
         - Le credenziali dell'account Telegram non sono qui.\n\
         \n\
         FINO A CHE PUNTO ARRIVA\n\
         \n\
         Questa copia contiene la storia dell'Hub fino all'evento numero\n\
         {last_event}. Le postazioni che hanno già visto oltre quel numero, se\n\
         l'Hub viene ripristinato da qui, SI FERMANO dicendolo invece di\n\
         divergere in silenzio.\n\
         \n\
         IL RIPRISTINO NON È UN PULSANTE\n\
         \n\
         Il prodotto non ripristina da solo: sovrascrivere un archivio in uso\n\
         con uno più vecchio cancellerebbe il lavoro di tutti in un secondo.\n\
         Il ripristino si fa a mano, a Hub spento, da chi amministra.\n\
         \n\
         E chi lo fa deve sapere che l'archivio NON è un file, sono TRE:\n\
         «{vivo}», «{vivo}-wal» - il giornale delle ultime scritture - e\n\
         «{vivo}-shm». Vanno spostati TUTTI E TRE prima di mettere questa copia\n\
         al loro posto, rinominata esattamente «{vivo}».\n\
         \n\
         Lasciandone uno, riaprendo l'Hub il giornale rimasto viene riversato\n\
         sull'archivio appena ripristinato e si torna a leggere quello di\n\
         prima: l'archivio si apre, è integro, e il ripristino non è avvenuto.\n\
         \n\
         CHI PUÒ APRIRE QUESTA COPIA\n\
         \n\
         Copia e foglio sono accessibili al solo utente Windows «{chi}»\n\
         (identificativo {sid}), senza ereditare i permessi della cartella, e\n\
         sono stati riletti per verificarlo: gli altri utenti, anche quelli che\n\
         possono leggere questa cartella, non li aprono (ADR-0159).\n\
         \n\
         Chi ripristina deve essere lo stesso account. Con un account di\n\
         dominio basta accedere con quello anche da un altro computer; con un\n\
         account locale, su un'altra macchina, serve un amministratore che\n\
         prenda possesso del file. I permessi NON viaggiano: copiata altrove,\n\
         la copia prende quelli del posto in cui arriva.\n\
         \n\
         IL FILE\n\
         \n\
         File:       {nome}\n\
         Dimensione: {bytes} byte\n\
         SHA-256:    {sha256}\n\
         Prodotta:   {}\n",
        now.to_readable_utc(),
        chi = owner.name,
        sid = owner.sid
    )
}

#[cfg(test)]
mod tests {
    use super::{HubBackupService, file_stem};
    use crate::sources::open_in_memory_database;
    use lisi_core::Timestamp;
    use lisi_core::text::Actor;

    fn attore() -> Actor {
        match Actor::try_new("amministratore.prova") {
            Ok(attore) => attore,
            Err(errore) => panic!("attore di prova: {errore}"),
        }
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn cartella() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(cartella) => cartella,
            Err(errore) => panic!("cartella temporanea: {errore}"),
        }
    }

    /// Il servizio su una postazione che **non** segue un Hub.
    fn servizio(base: &std::path::Path) -> HubBackupService {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        HubBackupService::new(database, base)
    }

    #[test]
    fn i_nomi_delle_copie_ordinano_per_data() {
        let primo = file_stem(Timestamp::from_millis(1_700_000_000_000));
        let secondo = file_stem(Timestamp::from_millis(1_800_000_000_000));
        assert!(
            primo < secondo,
            "«{primo}» deve ordinare prima di «{secondo}»"
        );
    }

    /// I nomi in una cartella, ordinati.
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

    /// **SEC-02, ADR-0159: a destinazione la copia dell'ufficio e il suo
    /// foglio sono del solo utente che li fa, anche se la condivisione concede
    /// a tutti; in casa non resta nulla.**
    ///
    /// La destinazione è aperta come la cartella del collaudo (lettura per
    /// `Users`, modifica per `Authenticated Users`); i permessi si leggono con
    /// .NET. Vista rossa il 2026-10-22 con la protezione tolta (mutazione di
    /// SEC-02).
    #[cfg(windows)]
    #[test]
    fn la_copia_dell_ufficio_e_del_solo_utente_anche_su_una_condivisione_aperta() {
        use crate::permessi_di_prova::{afferma_del_solo_utente, apri_come_nel_collaudo};

        let casa = cartella();
        let destinazione = cartella();
        apri_come_nel_collaudo(destinazione.path());
        let Ok(copia) =
            servizio(casa.path()).write_to(destinazione.path(), casa.path(), &attore(), adesso())
        else {
            panic!("la copia dell'ufficio deve potersi scrivere");
        };
        afferma_del_solo_utente(&copia.archive);
        afferma_del_solo_utente(&copia.note);
        assert!(copia.staging_removed, "la copia in casa non è stata tolta");
        assert_eq!(
            nomi_in(destinazione.path()).len(),
            2,
            "a destinazione è rimasto altro"
        );

        let Ok(foglio) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi leggere");
        };
        assert!(foglio.contains("CHI PUÒ APRIRE QUESTA COPIA"), "{foglio}");
        assert!(foglio.contains(&copia.owner.sid), "{foglio}");
        assert!(foglio.contains("serve un amministratore"), "{foglio}");
    }

    /// **Una destinazione che rifiuta i permessi non riceve la copia, e in
    /// casa non resta l'archivio** (ADR-0159, decisione 4).
    #[cfg(windows)]
    #[test]
    fn una_destinazione_che_rifiuta_i_permessi_non_riceve_la_copia() {
        let casa = cartella();
        let destinazione = cartella();
        crate::permessi_di_prova::rifiuta_i_permessi(destinazione.path());

        let servizio = servizio(casa.path());
        let esito = servizio.write_to(destinazione.path(), casa.path(), &attore(), adesso());
        assert!(
            matches!(
                esito,
                Err(crate::error::ServiceError::ProtectionNotGuaranteed { .. })
            ),
            "una destinazione che rifiuta i permessi ha ricevuto la copia: {esito:?}"
        );
        assert!(
            nomi_in(destinazione.path()).is_empty(),
            "a destinazione è rimasto qualcosa"
        );
        assert!(
            nomi_in(casa.path()).is_empty(),
            "in casa è rimasta la copia dell'archivio"
        );
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            voci.iter().any(|voce| voce.action.as_str()
                == crate::protected_output::REFUSED_AUDIT_ACTION
                && voce.entity.as_str() == "copia_ufficio"),
            "l'audit non registra il rifiuto della copia dell'ufficio"
        );
    }

    /// **La copia nasce in casa e arriva con il nome definitivo.**
    #[test]
    fn la_copia_arriva_e_il_provvisorio_non_resta() {
        let casa = cartella();
        let destinazione = cartella();
        let servizio = servizio(casa.path());

        let Ok(copia) = servizio.write_to(destinazione.path(), casa.path(), &attore(), adesso())
        else {
            panic!("la copia deve potersi scrivere");
        };

        assert!(
            copia.archive.exists(),
            "la copia deve essere a destinazione"
        );
        assert!(copia.note.exists(), "il foglio deve accompagnarla");
        assert!(copia.staging_removed, "il provvisorio in casa va tolto");
        assert_eq!(copia.sha256.len(), 64);

        let Ok(voci) = std::fs::read_dir(destinazione.path()) else {
            panic!("la cartella deve potersi leggere");
        };
        for voce in voci.flatten() {
            let nome = voce.file_name();
            let nome = nome.to_string_lossy();
            assert!(
                !nome.ends_with(".parziale"),
                "a destinazione non deve restare un file provvisorio: «{nome}»"
            );
        }
    }

    /// **Anche il foglio dell'Hub dice che l'archivio sono tre file.**
    ///
    /// Il foglio dell'Hub non da' passi — il ripristino si fa a mano, a Hub
    /// spento, da chi amministra — ma il pericolo fisico e' identico: e' lo
    /// stesso file, nella stessa modalita'. Un giornale rimasto accanto riporta
    /// indietro l'archivio appena ripristinato, e l'archivio si apre lo stesso,
    /// integro, con il contenuto di prima (ADR-0115).
    #[test]
    fn il_foglio_dell_hub_nomina_i_tre_file_dell_archivio() {
        let casa = cartella();
        let destinazione = cartella();
        let servizio = servizio(casa.path());
        let Ok(copia) = servizio.write_to(destinazione.path(), casa.path(), &attore(), adesso())
        else {
            panic!("la copia deve potersi scrivere");
        };
        let Ok(testo) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi leggere");
        };
        let vivo = crate::sources::DATABASE_FILE;

        for atteso in [
            vivo.to_owned(),
            format!("{vivo}-wal"),
            format!("{vivo}-shm"),
        ] {
            assert!(
                testo.contains(&atteso),
                "il foglio dell'Hub non nomina «{atteso}»: chi amministra mette da parte \
                 meno file di quanti ne abbia l'archivio, e il ripristino non avviene \
                 senza che nulla lo segnali (ADR-0115)"
            );
        }
    }

    /// **Il foglio dice in cima che cosa la copia non contiene.**
    #[test]
    fn il_foglio_dice_subito_che_cosa_manca() {
        let casa = cartella();
        let destinazione = cartella();
        let servizio = servizio(casa.path());
        let Ok(copia) = servizio.write_to(destinazione.path(), casa.path(), &attore(), adesso())
        else {
            panic!("la copia deve potersi scrivere");
        };
        let Ok(testo) = std::fs::read_to_string(&copia.note) else {
            panic!("il foglio deve potersi leggere");
        };

        let Some(manca) = testo.find("NON CONTIENE") else {
            panic!("il foglio non dice che cosa manca");
        };
        let Some(file) = testo.find("IL FILE") else {
            panic!("il foglio non descrive il file");
        };
        assert!(
            manca < file,
            "ciò che manca sta dopo la descrizione del file: chi legge lo leggerebbe dopo aver \
             concluso di essere coperto"
        );
        assert!(
            testo.contains("NON ripristina l'identità dell'Hub"),
            "il foglio non dice che il ripristino non rimette l'identità dell'Hub"
        );
        assert!(
            testo.contains("fino all'evento numero"),
            "il foglio non dice a che punto della storia si ferma"
        );
    }

    /// **Una copia non ne sovrascrive un'altra.**
    #[test]
    fn una_copia_non_ne_distrugge_un_altra() {
        let casa = cartella();
        let destinazione = cartella();
        let servizio = servizio(casa.path());
        let Ok(_) = servizio.write_to(destinazione.path(), casa.path(), &attore(), adesso()) else {
            panic!("la prima copia deve potersi scrivere");
        };
        assert!(
            servizio
                .write_to(destinazione.path(), casa.path(), &attore(), adesso())
                .is_err(),
            "una seconda copia con lo stesso nome non deve sovrascrivere la prima"
        );
    }

    /// **La copia dell'ufficio la fa l'Hub** (ADR-0101, decisione 1).
    ///
    /// Su una postazione che **segue** un Hub l'archivio è una proiezione
    /// potata e non contiene i fatti: una copia prodotta lì sarebbe un file
    /// che sembra una copia dell'ufficio e non lo è.
    #[test]
    fn la_copia_dell_ufficio_la_fa_l_hub() {
        let casa = cartella();
        let destinazione = cartella();

        // La presenza del file basta: il ruolo si decide su un fatto locale,
        // mai sul contenuto (ADR-0092).
        let segue = casa.path().join(crate::hub_client::HUB_FILE);
        if std::fs::write(&segue, b"non si legge, basta che ci sia").is_err() {
            panic!("il file di configurazione deve potersi scrivere");
        }

        let servizio = servizio(casa.path());
        let esito = servizio.write_to(destinazione.path(), casa.path(), &attore(), adesso());
        let Err(errore) = esito else {
            panic!("una postazione che segue un Hub non deve produrre la copia dell'ufficio");
        };
        let detto = errore.operator_message();
        assert!(
            detto.contains("segue un Hub"),
            "il rifiuto deve dire perché: «{detto}»"
        );

        let Ok(voci) = std::fs::read_dir(destinazione.path()) else {
            panic!("la cartella deve potersi leggere");
        };
        assert_eq!(
            voci.count(),
            0,
            "un rifiuto non deve lasciare niente a destinazione"
        );
    }

    /// **La copia arriva a destinazione con un nome provvisorio, e solo alla
    /// fine si rinomina** (ADR-0101, decisione 2).
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Scrivere direttamente con il nome definitivo su una condivisione di
    /// rete lascia, se la rete cade, un file che **sembra** una copia: nome
    /// giusto, data giusta, e si apre solo fino a dove è arrivato. Il rinomino
    /// è l'atto che rende la copia visibile.
    ///
    /// La prova guarda il **codice**, perché l'interruzione di una
    /// condivisione non si riproduce in una cartella temporanea: quella la
    /// guarda una persona (HVQ-82).
    ///
    /// # Riscritta il 2026-10-22 (SEC-02, ADR-0159), con la stessa proprietà
    ///
    /// Fino a SEC-02 il provvisorio era un file `.parziale` accanto alla
    /// destinazione, e la prova cercava quel nome. Ora la copia arriva nella
    /// **cartella di lavoro** della consegna comune (`.<radice>.parziale`, del
    /// solo utente), e il nome definitivo compare soltanto con il rinomino di
    /// `Delivery::deliver`. La prova verifica le due metà: qui, che l'unica
    /// scrittura a destinazione vada nella cartella di lavoro; nel modulo
    /// comune, che il rinomino sia ciò che porta il file al suo nome.
    #[test]
    fn a_destinazione_si_arriva_con_un_nome_provvisorio() {
        const QUESTO_MODULO: &str = include_str!("hub_backup.rs");
        const CONSEGNA: &str = include_str!("protected_output.rs");
        let produzione = QUESTO_MODULO
            .split_once("\n#[cfg(test)]")
            .map_or(QUESTO_MODULO, |(prima, _)| prima);
        assert_eq!(
            produzione.matches("std::fs::copy(").count(),
            1,
            "a destinazione si copia in più di un punto: uno potrebbe scrivere il nome definitivo"
        );
        assert!(
            produzione.contains("std::fs::copy(copia_locale, consegna.staging_path(nome_copia))"),
            "a destinazione si scrive qualcosa che non è nella cartella di lavoro: una copia \
             interrotta somiglierebbe a una buona"
        );
        assert!(
            produzione.contains("consegna.deliver(Existing::Refuse)"),
            "la copia non arriva con il rinomino della consegna"
        );
        let Some((_, consegna)) = CONSEGNA.split_once("pub fn deliver(") else {
            panic!("la consegna comune non ha più il passo dell'arrivo");
        };
        assert!(
            consegna.contains("std::fs::rename(&da, &a)"),
            "nella consegna comune il nome definitivo non arriva più con un rinomino"
        );
    }

    /// **Una cartella che non esiste lo dice.**
    #[test]
    fn una_destinazione_inesistente_lo_dice() {
        let casa = cartella();
        let servizio = servizio(casa.path());
        assert!(
            servizio
                .write_to(
                    std::path::Path::new("C:/questa/non/esiste"),
                    casa.path(),
                    &attore(),
                    adesso()
                )
                .is_err()
        );
    }
}

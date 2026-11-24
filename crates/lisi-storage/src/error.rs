//! Errori della persistenza.
//!
//! Gli errori di SQLite sono classificati in categorie di dominio. Un chiamante
//! deve poter distinguere «questo contenuto era già stato acquisito» da «questa
//! fonte non era selezionata per la sessione» senza ispezionare il testo di un
//! messaggio del motore.

use lisi_core::DomainError;

/// Esito di una operazione di persistenza.
pub type StorageResult<T> = Result<T, StorageError>;

/// Errore prodotto dalla persistenza.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Il contenuto è già stato registrato per quella sessione e quella fonte.
    ///
    /// Non è un errore dell'applicazione: è l'esito normale di un ritentativo di
    /// acquisizione. I chiamanti che vogliono trattarlo come tale usano le
    /// funzioni che restituiscono un esito di deduplicazione.
    #[error("contenuto gia' registrato per questa sessione e questa fonte")]
    DuplicateContent,

    /// La fonte non era fra quelle selezionate per la sessione indicata.
    #[error(
        "la fonte non risulta selezionata per la sessione indicata: nessun contenuto può esservi collegato"
    )]
    SourceNotSelectedForSession,

    /// È stata tentata una modifica o una cancellazione sull'audit.
    #[error("l'audit e' append-only: modifica e cancellazione non sono ammesse")]
    AuditIsAppendOnly,

    /// La fonte era già registrata con lo stesso identificativo.
    #[error("fonte gia' registrata con lo stesso tipo e identificativo")]
    DuplicateSource,

    /// Un'organizzazione con lo stesso nome era già dichiarata.
    ///
    /// Due organizzazioni omonime sarebbero indistinguibili nell'elenco che
    /// l'amministratore rilegge, e nelle attribuzioni che leggerebbe l'operatore.
    #[error("organizzazione gia' dichiarata con lo stesso nome")]
    DuplicateOrganisation,

    /// Il dominio era già dichiarato per un'altra organizzazione.
    ///
    /// Il vincolo è **globale** e non per organizzazione: lo stesso dominio
    /// dichiarato due volte produrrebbe due settori per lo stesso fatto, e
    /// nessuno dei due sarebbe contestabile più dell'altro.
    #[error("dominio gia' dichiarato per un'altra organizzazione")]
    DuplicateOrganisationDomain,

    /// La fonte e' stata usata in una sessione e non puo' essere cancellata.
    ///
    /// Cancellarla renderebbe lo storico non piu' interpretabile: i contenuti
    /// acquisiti non sarebbero piu' riconducibili alla loro origine.
    #[error("la fonte e' stata usata in una sessione e non puo' essere rimossa")]
    SourceStillInUse,

    /// Il contenuto ha già un alert.
    ///
    /// L'alert riassume l'esito dell'analisi di un contenuto: due esiti diversi
    /// per lo stesso contenuto sarebbero una contraddizione, non un secondo
    /// allarme.
    #[error("il contenuto ha gia' un alert registrato")]
    DuplicateAlert,

    /// Esiste gia' una persona con quell'identificativo sull'Hub.
    ///
    /// Non e' un guasto: e' la risposta a chi la stava creando. Riusare un
    /// identificativo vorrebbe dire che due persone diverse compaiono con lo
    /// stesso nome negli atti gia' scritti.
    #[error("esiste gia' una persona con questo identificativo")]
    DuplicatePerson,

    /// Lo stesso autore ha già un dizionario con quel nome.
    ///
    /// L'unicità è per autore e non globale: due operatori possono avere
    /// ciascuno il proprio «Incendi» senza doversi accordare sul nome.
    #[error("esiste gia' un dizionario con questo nome per lo stesso autore")]
    DuplicateDictionary,

    /// L'UUID di un account e' gia' presente.
    #[error("esiste gia' un account con questo UUID")]
    DuplicateAccountUuid,

    /// Il profilo API riferito da un account non esiste.
    #[error("il profilo API riferito dall'account non esiste")]
    AccountProfileMissing,

    /// È stata tentata una modifica o una cancellazione su un dizionario di
    /// sistema.
    ///
    /// I dizionari forniti con il prodotto si **duplicano**: se fossero
    /// modificabili, due installazioni con lo stesso numero di versione
    /// conterrebbero cose diverse.
    #[error("un dizionario di sistema non si modifica ne' si cancella: va duplicato")]
    BuiltInDictionaryIsReadOnly,

    /// Il dizionario è stato selezionato da una sessione e non può sparire.
    #[error("il dizionario e' stato usato in una sessione e non puo' essere rimosso")]
    DictionaryStillInUse,

    /// Il dizionario ha versioni pubblicate e non può essere cancellato.
    ///
    /// Pubblicare è un impegno: da quel momento una sessione può essere stata
    /// condotta con quei termini, e cancellare il dizionario renderebbe lo
    /// storico non più interpretabile. Resta la possibilità di archiviarlo, che
    /// lo toglie dalla scelta senza cancellare nulla.
    #[error(
        "il dizionario ha versioni pubblicate e non può essere cancellato: può essere archiviato"
    )]
    PublishedDictionaryIsNotDeletable,

    /// È stata tentata una modifica su una versione già pubblicata.
    ///
    /// L'immutabilità di ciò che è pubblicato è ciò che rende ripetibile una
    /// sessione conclusa: la sessione riferisce la versione, e se la versione
    /// cambiasse nessuno potrebbe più dire con quali termini fu condotta.
    #[error("una versione pubblicata non si modifica: occorre crearne una nuova")]
    PublishedVersionIsImmutable,

    /// Il dizionario ha già una versione con quel numero.
    #[error("il dizionario ha gia' una versione con questo numero")]
    DuplicateDictionaryVersion,

    /// Il termine è già presente nella versione con la stessa modalità.
    #[error("il termine e' gia' presente in questa versione con la stessa modalita' di riscontro")]
    DuplicateTerm,

    /// Lo stesso autore ha già un profilo con quel nome.
    #[error("esiste gia' un profilo con questo nome per lo stesso autore")]
    DuplicateProfile,

    /// Un limite del dominio è stato superato.
    ///
    /// I limiti sono riaffermati dalla persistenza e non solo dal livello
    /// superiore: un limite controllato in un solo punto viene aggirato dal
    /// primo percorso che dimentica di passare da lì.
    #[error("limite superato per '{limit}': il massimo ammesso e' {max}, richiesti {requested}")]
    LimitExceeded {
        /// Limite violato.
        limit: &'static str,
        /// Valore massimo ammesso.
        max: usize,
        /// Valore richiesto.
        requested: usize,
    },

    /// La sessione ha già una configurazione risolta.
    ///
    /// Lo snapshot è immutabile: sovrascriverlo significherebbe cambiare i
    /// termini di una sessione già avviata.
    #[error("la sessione ha gia' una configurazione risolta e non puo' esserne assegnata un'altra")]
    SessionConfigurationAlreadyResolved,

    /// Una provenienza contiene i separatori riservati alla codifica interna.
    ///
    /// Le provenienze di un termine risolto sono conservate in un solo campo,
    /// separate da caratteri di controllo. Un'etichetta che li contenesse
    /// spezzerebbe la codifica e farebbe rileggere provenienze diverse da
    /// quelle scritte. Viene rifiutata alla scrittura invece che ripulita in
    /// silenzio: una provenienza alterata è un dato sbagliato, non un dettaglio
    /// di formattazione.
    #[error("l'etichetta di provenienza contiene caratteri riservati e non puo' essere conservata")]
    InvalidProvenanceLabel,

    /// L'identificativo citabile del report è già usato da un altro pacchetto.
    ///
    /// È l'identificativo che compare **dentro** i documenti: due pacchetti che
    /// lo condividessero renderebbero impossibile dire a quale generazione
    /// appartenga un file consegnato.
    #[error("identificativo di report gia' usato da un altro pacchetto")]
    DuplicateReportId,

    /// Il pacchetto contiene già un artefatto di quel genere.
    ///
    /// Un pacchetto ha al più una relazione, un allegato tecnico, un registro:
    /// il secondo sovrascriverebbe il primo senza che nessuno lo sappia.
    #[error("il pacchetto contiene gia' un documento di quel genere")]
    DuplicateReportArtifact,

    /// Una fotografia ATT&CK di quella versione e' gia' in archivio.
    ///
    /// Non e' un errore innocuo da ignorare: due fotografie della stessa
    /// versione renderebbero ambiguo a quale delle due si riferisca un
    /// documento che cita una tecnica.
    #[error("una fotografia ATT&CK di quella versione e' gia' in archivio")]
    DuplicateAttackSnapshot,

    /// Quel termine e' gia' associato a quella tecnica, e l'associazione e' in piedi.
    ///
    /// Non e' un doppione innocuo: due dichiarazioni contemporanee dello stesso
    /// legame renderebbero ambiguo quale motivo valga. Ridichiarare DOPO un
    /// ritiro invece si puo', e sono due atti.
    #[error("quel termine e' gia' associato a quella tecnica")]
    DuplicateAttackAssociation,

    /// Una riga conservata non è più interpretabile.
    ///
    /// Come [`StorageError::CorruptedValue`], ma per ciò che non passa dalle
    /// validazioni del dominio: un intero fuori dall'intervallo del proprio
    /// tipo, una codifica interna malformata. Indica un database alterato o una
    /// migrazione incompleta, non un errore del chiamante.
    #[error("la riga conservata non e' interpretabile: {detail}")]
    CorruptedRow {
        /// Che cosa non torna.
        detail: &'static str,
    },

    /// Un campo personale del profilo documentale è arrivato in chiaro
    /// (ADR-0160): l'archivio lo conserva soltanto cifrato.
    ///
    /// È un errore di chi chiama, non dell'archivio: il servizio cifra prima
    /// di scrivere.
    #[error("il campo personale «{field}» del profilo si conserva soltanto cifrato")]
    PlaintextPersonalField {
        /// Quale campo.
        field: &'static str,
    },

    /// L'impronta ricalcolata non coincide con quella conservata.
    ///
    /// Segnala che la copia conservata non è più quella su cui l'impronta fu
    /// calcolata. **Non** dice chi l'abbia alterata né quando: l'impronta
    /// riconosce una differenza, non prova una responsabilità.
    #[error(
        "l'impronta ricalcolata della configurazione non coincide con quella conservata: la copia è stata alterata"
    )]
    SnapshotDigestMismatch,

    /// La transizione di stato richiesta non è ammessa dal ciclo di vita.
    #[error("transizione di stato non ammessa: da '{from}' a '{to}'")]
    InvalidSessionTransition {
        /// Stato di partenza.
        from: &'static str,
        /// Stato richiesto.
        to: &'static str,
    },

    /// L'intervallo richiesto non è un intervallo.
    ///
    /// Un inizio non anteriore alla fine descrive un periodo vuoto o
    /// rovesciato. Restituire zero righe lo farebbe passare per «nessuna
    /// occorrenza in quel periodo», che è una risposta e non un rifiuto.
    #[error("l'intervallo richiesto per {what} non e' un intervallo: l'inizio non precede la fine")]
    InvalidRange {
        /// Che cosa si stava leggendo.
        what: &'static str,
    },

    /// La riga richiesta non esiste.
    #[error("{entity} non trovata per l'identificatore {id}")]
    NotFound {
        /// Entità cercata.
        entity: &'static str,
        /// Identificatore usato nella ricerca.
        id: i64,
    },

    /// Il database dichiara una versione di schema più recente di quella nota.
    ///
    /// Aprirlo comunque significherebbe interpretare con lo schema sbagliato
    /// dati scritti da una versione successiva dell'applicazione.
    #[error(
        "il database dichiara la versione di schema {found}, superiore alla {supported} supportata da questa versione dell'applicazione"
    )]
    SchemaTooNew {
        /// Versione trovata nel database.
        found: u32,
        /// Versione massima conosciuta.
        supported: u32,
    },

    /// Una migrazione non è andata a buon fine.
    #[error("migrazione {version} non riuscita: {source}")]
    Migration {
        /// Numero della migrazione.
        version: u32,
        /// Errore riportato dal motore.
        source: rusqlite::Error,
    },

    /// Dopo le migrazioni restano riferimenti pendenti.
    ///
    /// Una migrazione che ricostruisce una tabella lavora con l'applicazione
    /// delle foreign key disattivata: riattivarla senza verificare
    /// significherebbe dichiarare integro ciò che non è stato guardato.
    #[error("dopo le migrazioni restano {count} riferimenti pendenti fra le tabelle")]
    MigrationLeftDanglingReferences {
        /// Numero di riferimenti non risolti.
        count: i64,
    },

    /// Un valore letto dal database non rispetta le invarianti del dominio.
    ///
    /// Indica un database alterato o una migrazione incompleta, non un errore
    /// del chiamante.
    #[error("valore non valido letto dal database: {0}")]
    CorruptedValue(#[from] DomainError),

    /// L'ambito di una scoperta letto dall'archivio non è uno di quelli che
    /// questo prodotto conosce.
    ///
    /// Indica un database alterato: il vincolo di schema esclude ogni altro
    /// valore. **Non si interpreta e non si indovina** — una provenienza che
    /// nessuno può leggere non si trasforma in una plausibile (ADR-0074).
    #[error("ambito di ricerca sconosciuto letto dal database: {0}")]
    UnknownSearchScope(String),

    /// Una decisione presa su un candidato, letta dall'archivio, non è una di
    /// quelle che questo prodotto conosce.
    ///
    /// Indica un database alterato: il vincolo di schema esclude ogni altro
    /// valore. **Non si interpreta**: una decisione che nessuno puo' leggere non
    /// si trasforma in una plausibile (ADR-0080).
    #[error("decisione sconosciuta letta dal database: {0}")]
    UnknownCandidateDecision(String),

    /// La cartella del database non è utilizzabile.
    #[error("impossibile preparare la cartella del database: {0}")]
    DatabaseDirectory(#[from] std::io::Error),

    /// Errore del motore non riconducibile alle categorie precedenti.
    #[error("errore del database: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Categoria del vincolo violato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConstraintKind {
    /// Violazione di `UNIQUE` o di chiave primaria.
    Unique,
    /// Violazione di una foreign key.
    ForeignKey,
    /// Violazione di un `CHECK`.
    Check,
    /// `RAISE(ABORT, …)` da un trigger.
    Trigger,
    /// Violazione di `NOT NULL`.
    NotNull,
}

/// Classifica un errore di SQLite in base al codice esteso.
///
/// Il codice esteso è stabile e documentato; il testo del messaggio no. La
/// classificazione non usa quindi il messaggio, che resta solo per la
/// diagnostica.
pub(crate) const fn constraint_kind(error: &rusqlite::Error) -> Option<ConstraintKind> {
    let rusqlite::Error::SqliteFailure(failure, _) = error else {
        return None;
    };

    match failure.extended_code {
        rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        | rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
        | rusqlite::ffi::SQLITE_CONSTRAINT_ROWID => Some(ConstraintKind::Unique),
        rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY => Some(ConstraintKind::ForeignKey),
        rusqlite::ffi::SQLITE_CONSTRAINT_CHECK => Some(ConstraintKind::Check),
        rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER => Some(ConstraintKind::Trigger),
        rusqlite::ffi::SQLITE_CONSTRAINT_NOTNULL => Some(ConstraintKind::NotNull),
        _ => None,
    }
}

/// Traduce un errore del motore usando il contesto della chiamata.
///
/// La stessa violazione di foreign key significa cose diverse a seconda della
/// tabella su cui si stava scrivendo: il motore non lo dice, quindi il contesto
/// lo fornisce il chiamante.
pub(crate) fn classify(
    error: rusqlite::Error,
    on: ConstraintKind,
    as_error: StorageError,
) -> StorageError {
    if constraint_kind(&error) == Some(on) {
        as_error
    } else {
        StorageError::Sqlite(error)
    }
}

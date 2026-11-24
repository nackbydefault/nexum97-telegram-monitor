//! Errori dei servizi applicativi.
//!
//! Ogni errore porta con sé un **messaggio per l'operatore**, distinto dal
//! messaggio tecnico. Un operatore non tecnico che legge «transizione di
//! autorizzazione non ammessa: da waiting_for_code a ready» non sa che cosa
//! fare; deve leggere che cosa è successo e quale sia il passo successivo.
//!
//! Nessun errore trasporta un valore riservato.

use lisi_core::{DomainError, RestrictedAction};
use lisi_storage::StorageError;
use lisi_telegram::TelegramError;

/// Esito di una operazione di servizio.
pub type ServiceResult<T> = Result<T, ServiceError>;

/// Che cosa dice `SessionUnavailable` all'operatore (D-18).
///
/// Fino al 2026-10-02 diceva di usare «Ripristina accesso», un comando che
/// l'interfaccia non ha. Ora nomina il percorso vero, con le etichette dello
/// schermo, e una prova dell'interfaccia verifica che ciascuna esista.
pub const SESSION_UNAVAILABLE_MESSAGE: &str = "Il programma non riesce a leggere dati salvati su \
     questo computer. Ciò che è già stato acquisito resta nell'archivio. Riprovare. Se succede \
     ancora durante l'accesso a Telegram, in Account aprire «Azzeramento e rimozione…», premere \
     «Rimuovi l'account selezionato…», confermare, e poi aggiungerlo di nuovo. Negli altri \
     casi aprire Diagnostica e riferire l'ora a chi amministra.";

/// Che cosa dice `ApplicationNotConfigured` (APP-CREDENTIALS-01, ADR-0204).
///
/// Non dice dove il programma cerca la configurazione né che cosa contiene:
/// chi la deve sistemare è l'amministratore, che lo sa.
pub const APPLICATION_NOT_CONFIGURED_MESSAGE: &str = "Questa installazione di NEXUM/97 non è \
     configurata per collegarsi a Telegram. Rivolgersi all'amministratore.";

/// Errore prodotto da un servizio applicativo.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Il comando non è ammesso nello stato corrente.
    ///
    /// Non dovrebbe mai raggiungere l'operatore, perché l'interfaccia disabilita
    /// i comandi non ammessi. Se accade è un difetto, e va segnalato come tale
    /// invece che nascosto.
    #[error("comando '{command}' non ammesso nello stato '{state}'")]
    CommandNotAllowed {
        /// Comando richiesto.
        command: &'static str,
        /// Stato corrente.
        state: &'static str,
    },

    /// Il codice di accesso è stato rifiutato.
    #[error("codice di accesso non accettato")]
    CodeRejected,

    /// La password della verifica in due passaggi è stata rifiutata.
    #[error("password della verifica in due passaggi non accettata")]
    PasswordRejected,

    /// La sessione è stata revocata.
    #[error("sessione revocata")]
    SessionRevoked,

    /// I dati della sessione non sono utilizzabili.
    #[error("dati della sessione non accessibili: {reason}")]
    SessionUnavailable {
        /// Descrizione priva di dati riservati.
        reason: String,
    },

    /// Questa installazione non ha le credenziali dell'applicazione
    /// (APP-CREDENTIALS-01, ADR-0204): né nella distribuzione né dall'amministratore.
    #[error("credenziali dell'applicazione assenti o non valide")]
    ApplicationNotConfigured,

    /// Un atto sull'identità di dispositivo o sull'arruolamento non è riuscito.
    ///
    /// # Perché una variante propria e non `SessionUnavailable`
    ///
    /// Perché il messaggio conta. `SessionUnavailable` rimanda, per l'accesso a
    /// Telegram, a togliere l'account e aggiungerlo di nuovo: il consiglio
    /// giusto per la sessione Telegram e **il consiglio sbagliato per tutto il
    /// resto**: un operatore che non riesce ad arruolare la postazione
    /// finirebbe per rifare l'accesso a Telegram, che non c'entra.
    ///
    /// La ragione qui è già scritta per essere letta: si mostra così com'è.
    #[error("identità di dispositivo: {reason}")]
    DeviceIdentity {
        /// Descrizione destinata all'operatore, priva di dati riservati.
        reason: String,
    },

    /// L'Hub rifiuta un'azione al dispositivo che la chiede (ADR-0042
    /// decisione 3, ADR-0085).
    ///
    /// La ragione dice il ruolo del dispositivo e perché l'azione è riservata:
    /// un rifiuto senza ragione manda a cercare il modo di aggirarlo.
    #[error("azione non consentita dall'Hub: {reason}")]
    HubForbidden {
        /// Descrizione destinata all'operatore, priva di dati riservati.
        reason: String,
    },

    /// La modalità Hub non si può attivare, o la sua configurazione non è
    /// utilizzabile (TEAM-LIVE-01, ADR-0093).
    ///
    /// Come [`Self::HubClient`], è ciò che impedisce di **cominciare**: una
    /// postazione che segue un Hub, un indirizzo che manca, una chiave che non
    /// si può usare. Ciò che accade a una singola connessione dopo che la porta
    /// è aperta non risale mai fin qui: chiude quella connessione e basta.
    ///
    /// La ragione è già scritta per essere letta: si mostra così com'è.
    #[error("modalità Hub: {reason}")]
    HubServer {
        /// Descrizione destinata all'operatore, priva di dati riservati.
        reason: String,
    },

    /// Il collegamento della postazione all'Hub non si può nemmeno tentare
    /// (TEAM-CLIENT-01, ADR-0091).
    ///
    /// # Perché una variante propria
    ///
    /// Perché **non** è un esito della sessione. Un Hub che non risponde, che
    /// rifiuta o che non è quello atteso è un fatto da leggere, e sta in
    /// `hub_client::SessionOutcome`. Qui stanno soltanto le ragioni per cui la
    /// sessione non comincia: nessun Hub configurato, nessuna identità
    /// arruolata, tetti inutilizzabili, configurazione illeggibile.
    ///
    /// La ragione è già scritta per essere letta: si mostra così com'è.
    #[error("collegamento all'Hub: {reason}")]
    HubClient {
        /// Descrizione destinata all'operatore, priva di dati riservati.
        reason: String,
    },

    /// L'account è già in uso: in questa finestra, in un'altra istanza, o
    /// ancora aperto mentre se ne chiede la rimozione.
    #[error("l'account e' gia' in uso")]
    AccountInUse,

    /// Gli account attivi insieme sono già al tetto (ADR-0173, decisione 2).
    #[error("account attivi gia' al tetto di {limit}")]
    ActiveAccountLimit {
        /// Il tetto.
        limit: usize,
    },

    /// La rete non è disponibile.
    #[error("rete non disponibile")]
    NetworkUnavailable,

    /// L'attesa è scaduta.
    #[error("attesa scaduta")]
    TimedOut,

    /// L'operazione è stata annullata dall'operatore.
    #[error("operazione annullata")]
    Cancelled,

    /// La fonte indicata non è accessibile all'account.
    #[error("la fonte non risulta accessibile all'account configurato")]
    SourceNotAccessible,

    /// La fonte è già configurata.
    #[error("la fonte e' gia' configurata")]
    SourceAlreadyConfigured,

    /// Esiste già un workspace **aperto** con quel nome.
    ///
    /// Chi lavora li chiama per nome, e due contenitori aperti con lo stesso
    /// nome sono una trappola: si mette una cosa nell'uno credendo di metterla
    /// nell'altro.
    #[error("esiste gia' un raccoglitore aperto di nome '{name}'")]
    WorkspaceNameTaken {
        /// Il nome richiesto.
        name: String,
    },

    /// Il workspace è chiuso.
    ///
    /// Uno stato del ciclo di vita che non impedisce nulla è una decorazione: un
    /// workspace chiuso non accetta né perde elementi, e non si riapre.
    #[error("il raccoglitore '{name}' e' chiuso")]
    WorkspaceClosed {
        /// Il nome del workspace.
        name: String,
    },

    /// Il riferimento è già nel workspace (UX-EXCELLENCE-02, SIM3-02).
    ///
    /// Non è un guasto: è la risposta a chi lo stava aggiungendo una seconda
    /// volta. Nulla viene scritto.
    #[error("il riferimento e' gia' nel raccoglitore '{name}'")]
    AlreadyInWorkspace {
        /// Il nome del workspace.
        name: String,
    },

    /// La stessa cosa è già segnata da chi la sta segnando.
    ///
    /// Due righe identiche non direbbero nulla di più, e chi legge conterebbe
    /// due volte lo stesso oggetto.
    #[error("questa cosa e' gia' segnata")]
    AlreadyBookmarked,

    /// Esiste già una raccolta con quel nome.
    ///
    /// A differenza dei workspace, qui non c'è un ciclo di vita che liberi il
    /// nome: una raccolta è un'etichetta, e due etichette uguali sono una
    /// trappola per sempre.
    #[error("esiste gia' una raccolta di nome '{name}'")]
    CollectionNameTaken {
        /// Il nome richiesto.
        name: String,
    },

    /// La raccolta contiene ancora segnalibri.
    ///
    /// Cancellarla porterebbe via, o lascerebbe orfani, i segni che qualcuno
    /// aveva messo. La frase dice **quanti**: «non si può» senza dire quanti
    /// lascia chi legge a indovinare quanto lavoro ha davanti.
    #[error("la raccolta contiene ancora {count} segnalibri")]
    CollectionNotEmpty {
        /// Quanti ne contiene.
        count: usize,
    },

    /// Esiste già un modello di monitoraggio con quel nome.
    ///
    /// Come per le raccolte e le ricerche salvate, qui non c'è un ciclo di vita
    /// che liberi il nome: un modello si cancella, non si chiude.
    #[error("esiste gia' un modello di monitoraggio di nome '{name}'")]
    TemplateNameTaken {
        /// Il nome richiesto.
        name: String,
    },

    /// Non c'è nulla da chiudere: il soggetto non esiste, o era già chiuso.
    ///
    /// I due casi si dicono con una frase sola perché portano allo stesso
    /// gesto: se il lavoro riprende, se ne apre uno nuovo. Un soggetto chiuso
    /// non si riapre — la chiusura sarebbe una parentesi invece che un fatto.
    #[error("non c'e' nulla da chiudere: il soggetto non esiste o era gia' chiuso")]
    PersonAlreadyClosed,

    /// Non c'è nulla da ritirare: la nota non esiste, o era già ritirata.
    ///
    /// I due casi si dicono con una frase sola perché portano allo stesso
    /// gesto: se serve dire qualcosa di diverso, se ne scrive una nuova. Una
    /// nota non si riscrive — l'autore e l'istante che porta mentirebbero.
    #[error("non c'e' nulla da ritirare: la nota non esiste o era gia' ritirata")]
    NoteAlreadyWithdrawn,

    /// Esiste già una ricerca salvata con quel nome.
    ///
    /// Come per le raccolte, qui non c'è un ciclo di vita che liberi il nome:
    /// una ricerca salvata si cancella, non si chiude.
    #[error("esiste gia' una ricerca salvata di nome '{name}'")]
    SavedSearchNameTaken {
        /// Il nome richiesto.
        name: String,
    },

    /// Si è chiesto di conservare un contesto senza dire perché.
    ///
    /// Conservare ciò che Telegram mostra adesso è un atto di cui qualcuno
    /// risponde: senza una ragione non è documentato, è soltanto avvenuto. È la
    /// stessa disciplina di [`Self::ReviewNeedsReason`], applicata a un altro
    /// atto.
    #[error("una fotografia del contesto richiede una ragione")]
    SnapshotNeedsReason,

    /// Si è chiesto di conservare un contesto che **Telegram non ha dato**:
    /// nessun collegamento, richiesta non riuscita, contenuto che Telegram non
    /// saprebbe ritrovare (COLLAUDO-FIX-01, CU01-013, DEC-508).
    ///
    /// Una fotografia conserva ciò che Telegram mostrava. Presa senza una
    /// risposta direbbe che Telegram non ha restituito nulla, e sarebbe
    /// un'osservazione mai avvenuta dentro un atto.
    #[error("una fotografia del contesto richiede che Telegram abbia risposto")]
    SnapshotWithoutAnswer,

    /// La decisione smentisce il motore senza spiegare perché.
    ///
    /// La divergenza fra ciò che il motore ha segnalato e ciò che l'operatore
    /// giudica è il segnale da cui i dizionari si correggono: registrarla senza
    /// motivo la sprecherebbe.
    #[error("la decisione '{state}' richiede una motivazione")]
    ReviewNeedsReason {
        /// Stato richiesto.
        state: &'static str,
    },

    /// La decisione ripete lo stato già registrato.
    #[error("il contenuto e' gia' nello stato '{state}'")]
    ReviewStateUnchanged {
        /// Stato corrente.
        state: &'static str,
    },

    /// L'azione richiesta non è ammessa nello stato corrente del monitoraggio.
    ///
    /// L'insieme dei comandi ammessi è calcolato dai servizi, non
    /// dall'interfaccia: un pulsante che avvia un monitoraggio già concluso è
    /// una decisione di sicurezza, non un dettaglio grafico.
    #[error("azione di monitoraggio '{action}' non ammessa nello stato '{state}'")]
    MonitoringActionNotAllowed {
        /// Azione richiesta.
        action: &'static str,
        /// Stato corrente del monitoraggio.
        state: &'static str,
    },

    /// L'inizio programmato non è ammesso: troppo vicino o troppo lontano
    /// (SCHEDULE-01, ADR-0171). La ragione è scritta per l'operatore.
    #[error("inizio programmato rifiutato: {reason}")]
    ScheduleRefused {
        /// Perché, già scritto per chi legge.
        reason: &'static str,
    },

    /// La pausa dell'acquisizione non si mette o non si riprende (PAUSE-01,
    /// ADR-0172). La ragione è scritta per l'operatore.
    #[error("pausa dell'acquisizione rifiutata: {reason}")]
    PauseRefused {
        /// Perché, già scritto per chi legge.
        reason: &'static str,
    },

    /// La selezione contiene contenuti che la sessione non ha monitorato.
    ///
    /// Non è un dettaglio da assorbire in silenzio: significherebbe
    /// rappresentare in una relazione qualcosa che **questa** attività non ha
    /// osservato, e una relazione che lo facesse non sarebbe più spiegabile a
    /// partire dai propri dati.
    #[error(
        "la selezione contiene contenuti che questa sessione non ha monitorato: \
         una relazione può rappresentare solo ciò che l'attività ha osservato"
    )]
    ReportSelectionOutsideSession,

    /// Il documento non è stato composto.
    ///
    /// È distinto da [`Self::ExportNotWritten`] e la distinzione serve a chi
    /// deve capire che cosa è andato storto: qui il file non è mai esistito
    /// perché la scrittura del formato è fallita; là il documento c'era e non
    /// si è potuto posare sul disco.
    #[error("documento non generato: {reason}")]
    DocumentGeneration {
        /// Ragione tecnica, per il log.
        reason: String,
    },

    /// Il documento non è stato scritto.
    ///
    /// Comprende il caso di un documento con lo stesso nome già presente: non
    /// viene sostituito, perché un rapporto consegnato e poi cambiato in
    /// silenzio renderebbe vuota la promessa del manifest.
    #[error("documento non prodotto: {reason}")]
    ExportNotWritten {
        /// Ragione tecnica, per il log.
        reason: String,
    },

    /// Una copia dell'archivio o un pacchetto **non** è stato scritto perché
    /// la protezione del solo utente non si è potuta applicare e verificare
    /// (SEC-01, ADR-0157 integrato il 2026-10-22).
    ///
    /// È distinto da [`Self::ExportNotWritten`] perché la via d'uscita è
    /// un'altra: non riprovare fra un istante, ma scegliere una cartella in cui
    /// i permessi di Windows esistono. Nulla di ciò che il programma aveva
    /// cominciato a scrivere resta sul disco.
    #[error("{what}: protezione del solo utente non garantita: {reason}")]
    ProtectionNotGuaranteed {
        /// Che cosa non è stato scritto, come frase intera («La copia di
        /// sicurezza NON è stata scritta»).
        what: &'static str,
        /// Perché, in una frase per l'operatore, senza percorsi.
        reason: String,
    },

    /// Una copia cifrata dell'archivio non è stata scritta o non è stata
    /// aperta (ENCRYPT-01, ADR-0175): la frase troppo corta o sbagliata, un
    /// file che non è una copia cifrata, un blocco alterato, un nome già
    /// presente. Nulla di ciò che il programma aveva cominciato a scrivere
    /// resta sul disco.
    #[error("copia cifrata rifiutata: {reason}")]
    SealedCopyRefused {
        /// Perché, in una frase per l'operatore, senza la frase segreta.
        reason: String,
    },

    /// Il monitoraggio non ha nulla che si possa dire in STIX senza inventarlo.
    ///
    /// **Non è un guasto.** È l'esito onesto di una selezione in cui nessun
    /// valore regge la semantica dello standard: un pacchetto vuoto sarebbe
    /// formalmente valido e direbbe «non abbiamo trovato niente», che è una
    /// cosa diversa da «non c'è niente che si possa dire correttamente»
    /// (ADR-0057).
    #[error("nessun elemento del monitoraggio e' rappresentabile in STIX")]
    StixNothingToExport,

    /// L'importazione della fotografia ATT&CK è stata rifiutata.
    ///
    /// **Non è un guasto**: è un file che non è quello che dice di essere,
    /// oppure un contenuto che non supera la validazione.
    ///
    /// Il motivo è una **costante** e non un frammento del file: il pacchetto
    /// arriva da fuori, e un messaggio composto da un dato d'ingresso è un
    /// messaggio che un dato d'ingresso può riscrivere (ADR-0058).
    #[error("importazione della fotografia ATT&CK rifiutata: {reason}")]
    AttackImportRefused {
        /// Perché è stata rifiutata.
        reason: &'static str,
    },

    /// L'importazione della fotografia CVE è stata rifiutata.
    ///
    /// **Non è un guasto**: è un file che non è quello che NVD dichiara di aver
    /// pubblicato, oppure un contenuto che non supera la validazione.
    ///
    /// Il motivo è una **costante** e non un frammento del file, che arriva da
    /// fuori (ADR-0060).
    #[error("importazione della fotografia CVE rifiutata: {reason}")]
    CveImportRefused {
        /// Perché è stata rifiutata.
        reason: &'static str,
    },

    /// L'importazione della fotografia CISA KEV è stata rifiutata.
    ///
    /// **Non è un guasto**: è un file che non regge la propria coerenza — il
    /// conteggio che dichiara non corrisponde alle voci che contiene — oppure
    /// che è cambiato da quando è stato acquisito.
    ///
    /// Il motivo è una **costante** e non un frammento del file, che arriva da
    /// fuori (ADR-0061).
    #[error("importazione della fotografia KEV rifiutata: {reason}")]
    KevImportRefused {
        /// Perché è stata rifiutata.
        reason: &'static str,
    },

    /// Il documento non è arrivato dalla rete.
    ///
    /// **Non è un aggiornamento rifiutato**, ed è importante che siano due cose
    /// diverse: «è arrivato e non si può accettare» e «non è arrivato» portano a
    /// due azioni diverse, e appiattirle insegnerebbe a ignorarle entrambe.
    ///
    /// Il motivo viene dal trasporto, che compone le proprie frasi da testo
    /// **costante** più eventuali numeri (lo stato HTTP, il codice di Windows):
    /// nessun frammento di ciò che il server ha mandato entra qui.
    #[error("il documento non e' arrivato: {reason}")]
    UpdateNotFetched {
        /// Perché non è arrivato.
        reason: String,
    },

    /// Il manifesto indica l'artefatto su un altro host.
    ///
    /// **L'indirizzo dell'artefatto viene dal manifesto, che è dato non fidato**
    /// (ADR-0040): chi controlla il manifesto sceglierebbe dove la postazione va
    /// a bussare. ADR-0068 lo vincola allo **stesso host** dell'origine
    /// configurata, così chi decide con chi la postazione parla resta la
    /// configurazione.
    ///
    /// Il messaggio nomina l'host **configurato**, che è nostro, e non quello
    /// del manifesto: ripetere testo che arriva da fuori dentro una frase che
    /// un operatore legge è la cosa che questo prodotto non fa.
    #[error("l'artefatto non e' sull'host configurato ({expected})")]
    UpdateArtifactElsewhere {
        /// L'host dell'origine configurata.
        expected: String,
    },

    /// Il candidato indicato non esiste fra le scoperte registrate.
    #[error("il candidato indicato non risulta fra le scoperte registrate")]
    CandidateNotFound,

    /// Il candidato non ha un indirizzo pubblico.
    ///
    /// Non è un guasto: **senza indirizzo non c'è niente da aprire e niente da
    /// sorvegliare**, e dirlo è meglio che lasciare un comando che non funziona
    /// (ADR-0080).
    #[error("il candidato non ha un indirizzo pubblico: non c'e' niente da aprire")]
    CandidateWithoutAddress,

    /// Una decisione su un candidato è stata presa senza un motivo.
    ///
    /// Un motivo per candidato è la difesa più semplice contro il gesto: **non
    /// si scrive un motivo dieci volte per distrazione** (ADR-0080).
    #[error("una decisione su un candidato richiede un motivo")]
    CandidateDecisionWithoutReason,

    /// Un legame chiesto da una ricerca puntuale che non si può collegare
    /// (PR-10, ADR-0126): non è un «trovato», o non è una persona.
    ///
    /// Non è un guasto: è la regola. Un «dato non disponibile» collegato a un
    /// soggetto diventerebbe un'informazione che non c'è.
    #[error("la ricerca non si collega a un soggetto: {reason}")]
    LinkBasisRefused {
        /// Perché, nella frase per l'operatore.
        reason: &'static str,
    },

    /// L'aggiornamento non è stato consegnato perché non ha superato la verifica.
    ///
    /// Non è un guasto: è **il motivo per cui la verifica esiste**. Offrire di
    /// procedere comunque significherebbe che la verifica è decorativa
    /// (ADR-0037).
    #[error("l'aggiornamento non ha superato la verifica e non si consegna")]
    UpdateNotVerified,

    /// C'è un monitoraggio in corso, e non si sostituisce il programma mentre
    /// osserva.
    ///
    /// **Lo dice ADR-0037**, e la ragione è che sostituire il programma mentre
    /// osserva significa interrompere un'osservazione — che questo prodotto
    /// tratta come un fatto grave, con il proprio ADR (ADR-0064).
    ///
    /// Il rifiuto **non** è «riprova più tardi»: fermare un monitoraggio è una
    /// decisione di chi lo ha aperto.
    #[error("c'e' un monitoraggio in corso: l'aggiornamento non si consegna")]
    UpdateMonitoringRunning {
        /// Quanti monitoraggi stanno osservando.
        running: usize,
    },

    /// Il manifesto non offre un aggiornamento per questa postazione.

    ///
    /// Non è un guasto: è la risposta. Si scarica l'artefatto **solo** di un
    /// manifesto che è stato accettato, e accettarlo è una decisione che si
    /// rifà ogni volta.
    #[error("il manifesto non offre un aggiornamento per questa postazione")]
    UpdateNotOffered,

    /// Non esiste un'origine da cui scaricare.

    ///
    /// Di fabbrica non c'è, ed è la verità: nulla è pubblicato su alcun canale
    /// finché manca il certificato di firma. Un'origine inventata sarebbe un
    /// indirizzo che un giorno qualcuno contatta.
    #[error("nessuna origine configurata per gli aggiornamenti")]
    UpdateOriginMissing,

    /// L'origine scritta non è un indirizzo `https://` utilizzabile
    /// (OPERATOR-E2E-REMEDIATION-01, F-11).
    ///
    /// Prima si salvava e il messaggio d'errore della schermata veniva coperto
    /// dall'aggiornamento successivo: l'operatore non vedeva nulla.
    #[error("l'origine degli aggiornamenti non è accettabile: {reason}")]
    UpdateOriginRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// Non è stato indicato da dove scaricare i dizionari (DICT-NET-01,
    /// ADR-0178, decisione 5).
    ///
    /// Di fabbrica non c'è: finché manca, il programma non contatta nessuno.
    #[error("nessuna fonte configurata per i dizionari")]
    DictionarySourceMissing,

    /// Nessun firmatario di dizionari è ammesso (ADR-0178, decisione 4).
    ///
    /// Di fabbrica l'elenco è vuoto, e con l'elenco vuoto ogni dizionario
    /// scaricato si rifiuterebbe: non si va nemmeno in rete.
    #[error("nessun firmatario di dizionari ammesso")]
    NoDictionarySignerAllowed,

    /// La fonte dei dizionari scritta non è utilizzabile.
    #[error("la fonte dei dizionari non è accettabile: {reason}")]
    DictionarySourceRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// L'elenco dei firmatari scritto non è utilizzabile.
    #[error("i firmatari dei dizionari non sono accettabili: {reason}")]
    DictionarySignersRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// Non è stata indicata una destinazione TAXII (TAXII-01, ADR-0179,
    /// decisione 3).
    ///
    /// Di fabbrica non c'è: finché manca, il programma non manda niente.
    #[error("nessuna destinazione TAXII configurata")]
    TaxiiDestinationMissing,

    /// Mancano il nome utente o la parola d'ordine per TAXII (ADR-0179,
    /// decisione 5).
    ///
    /// La parola d'ordine è protetta per l'utente di Windows che l'ha scritta:
    /// un altro utente della stessa postazione non la legge, e la riscrive.
    #[error("mancano le credenziali TAXII")]
    TaxiiCredentialsMissing,

    /// La destinazione TAXII scritta non è utilizzabile.
    #[error("la destinazione TAXII non è accettabile: {reason}")]
    TaxiiDestinationRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// La parola d'ordine TAXII scritta non è utilizzabile, o non si è potuta
    /// proteggere.
    #[error("la parola d'ordine TAXII non è stata salvata: {reason}")]
    TaxiiPasswordRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// In Esercitazione non si manda (ADR-0179, decisione 8).
    #[error("in esercitazione non si manda a TAXII")]
    TaxiiInExercise,

    /// Non è stato scelto un certificato con cui firma l'ufficio (SIGN-01,
    /// ADR-0181, decisione 3).
    ///
    /// Di fabbrica non c'è: finché manca, il programma non firma niente.
    #[error("nessun certificato di firma scelto")]
    SigningCertificateMissing,

    /// Il certificato indicato non si può scegliere.
    #[error("il certificato di firma non è accettabile: {reason}")]
    SigningCertificateRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// Il registro delle consultazioni non si regola così (AUDIT-VIEW-01,
    /// ADR-0193).
    #[error("registro delle consultazioni rifiutato: {reason}")]
    ConsultationLogRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// Il rapporto complessivo non si produce (REPORT-MULTI-01, ADR-0192).
    #[error("rapporto complessivo rifiutato: {reason}")]
    OverviewRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// La pianificazione delle copie indicata non si può scegliere
    /// (BACKUP-SCHEDULE-01, ADR-0191).
    #[error("pianificazione delle copie rifiutata: {reason}")]
    BackupScheduleRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// Il firmatario degli aggiornamenti indicato non si può ammettere o
    /// ritirare (ADR-0183).
    #[error("il firmatario degli aggiornamenti non è accettabile: {reason}")]
    UpdateSignerRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// Una fotografia non si è potuta scaricare (SNAP-NET-01, ADR-0186).
    #[error("la fotografia non è stata scaricata: {reason}")]
    SnapshotDownloadRefused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },

    /// In Esercitazione non si firma (DEC-463, decisione 9).
    #[error("in esercitazione non si firma")]
    SigningInExercise,

    /// Il canale conservato in archivio non si riconosce.
    ///
    /// La migrazione ha un vincolo che lo impedisce, quindi questo errore
    /// significa una cosa sola: **qualcuno ha scritto nell'archivio a mano**.
    /// Ripiegare su «stabile» sarebbe comodo e sbagliato — una postazione messa
    /// sul pilota tornerebbe indietro in silenzio, e la scelta scritta direbbe
    /// una cosa mentre il programma ne fa un'altra.
    #[error("il canale degli aggiornamenti conservato non si riconosce: «{found}»")]
    UnreadableUpdateChannel {
        /// L'etichetta trovata, che viene dall'archivio e non da fuori.
        found: String,
    },

    /// La parola di sblocco proposta non è utilizzabile.
    ///
    /// Non è una password: protegge una modalità operativa, non un segreto. Ma
    /// una parola troppo corta si indovina al primo tentativo, e la modalità
    /// operatore diventerebbe una decorazione.
    #[error("la parola di sblocco non e' utilizzabile")]
    WeakUnlockWord,

    /// La parola di sblocco non corrisponde a quella fissata.
    #[error("parola di sblocco non corretta")]
    WrongUnlockWord,

    /// L'elenco delle persone è stato chiesto senza una ragione registrata.
    ///
    /// **Non è un errore tecnico.** Un elenco di persone non è un elenco di
    /// contenuti: chi lo custodisce risponde di averlo, e «l'ho tirato fuori
    /// perché il programma lo permetteva» non è una risposta. La ragione si
    /// registra una volta, resta nell'audit, e senza di essa l'elenco non si
    /// produce.
    #[error(
        "l'elenco delle persone richiede una ragione registrata: \
         va scritta una volta e resta nel registro delle operazioni"
    )]
    MissingParticipantBasis,

    /// L'azione è riservata alla modalità amministratore.
    ///
    /// Il rifiuto arriva dal **servizio**, non dall'interfaccia: un pulsante
    /// disabilitato non è un controllo, e questa regola è già quella adottata
    /// per i comandi dell'autenticazione.
    #[error("azione '{}' riservata alla modalita' amministratore", action.as_str())]
    ActionReservedToAdministrator {
        /// Azione rifiutata, che porta con sé la propria ragione.
        action: RestrictedAction,
    },

    /// Togliere un'organizzazione sorvegliata richiede un motivo.
    ///
    /// Sospenderla è reversibile e lascia una traccia leggibile; toglierla no.
    /// Senza un motivo, fra sei mesi l'unica cosa che si saprà è che qualcosa
    /// c'era e non c'è più.
    #[error("togliere un'organizzazione sorvegliata richiede un motivo registrato")]
    ReasonRequired,

    /// Il nome del dizionario è già usato da chi lo sta creando.
    #[error("nome di dizionario gia' usato dallo stesso autore")]
    DictionaryNameAlreadyUsed,

    /// Il termine c'è già nella versione, con la stessa modalità di riscontro
    /// (OPERATOR-E2E-REMEDIATION-01, F-10).
    ///
    /// È un doppione ordinario, che si corregge: presentarlo come «problema
    /// tecnico» diceva il falso e mandava a cercare un guasto che non c'era.
    #[error("il termine e' gia' presente in questa versione con la stessa modalita' di riscontro")]
    TermAlreadyInVersion,

    /// Quel termine è già associato a quella tecnica, e l'associazione è in
    /// piedi (OPERATOR-E2E-REMEDIATION-01, F-10).
    ///
    /// Un doppione che si corregge, non un guasto: ridichiarare dopo un ritiro
    /// si può, e sono due atti.
    #[error("quel termine e' gia' associato a quella tecnica")]
    AttackAssociationAlreadyStanding,

    /// È stata tentata una modifica su un dizionario di sistema.
    #[error("i dizionari di sistema non si modificano")]
    BuiltInDictionaryIsReadOnly,

    /// Il dizionario non ha alcuna versione pubblicata.
    #[error("il dizionario non ha versioni pubblicate")]
    DictionaryHasNoPublishedVersion,

    /// È stata tentata la pubblicazione di una versione senza termini.
    ///
    /// Non è un vincolo di integrità, ed è per questo che lo schema non lo
    /// impone: è una decisione di prodotto. Un dizionario pubblicato vuoto
    /// comparirebbe fra quelli selezionabili e non contribuirebbe nulla,
    /// lasciando credere il contrario.
    #[error("una versione senza termini non puo' essere pubblicata")]
    EmptyDictionaryVersion,

    /// È stata tentata una modifica su una versione già pubblicata.
    #[error("una versione pubblicata non si modifica")]
    PublishedVersionIsImmutable,

    /// Il dizionario scelto non è utilizzabile per una sessione.
    #[error("il dizionario '{name}' non e' selezionabile")]
    DictionaryNotSelectable {
        /// Nome del dizionario, che non è un dato riservato.
        name: String,
    },

    /// Il file di import supera la dimensione ammessa.
    ///
    /// **Limite di questa versione:** il controllo avviene sui byte già in
    /// memoria, perché `import` riceve il contenuto e non un percorso. Chi lo
    /// chiamerà da un selettore di file dovrà limitare la lettura **prima**,
    /// perché un limite applicato dopo l'apertura non protegge da ciò che
    /// l'apertura stessa comporta. Oggi nessun percorso dell'interfaccia
    /// importa da disco, quindi il difetto è latente e dichiarato.
    #[error("il file supera la dimensione massima ammessa di {max} byte")]
    ImportTooLarge {
        /// Dimensione massima ammessa.
        max: usize,
    },

    /// Il file di import non è utilizzabile.
    ///
    /// Il motivo è una costante di questo crate e **non** riporta il contenuto
    /// del file: un messaggio che citasse un campo scritto da chi ha prodotto
    /// il file gli lascerebbe scegliere che cosa l'operatore legge.
    #[error("il file non puo' essere importato: {reason}")]
    ImportRefused {
        /// Motivo del rifiuto.
        reason: &'static str,
    },

    /// Un termine del file è un'espressione che il programma non cerca
    /// (COLLAUDO-FIX-01, CU01-003, DEC-510).
    ///
    /// Il termine si nomina **per posizione** e non si cita: la stessa regola di
    /// [`Self::ImportRefused`]. Il motivo è una costante del dominio.
    #[error("il termine {position} del file non e' un'espressione ammessa: {reason}")]
    ImportExpressionRefused {
        /// La posizione del termine nel file, da 1.
        position: usize,
        /// Perché l'espressione non è ammessa.
        reason: &'static str,
    },

    /// Un fascicolo condivisibile non e' stato accettato.
    ///
    /// # Perche' non riusa `ImportRefused`
    ///
    /// Quella variante porta un motivo **fisso**, e i controlli del fascicolo
    /// producono ragioni diverse fra loro: dimensione, forma, versione,
    /// impronta, un valore non ammesso. Appiattirle in un testo unico
    /// toglierebbe a chi legge l'unica cosa che serve — **quale** controllo ha
    /// fallito.
    #[error("fascicolo non accettato: {reason}")]
    FascicoloRefused {
        /// Il motivo, gia' scritto per una persona.
        reason: String,
    },

    /// Una voce della scheda del soggetto non accettata (ADR-0153): soggetto
    /// chiuso, testo vuoto, ragione troppo corta, voce che non esiste.
    #[error("voce del soggetto non accettata: {reason}")]
    SubjectEntryRefused {
        /// Il motivo, gia' scritto per una persona.
        reason: String,
    },

    /// La sessione non ha alcun termine con cui lavorare.
    ///
    /// Una sessione senza termini acquisirebbe contenuti senza poterne
    /// segnalare alcuno: sembrerebbe funzionare e non direbbe nulla.
    #[error("nessun dizionario scelto e nessuna parola aggiunta")]
    EmptyDictionarySelection,

    /// Il collegamento non è stato aperto.
    ///
    /// Il motivo è una **costante**, non l'URL: un indirizzo ostile non deve
    /// scegliere il testo che l'operatore legge.
    #[error("collegamento non aperto: {reason}")]
    LinkNotOpened {
        /// Motivo tecnico, costante.
        reason: &'static str,
    },

    /// Errore proveniente dal connettore.
    #[error("errore del connettore: {0}")]
    Connector(#[from] TelegramError),

    /// Guasto diagnosticato durante l'avvio della modalita' Live, con la fase
    /// esatta in cui si e' presentato.
    ///
    /// Nasce dalla lacuna osservata nel pilot Live del 2026-07-29: prima di
    /// questa variante, ogni guasto durante l'avvio Live confluiva nella
    /// categoria generica [`Self::Connector`], senza dire quale fase fosse
    /// fallita. Vedere [`crate::live_diagnostics`].
    #[error("{0}")]
    LiveStartup(crate::live_diagnostics::LiveDiagnostic),

    /// Il monitoraggio non risulta avviato, e senza un periodo di osservazione
    /// una cronologia non si compone.
    ///
    /// # Perché è un errore e non una cronologia senza finestra
    ///
    /// Perché una linea del tempo con dei buchi si legge in un modo solo — «qui
    /// non è successo niente» — e la finestra di osservazione è l'unica cosa che
    /// la rende leggibile. Mostrarla comunque significherebbe consegnare a chi
    /// legge una successione di vuoti senza il fatto che li spiega (ADR-0053).
    #[error("il monitoraggio #{session} non risulta avviato: non ha un periodo di osservazione")]
    NoObservationWindow {
        /// Il monitoraggio.
        session: i64,
    },
    /// Errore proveniente dalla persistenza.
    #[error("errore della persistenza: {0}")]
    Storage(#[from] StorageError),

    /// Un valore non rispetta le invarianti del dominio.
    #[error("valore non valido: {0}")]
    Domain(#[from] DomainError),

    /// Errore proveniente dalla protezione locale dei segreti.
    ///
    /// Comprende la derivazione e la verifica delle frasi di accesso
    /// (TEAM-ASSIGN-01, ADR-0097). **Non contiene mai una frase.**
    #[error("errore della protezione locale: {0}")]
    Security(#[from] lisi_security::SecurityError),
}

impl ServiceError {
    /// Messaggio destinato all'operatore.
    ///
    /// Dice che cosa è successo **e** che cosa fare. Un messaggio che si limita
    /// a constatare il guasto lascia l'operatore senza una via d'uscita.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::CommandNotAllowed { .. } => String::from(
                "Questa operazione non è disponibile in questo momento. \
                 Se il problema persiste, segnalarlo all'amministratore.",
            ),
            Self::CodeRejected => String::from(
                "Il codice inserito non è corretto. Controllare il messaggio ricevuto \
                 da Telegram e reinserirlo.",
            ),
            Self::PasswordRejected => String::from(
                "La password della verifica in due passaggi non è corretta. Reinserirla.",
            ),
            Self::SessionRevoked => String::from(
                "L'accesso è stato revocato, probabilmente da un altro dispositivo. \
                 È necessario accedere di nuovo.",
            ),
            // D-18: il messaggio nomina soltanto comandi che esistono, e il
            // percorso che toglie l'account e' detto solo per l'accesso a
            // Telegram. Questa variante nasce anche altrove — un profilo che
            // manca, la cartella dati, la protezione locale — e li' togliere
            // l'account sarebbe il consiglio sbagliato.
            Self::SessionUnavailable { .. } => String::from(SESSION_UNAVAILABLE_MESSAGE),
            Self::ApplicationNotConfigured => String::from(APPLICATION_NOT_CONFIGURED_MESSAGE),
            // La ragione è già scritta per l'operatore, e si mostra così com'è.
            // I valori che vi compaiono sono testi già validati — nomi di Hub,
            // messaggi costanti — e non contengono segreti.
            Self::DeviceIdentity { reason } => reason.clone(),
            Self::HubForbidden { reason } => reason.clone(),
            Self::HubClient { reason } => reason.clone(),
            Self::HubServer { reason } => reason.clone(),
            Self::AccountInUse => String::from(
                "Questo account è già in uso, in questa finestra o in un'altra finestra \
                 del programma. Chiuderlo prima di riaprirlo o di rimuoverlo.",
            ),
            Self::ActiveAccountLimit { limit } => format!(
                "Sono già attivi {limit} account, il massimo. Per attivarne un altro, \
                 chiuderne prima uno: nessun account ne sostituisce un altro da sé."
            ),
            Self::NetworkUnavailable => {
                String::from("La rete non è raggiungibile. Verificare la connessione e riprovare.")
            }
            Self::TimedOut => String::from(
                "L'operazione ha impiegato troppo tempo. Riprovare fra qualche istante.",
            ),
            Self::Cancelled => String::from("Operazione annullata."),
            Self::SourceNotAccessible => String::from(
                "La fonte indicata non risulta accessibile all'account configurato. \
                 L'accesso alla fonte va ottenuto con le vie ordinarie: \
                 l'applicazione non vi accede automaticamente.",
            ),
            Self::SourceAlreadyConfigured => {
                String::from("Questa fonte è già presente nell'elenco.")
            }
            Self::WorkspaceNameTaken { name } => format!(
                "Esiste già un raccoglitore aperto che si chiama «{name}». Due contenitori aperti \
                 con lo stesso nome sono una trappola: si mette una cosa nell'uno credendo di \
                 metterla nell'altro. Scegliere un altro nome, oppure aggiungere a quello che \
                 c'è già."
            ),
            Self::WorkspaceClosed { name } => format!(
                "Il raccoglitore «{name}» è chiuso: non accetta né perde elementi, e non si riapre. \
                 Se il lavoro continua, crearne un altro."
            ),
            Self::AlreadyInWorkspace { name } => format!(
                "Questo elemento è già nel raccoglitore «{name}»: non è stato aggiunto una \
                 seconda volta."
            ),
            Self::AlreadyBookmarked => String::from(
                "Questa cosa è già segnata. Il segnalibro che c'è già la ritrova: due segni \
                 sulla stessa cosa non ne aggiungono uno, la farebbero contare due volte.",
            ),
            Self::CollectionNameTaken { name } => format!(
                "Esiste già una raccolta che si chiama «{name}». A differenza di un raccoglitore, \
                 una raccolta non si chiude: il nome resta preso. Scegliere un altro nome, \
                 oppure mettere il segnalibro nella raccolta che c'è già."
            ),
            Self::CollectionNotEmpty { count } => format!(
                "La raccolta contiene ancora {count} segnalibri: cancellarla porterebbe via i \
                 segni che qualcuno aveva messo. Toglierli prima, oppure spostarli in un'altra \
                 raccolta."
            ),
            Self::TemplateNameTaken { name } => format!(
                "Esiste già un modello di monitoraggio che si chiama «{name}». Preparare un \
                 monitoraggio con il modello sbagliato non si vede, e per questo i nomi devono \
                 restare distinti. Scegliere un altro nome, oppure cancellare quello che c'è: un \
                 modello non si modifica, perché porta chi lo ha creato e quando."
            ),
            Self::PersonAlreadyClosed => String::from(
                "Non c'è nulla da chiudere: questo soggetto è già stato chiuso, oppure non esiste \
                 più nell'elenco che si sta guardando. Un soggetto chiuso non si riapre. \
                 Altrimenti la chiusura sarebbe una parentesi invece che un fatto. Chi avesse letto \
                 «chiuso» non saprebbe che adesso non lo è più. Se il lavoro riprende, se ne apre \
                 uno nuovo, con la ragione che lo giustifica adesso.",
            ),
            Self::NoteAlreadyWithdrawn => String::from(
                "Non c'è nulla da ritirare: questa nota è già stata ritirata, oppure non esiste \
                 più nell'elenco che si sta guardando. Una nota non si riscrive — porta chi \
                 l'ha scritta e quando, e cambiarne il testo farebbe dire a quei due valori una \
                 cosa falsa. Se serve dire qualcosa di diverso, scriverne una nuova.",
            ),
            Self::SavedSearchNameTaken { name } => format!(
                "Esiste già una ricerca salvata che si chiama «{name}». Scegliere un altro \
                 nome, oppure cancellare quella che c'è: una ricerca salvata non si modifica, \
                 perché porta chi l'ha salvata e quando."
            ),
            Self::SnapshotNeedsReason => String::from(
                "Conservare ciò che Telegram mostra adesso è un atto di cui qualcuno risponde: \
                 indicare perché lo si conserva. Senza una ragione la fotografia non sarebbe \
                 documentata, e chi la rileggesse fra un anno non saprebbe a che cosa servisse.",
            ),
            Self::SnapshotWithoutAnswer => String::from(
                "La fotografia non si prende: Telegram non ha dato i messaggi attorno, e il \
                 perché è scritto più sopra. Una fotografia presa così conserva una risposta che \
                 non c'è stata. Se manca il collegamento, collegare un account e riaprire la \
                 conversazione.",
            ),
            // DUE FRASI, PERCHÉ LE RAGIONI SONO DUE (OPERATOR-UX-REMEDIATION-01,
            // OS-04). «Segnalato» non contraddice nulla: chiede un motivo perché
            // chi riceve la segnalazione deve sapere perché. La frase sul
            // disaccordo detta a chi voleva segnalare lo confondeva.
            Self::ReviewNeedsReason { state } if *state == "reported" => String::from(
                "Per «Segnalato» serve un motivo: scriverlo nel campo «Motivo» e premere di \
                 nuovo «Segnalato». Chi riceve la segnalazione deve sapere perché.",
            ),
            Self::ReviewNeedsReason { .. } => String::from(
                "Il monitoraggio aveva segnalato questo messaggio, e questa decisione dice il \
                 contrario: scrivere perché nel campo «Motivo» e premere di nuovo. Il motivo \
                 serve a correggere i dizionari.",
            ),
            Self::ReviewStateUnchanged { .. } => {
                String::from("Il contenuto si trova già in questo stato: nulla da registrare.")
            }
            Self::MonitoringActionNotAllowed { .. } => {
                String::from("Questa azione non è ammessa sul monitoraggio nel suo stato attuale.")
            }
            Self::ScheduleRefused { reason } | Self::PauseRefused { reason } => {
                String::from(*reason)
            }
            Self::ExportNotWritten { .. } => String::from(
                "Il documento non è stato prodotto. La cartella dei documenti potrebbe non \
                 essere scrivibile. Oppure esiste già un rapporto con lo stesso nome: in quel \
                 caso attendere un istante e riprovare, perché il nome contiene l'ora.",
            ),
            Self::ProtectionNotGuaranteed { what, reason } => format!(
                "{what}. In questa cartella i permessi di Windows non si sono potuti \
                 restringere al solo utente. Il programma non lascia sul disco file \
                 leggibili da altri utenti: non è rimasto nulla. {reason}. Scegliere una \
                 cartella su un disco di questo computer, per esempio una cartella personale, \
                 e riprovare. Per portare i file altrove, copiarli dopo: i permessi non \
                 viaggiano con i file."
            ),
            Self::SealedCopyRefused { reason } => format!(
                "La copia cifrata non è stata scritta o aperta: {reason}. Nella cartella \
                 scelta non è rimasto nulla."
            ),
            Self::CveImportRefused { .. } => String::from(
                "La fotografia CVE non è stata importata. Un file non è quello che NVD dichiara \
                 di aver pubblicato, oppure il suo contenuto non è utilizzabile. Rifare \
                 l'acquisizione con la procedura prevista.",
            ),
            Self::UpdateNotFetched { reason } => format!(
                "L'informazione sull'aggiornamento non è arrivata: {reason}. \
                 Non significa che non ci sia un aggiornamento, e non significa \
                 che ce ne sia uno: significa che non si è potuto sapere."
            ),
            Self::UpdateArtifactElsewhere { expected } => format!(
                "L'informazione ricevuta indica il file dell'aggiornamento su un \
                 indirizzo diverso da quello configurato ({expected}). Non è stato \
                 scaricato nulla: dove questa postazione va a prendere il \
                 programma lo decide la configurazione, non il documento."
            ),
            Self::CandidateNotFound => String::from(
                "Il suggerimento indicato non risulta più fra quelli registrati. \
                 Riaprire la ricerca e riprovare.",
            ),
            Self::CandidateWithoutAddress => String::from(
                "Questa chat non ha un indirizzo pubblico: non c'è niente da aprire e \
                 niente da sorvegliare. Se serve, va aggiunta a mano dalla schermata \
                 delle fonti.",
            ),
            Self::CandidateDecisionWithoutReason => String::from(
                "Scrivere il motivo della decisione prima di confermarla: resta in \
                 archivio insieme alla decisione.",
            ),
            Self::LinkBasisRefused { reason } => String::from(*reason),
            Self::UpdateNotVerified => String::from(
                "Il file non ha superato la verifica, quindi non è stato \
                 consegnato e non è stato installato nulla. Non è un guasto: è \
                 il motivo per cui la verifica esiste.",
            ),
            Self::UpdateMonitoringRunning { running } => format!(
                "C'è {running} monitoraggio in corso su questa postazione, e \
                 sostituire il programma mentre osserva significherebbe \
                 interrompere l'osservazione. Va fermato da chi lo ha aperto, e \
                 non è il programma a decidere quando."
            ),
            Self::UpdateNotOffered => String::from(
                "L'informazione ricevuta non offre un aggiornamento per questa \
                 postazione, quindi non c'è niente da scaricare.",
            ),
            Self::UpdateOriginRefused { reason } => {
                format!("L'origine non è stata salvata: {reason}. Resta quella di prima.")
            }
            Self::DictionarySourceMissing => String::from(
                "Non è stato indicato un indirizzo da cui scaricare i dizionari. Finché \
                 non c'è, il programma non contatta nessuno.",
            ),
            Self::NoDictionarySignerAllowed => String::from(
                "Nessun firmatario di dizionari è ammesso. Finché l'elenco è vuoto, ogni \
                 dizionario scaricato si rifiuterebbe: il programma non lo scarica.",
            ),
            Self::DictionarySourceRefused { reason } => format!(
                "L'indirizzo dei dizionari non è stato salvato: {reason}. Resta quello di prima."
            ),
            Self::DictionarySignersRefused { reason } => {
                format!("I firmatari non sono stati salvati: {reason}. Restano quelli di prima.")
            }
            Self::TaxiiDestinationMissing => String::from(
                "Non è stata indicata una destinazione TAXII. Finché non c'è, il programma \
                 non manda niente.",
            ),
            Self::TaxiiCredentialsMissing => String::from(
                "Mancano il nome o la parola d'ordine della destinazione TAXII: senza, il \
                 programma non manda niente. La parola d'ordine la scrive ogni utente di \
                 Windows, in modalità amministratore.",
            ),
            Self::TaxiiDestinationRefused { reason } => format!(
                "La destinazione TAXII non è stata salvata: {reason}. Resta quella di prima."
            ),
            Self::TaxiiPasswordRefused { reason } => {
                format!("La parola d'ordine non è stata salvata: {reason}. Resta quella di prima.")
            }
            Self::SigningCertificateMissing => String::from(
                "Non è stato scelto un certificato con cui firma l'ufficio. Finché non c'è, il \
                 programma non firma niente. Lo sceglie l'amministratore.",
            ),
            Self::SigningCertificateRefused { reason } => {
                format!("Il certificato non è stato scelto: {reason}. Resta quello di prima.")
            }
            Self::ConsultationLogRefused { reason } => {
                format!("Il registro delle consultazioni non è cambiato: {reason}.")
            }
            Self::OverviewRefused { reason } => {
                format!("Il rapporto complessivo non è stato prodotto: {reason}.")
            }
            Self::BackupScheduleRefused { reason } => {
                format!("La pianificazione delle copie non è cambiata: {reason}.")
            }
            Self::UpdateSignerRefused { reason } => {
                format!("Il firmatario degli aggiornamenti non è cambiato: {reason}.")
            }
            Self::SnapshotDownloadRefused { reason } => {
                format!(
                    "La fotografia non è stata scaricata: {reason}. Le fotografie di prima restano."
                )
            }
            Self::SigningInExercise => String::from(
                "In esercitazione non si firma: fuori da questa postazione un dato di prova \
                 firmato dall'ufficio sembra vero.",
            ),
            Self::TaxiiInExercise => String::from(
                "In esercitazione non si manda niente a TAXII: fuori da questa postazione un \
                 dato di prova sembra vero.",
            ),
            Self::UpdateOriginMissing => String::from(
                "Non è stata indicata un'origine da cui scaricare l'informazione \
                 sugli aggiornamenti. Finché non c'è, il programma non contatta \
                 nessuno.",
            ),
            Self::UnreadableUpdateChannel { .. } => String::from(
                "Il canale degli aggiornamenti scritto in archivio non si riconosce. \
                 Il programma non sceglie al posto di chi lo aveva impostato: \
                 l'impostazione va rifatta.",
            ),
            Self::KevImportRefused { .. } => String::from(
                "Il catalogo CISA KEV non è stato importato. Il file non è coerente: il numero \
                 di voci che dichiara non corrisponde a quelle che contiene. Oppure è cambiato \
                 da quando è stato acquisito. Rifare l'acquisizione con la procedura prevista.",
            ),
            Self::AttackImportRefused { .. } => String::from(
                "La fotografia MITRE ATT&CK non è stata importata. Il file non è quello che \
                 questa versione del programma conosce, oppure il suo contenuto non è \
                 utilizzabile. Rifare l'acquisizione con la procedura prevista. Non aggirare \
                 un'impronta diversa.",
            ),
            Self::StixNothingToExport => String::from(
                "Nessun elemento di questo monitoraggio si può rappresentare in STIX senza \
                 affermare più di quanto si sappia. Non è un errore: il pacchetto non viene \
                 prodotto invece di uscire vuoto o inesatto.",
            ),
            Self::DocumentGeneration { .. } => String::from(
                "Il documento non è stato generato e nessun file è stato scritto. \
                 Riprovare; se il problema resta, segnalarlo con l'ora esatta del tentativo.",
            ),
            Self::ReportSelectionOutsideSession => String::from(
                "La selezione comprende contenuti che questo monitoraggio non ha acquisito. \
                 Rivedere la scelta: una relazione può rappresentare soltanto ciò che \
                 l'attività ha osservato.",
            ),
            Self::WeakUnlockWord => String::from(
                "La parola di sblocco deve avere almeno quattro caratteri e non contenere \
                 caratteri speciali di controllo. Sceglierne una più robusta.",
            ),
            Self::MissingParticipantBasis => String::from(
                "L'elenco delle persone non è stato prodotto: manca la ragione per cui \
                 l'ufficio lo compone. Va scritta una volta, in APPROFONDIRE › Persone, resta nel \
                 registro delle operazioni, e da quel momento l'elenco è disponibile. Non è una \
                 formalità: chi custodisce un elenco di persone risponde di averlo.",
            ),
            Self::WrongUnlockWord => String::from(
                "La parola di sblocco non è corretta. Reinserirla. Se è stata dimenticata, \
                 la postazione va riconfigurata da chi la amministra.",
            ),
            Self::ActionReservedToAdministrator { action } => format!(
                "Questa operazione è riservata alla modalità amministratore, perché {}. \
                 Chiedere a chi amministra la postazione di eseguirla.",
                action.reason()
            ),
            Self::ReasonRequired => String::from(
                "Per togliere un'organizzazione sorvegliata serve un motivo. \
                 Sospenderla, invece, non lo richiede: ferma i riscontri futuri \
                 e lascia leggibili quelli già registrati.",
            ),
            Self::DictionaryNameAlreadyUsed => {
                String::from("Esiste già un dizionario con questo nome. Sceglierne uno diverso.")
            }
            Self::AttackAssociationAlreadyStanding => String::from(
                "Questo termine è già associato a questa tecnica, e l'associazione è in \
                 vigore: non è stata dichiarata una seconda volta. Per cambiarne il motivo, \
                 ritirarla e dichiararla di nuovo.",
            ),
            Self::TermAlreadyInVersion => String::from(
                "Questo termine c'è già nella bozza, cercato nello stesso modo: non è stato \
                 aggiunto una seconda volta. Per cambiarne il livello o la categoria, toglierlo \
                 dalla bozza e aggiungerlo di nuovo.",
            ),
            Self::BuiltInDictionaryIsReadOnly => String::from(
                "I dizionari forniti con il prodotto non si modificano. \
                 Usare \"Duplica\" per ottenerne una copia da modificare liberamente.",
            ),
            Self::DictionaryHasNoPublishedVersion => String::from(
                "Questo dizionario non ha ancora una versione pubblicata. \
                 Aggiungere i termini e pubblicare la versione per poterlo usare.",
            ),
            Self::EmptyDictionaryVersion => String::from(
                "Non ci sono termini da pubblicare. Aggiungere almeno un termine \
                 prima di pubblicare la versione.",
            ),
            Self::PublishedVersionIsImmutable => String::from(
                "Questa versione è già pubblicata e non si modifica. \
                 Usare \"Nuova versione\" per apportare correzioni: la versione \
                 pubblicata resta, così che le sessioni già svolte restino leggibili.",
            ),
            Self::DictionaryNotSelectable { name } => format!(
                "Il dizionario \"{name}\" non è utilizzabile: è archiviato oppure \
                 non ha una versione pubblicata. Toglierlo dalla scelta o pubblicarne \
                 una versione."
            ),
            Self::ImportTooLarge { .. } => String::from(
                "Il file è troppo grande per essere un dizionario. \
                 Controllare di avere scelto il file giusto.",
            ),
            // Il motivo arriva gia' scritto per una persona dal modulo che ha
            // rifiutato: riscriverlo qui perderebbe la ragione precisa.
            Self::FascicoloRefused { reason } => reason.clone(),
            Self::SubjectEntryRefused { reason } => reason.clone(),
            Self::ImportRefused { reason } => format!(
                "Il file non può essere importato: {reason}. \
                 Chiedere a chi lo ha inviato di esportarlo di nuovo dal prodotto."
            ),
            Self::ImportExpressionRefused { position, reason } => format!(
                "Il dizionario non è stato importato: l'espressione del termine numero \
                 {position} del file non è ammessa. Il motivo: {reason}. Correggere il file e \
                 riprovare."
            ),
            Self::EmptyDictionarySelection => String::from(
                "Non è stato scelto alcun dizionario e non è stata aggiunta alcuna parola. \
                 Il monitoraggio acquisirebbe contenuti senza poterne segnalare alcuno.",
            ),
            Self::LinkNotOpened { .. } => String::from(
                "Non è stato possibile aprire il collegamento. Deve essere un indirizzo web \
                 (che comincia con http:// o https://). Un altro tipo di indirizzo non viene aperto, per sicurezza.",
            ),
            Self::NoObservationWindow { session } => format!(
                "Il monitoraggio #{session} non risulta avviato. Senza il periodo in cui si è \
                 osservato, una cronologia non si può mostrare. Righe senza quel periodo si \
                 leggerebbero come «qui non è successo niente»."
            ),
            Self::Connector(TelegramError::InvalidSecret { field, reason }) => format!(
                "Il campo «{}» non è valido: {reason}.",
                friendly_secret_field_name(field)
            ),
            Self::Security(_) => String::from(
                "La protezione locale dei segreti non ha risposto. Se il problema resta, \
                 segnalarlo a chi amministra.",
            ),
            // LA FRASE DICE «REGISTRATO», E QUI SI REGISTRA (UX-EXCELLENCE-02,
            // SIM3-02). Il messaggio prometteva un dettaglio nel registro
            // applicativo, ma la registrazione toccava a chi mostrava il
            // messaggio, e molti non la facevano: chi cercava trovava il registro
            // vuoto. Ora la promessa e la scrittura stanno nello stesso punto.
            Self::Connector(_) => {
                tracing::warn!(
                    kind = self.kind(),
                    "problema tecnico mostrato all'operatore"
                );
                String::from(TECHNICAL_PROBLEM)
            }
            Self::Storage(errore) => {
                tracing::warn!(
                    kind = self.kind(),
                    dettaglio = %errore,
                    "problema tecnico mostrato all'operatore"
                );
                String::from(TECHNICAL_PROBLEM)
            }
            Self::LiveStartup(diagnostic) => diagnostic.operator_summary(),
            Self::Domain(error) => domain_operator_message(error),
        }
    }

    /// Etichetta stabile per l'audit.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::CommandNotAllowed { .. } => "comando_non_ammesso",
            Self::CodeRejected => "codice_rifiutato",
            Self::PasswordRejected => "password_rifiutata",
            Self::SessionRevoked => "sessione_revocata",
            Self::SessionUnavailable { .. } => "sessione_non_accessibile",
            Self::ApplicationNotConfigured => "applicazione_non_configurata",
            Self::DeviceIdentity { .. } => "identita_dispositivo",
            Self::HubForbidden { .. } => "azione_non_consentita_dall_hub",
            Self::HubClient { .. } => "collegamento_hub",
            Self::HubServer { .. } => "modalita_hub",
            Self::AccountInUse => "account_in_uso",
            Self::ActiveAccountLimit { .. } => "tetto_degli_account_attivi",
            Self::NetworkUnavailable => "rete_non_disponibile",
            Self::TimedOut => "attesa_scaduta",
            Self::Cancelled => "annullato",
            Self::SourceNotAccessible => "fonte_non_accessibile",
            Self::CandidateNotFound => "candidato_non_trovato",
            Self::CandidateWithoutAddress => "candidato_senza_indirizzo",
            Self::CandidateDecisionWithoutReason => "decisione_senza_motivo",
            Self::LinkBasisRefused { .. } => "base_del_legame_rifiutata",
            Self::SourceAlreadyConfigured => "fonte_gia_presente",
            Self::WorkspaceNameTaken { .. } => "workspace_nome_gia_preso",
            Self::WorkspaceClosed { .. } => "workspace_chiuso",
            Self::AlreadyInWorkspace { .. } => "workspace_elemento_gia_presente",
            Self::AlreadyBookmarked => "gia_segnato",
            Self::CollectionNameTaken { .. } => "raccolta_nome_gia_preso",
            Self::CollectionNotEmpty { .. } => "raccolta_non_vuota",
            Self::TemplateNameTaken { .. } => "modello_nome_gia_preso",
            Self::PersonAlreadyClosed => "soggetto_gia_chiuso",
            Self::NoteAlreadyWithdrawn => "nota_gia_ritirata",
            Self::SavedSearchNameTaken { .. } => "ricerca_nome_gia_preso",
            Self::SnapshotNeedsReason => "fotografia_senza_ragione",
            Self::SnapshotWithoutAnswer => "fotografia_senza_risposta",
            Self::ReviewNeedsReason { .. } => "revisione_senza_motivazione",
            Self::ReviewStateUnchanged { .. } => "revisione_invariata",
            Self::MonitoringActionNotAllowed { .. } => "azione_monitoraggio_non_ammessa",
            Self::ScheduleRefused { .. } => "inizio_programmato_rifiutato",
            Self::PauseRefused { .. } => "pausa_acquisizione_rifiutata",
            Self::ExportNotWritten { .. } => "documento_non_prodotto",
            Self::ProtectionNotGuaranteed { .. } => "protezione_non_garantita",
            Self::SealedCopyRefused { .. } => "copia_cifrata_rifiutata",
            Self::CveImportRefused { .. } => "cve_importazione_rifiutata",
            Self::KevImportRefused { .. } => "kev_importazione_rifiutata",
            Self::UnreadableUpdateChannel { .. } => "canale_aggiornamenti_illeggibile",
            Self::UpdateNotFetched { .. } => "aggiornamento_non_scaricato",
            Self::UpdateArtifactElsewhere { .. } => "artefatto_su_altro_host",
            Self::UpdateNotOffered => "aggiornamento_non_offerto",
            Self::UpdateNotVerified => "aggiornamento_non_verificato",
            Self::UpdateMonitoringRunning { .. } => "monitoraggio_in_corso",
            Self::UpdateOriginMissing => "origine_aggiornamenti_assente",
            Self::UpdateOriginRefused { .. } => "origine_aggiornamenti_rifiutata",
            Self::DictionarySourceMissing => "fonte_dizionari_assente",
            Self::NoDictionarySignerAllowed => "firmatari_dizionari_assenti",
            Self::DictionarySourceRefused { .. } => "fonte_dizionari_rifiutata",
            Self::DictionarySignersRefused { .. } => "firmatari_dizionari_rifiutati",
            Self::TaxiiDestinationMissing => "taxii_destinazione_assente",
            Self::TaxiiCredentialsMissing => "taxii_credenziali_assenti",
            Self::TaxiiDestinationRefused { .. } => "taxii_destinazione_rifiutata",
            Self::TaxiiPasswordRefused { .. } => "taxii_parola_rifiutata",
            Self::TaxiiInExercise => "taxii_in_esercitazione",
            Self::SigningCertificateMissing => "firma_certificato_assente",
            Self::SigningCertificateRefused { .. } => "firma_certificato_rifiutato",
            Self::BackupScheduleRefused { .. } => "pianificazione_copie_rifiutata",
            Self::OverviewRefused { .. } => "rapporto_complessivo_rifiutato",
            Self::ConsultationLogRefused { .. } => "registro_consultazioni_rifiutato",
            Self::SigningInExercise => "firma_in_esercitazione",
            Self::SnapshotDownloadRefused { .. } => "fotografia_non_scaricata",
            Self::UpdateSignerRefused { .. } => "firmatario_aggiornamenti_rifiutato",
            Self::AttackImportRefused { .. } => "attack_importazione_rifiutata",
            Self::StixNothingToExport => "stix_nulla_da_esportare",
            Self::DocumentGeneration { .. } => "documento_non_generato",
            Self::ReportSelectionOutsideSession => "selezione_fuori_sessione",
            Self::WeakUnlockWord => "parola_sblocco_debole",
            Self::WrongUnlockWord => "parola_sblocco_errata",
            Self::MissingParticipantBasis => "ragione_elenco_persone_mancante",
            Self::ActionReservedToAdministrator { .. } => "azione_riservata",
            Self::ReasonRequired => "motivo_obbligatorio",
            Self::DictionaryNameAlreadyUsed => "nome_dizionario_gia_usato",
            Self::TermAlreadyInVersion => "termine_gia_presente",
            Self::AttackAssociationAlreadyStanding => "associazione_attack_gia_presente",
            Self::BuiltInDictionaryIsReadOnly => "dizionario_di_sistema",
            Self::DictionaryHasNoPublishedVersion => "dizionario_senza_versioni",
            Self::EmptyDictionaryVersion => "versione_senza_termini",
            Self::PublishedVersionIsImmutable => "versione_gia_pubblicata",
            Self::DictionaryNotSelectable { .. } => "dizionario_non_selezionabile",
            Self::ImportTooLarge { .. } => "import_troppo_grande",
            Self::ImportRefused { .. } => "import_rifiutato",
            Self::ImportExpressionRefused { .. } => "import_espressione_rifiutata",
            Self::FascicoloRefused { .. } => "fascicolo_rifiutato",
            Self::SubjectEntryRefused { .. } => "voce_soggetto_rifiutata",
            Self::EmptyDictionarySelection => "selezione_vuota",
            Self::LinkNotOpened { .. } => "collegamento_non_aperto",
            Self::NoObservationWindow { .. } => "nessun_periodo_di_osservazione",
            Self::Connector(_) => "errore_connettore",
            Self::LiveStartup(diagnostic) => diagnostic.code(),
            Self::Storage(_) => "errore_persistenza",
            Self::Security(_) => "errore_protezione_locale",
            Self::Domain(_) => "valore_non_valido",
        }
    }

    /// Se l'operatore può correggere reinserendo un dato.
    #[must_use]
    pub const fn is_correctable_by_operator(&self) -> bool {
        matches!(self, Self::CodeRejected | Self::PasswordRejected)
    }
}

/// Messaggio per l'operatore di un errore di validazione di un campo digitato.
///
/// Un campo che l'operatore ha appena scritto (nome, etichetta, numero...) e
/// che risulta vuoto, troppo lungo o con caratteri non ammessi va segnalato
/// con la ragione: il messaggio tecnico generico degli altri errori di
/// servizio lascerebbe l'operatore a indovinare quale campo correggere. Le
/// varianti restanti di [`DomainError`] nascono da dati che l'operatore non
/// digita direttamente (orologio, impronte, stato conservato...): per quelle
/// resta il messaggio tecnico generico.
fn domain_operator_message(error: &DomainError) -> String {
    match error {
        DomainError::Empty { .. } => {
            String::from("Il campo non può essere lasciato vuoto. Inserire un valore e riprovare.")
        }
        DomainError::TooLong { max, actual, .. } => format!(
            "Il testo inserito è troppo lungo: sono ammessi al massimo {max} \
             caratteri, ne sono stati inseriti {actual}. Accorciarlo e riprovare."
        ),
        DomainError::ControlCharacters { .. } => String::from(
            "Il testo contiene caratteri non ammessi (per esempio un ritorno a \
             capo). Rimuoverli e riprovare.",
        ),
        DomainError::BidirectionalOverride { .. } => String::from(
            "Il testo contiene caratteri invisibili che ne alterano l'ordine di \
             lettura e non sono ammessi. Reinserirlo digitandolo e riprovare.",
        ),
        DomainError::InvalidUrl { .. } => {
            String::from("L'indirizzo web non è valido: deve iniziare con http:// o https://.")
        }
        // La ragione è una costante scritta per chi compila il dizionario
        // (DICT-CODES-01, ADR-0170); per le espressioni lo è dal collaudo
        // (COLLAUDO-FIX-01, CU01-003, DEC-510), che le trovava dette «problema
        // tecnico».
        DomainError::InvalidNumericCode { reason } | DomainError::InvalidExpression { reason } => {
            format!("Il termine non è stato aggiunto: {reason}. Correggere e riprovare.")
        }
        _ => {
            tracing::warn!(dettaglio = %error, "problema tecnico mostrato all'operatore");
            String::from(TECHNICAL_PROBLEM)
        }
    }
}

/// Il messaggio di ripiego per un guasto che l'operatore non può correggere.
///
/// Dice che il dettaglio è nel registro applicativo: **chi lo restituisce lo
/// registra nello stesso punto**, perché una promessa che dipende dal
/// chiamante è una promessa che un chiamante dimentica (SIM3-02).
const TECHNICAL_PROBLEM: &str = "Si è verificato un problema tecnico. Il dettaglio è stato \
                                 registrato nel registro applicativo.";

/// Nome leggibile di un campo riservato, per i messaggi di
/// [`TelegramError::InvalidSecret`].
///
/// Il campo tecnico (`api_id`, `numero_di_telefono`...) è pensato per
/// l'audit, non per lo schermo: qui si traduce nell'etichetta che l'operatore
/// vede accanto al campo nella schermata Account.
fn friendly_secret_field_name(field: &str) -> &str {
    match field {
        "api_id" => "API ID",
        "api_hash" => "API hash",
        "numero_di_telefono" => "numero di telefono",
        "codice_di_accesso" => "codice di accesso",
        "password_2fa" => "password della verifica in due passaggi",
        other => other,
    }
}

/// Traduce un errore del connettore in un errore di servizio, distinguendo i
/// casi che hanno un significato per l'operatore.
pub(crate) fn from_connector(error: TelegramError) -> ServiceError {
    match error {
        TelegramError::CodeRejected => ServiceError::CodeRejected,
        TelegramError::PasswordRejected => ServiceError::PasswordRejected,
        TelegramError::SessionRevoked => ServiceError::SessionRevoked,
        TelegramError::SessionUnavailable { reason } => ServiceError::SessionUnavailable {
            reason: String::from(reason),
        },
        TelegramError::NetworkUnavailable => ServiceError::NetworkUnavailable,
        TelegramError::Timeout { .. } => ServiceError::TimedOut,
        other => ServiceError::Connector(other),
    }
}

/// Traduce un errore della persistenza in un errore di servizio.
///
/// Solo i casi che l'operatore può correggere da sé meritano un messaggio
/// proprio. Tutto il resto resta [`ServiceError::Storage`]: promuovere ogni
/// errore del motore a messaggio dedicato produrrebbe testi che nessuno sa
/// come usare.
pub(crate) fn from_storage(error: StorageError) -> ServiceError {
    match error {
        StorageError::DuplicateDictionary => ServiceError::DictionaryNameAlreadyUsed,
        StorageError::DuplicateTerm => ServiceError::TermAlreadyInVersion,
        StorageError::BuiltInDictionaryIsReadOnly => ServiceError::BuiltInDictionaryIsReadOnly,
        StorageError::PublishedVersionIsImmutable => ServiceError::PublishedVersionIsImmutable,
        other => ServiceError::Storage(other),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::DomainError;
    use lisi_telegram::TelegramError;

    use super::{ServiceError, from_connector};

    #[test]
    fn every_error_offers_a_non_empty_operator_message() {
        for error in [
            ServiceError::CommandNotAllowed {
                command: "x",
                state: "y",
            },
            ServiceError::CodeRejected,
            ServiceError::PasswordRejected,
            ServiceError::SessionRevoked,
            ServiceError::SessionUnavailable {
                reason: String::from("prova"),
            },
            ServiceError::AccountInUse,
            ServiceError::ActiveAccountLimit { limit: 3 },
            ServiceError::NetworkUnavailable,
            ServiceError::TimedOut,
            ServiceError::Cancelled,
            ServiceError::SourceNotAccessible,
            ServiceError::SourceAlreadyConfigured,
            ServiceError::DictionaryNameAlreadyUsed,
            ServiceError::BuiltInDictionaryIsReadOnly,
            ServiceError::DictionaryHasNoPublishedVersion,
            ServiceError::EmptyDictionaryVersion,
            ServiceError::PublishedVersionIsImmutable,
            ServiceError::DictionaryNotSelectable {
                name: String::from("Prova"),
            },
            ServiceError::EmptyDictionarySelection,
            ServiceError::LinkNotOpened {
                reason: "schema non ammesso",
            },
            ServiceError::ProtectionNotGuaranteed {
                what: "La copia di sicurezza NON è stata scritta",
                reason: String::from("Windows non ha accettato i nuovi permessi"),
            },
            ServiceError::SealedCopyRefused {
                reason: String::from("la frase non apre la copia"),
            },
            ServiceError::TaxiiDestinationMissing,
            ServiceError::TaxiiCredentialsMissing,
            ServiceError::TaxiiDestinationRefused {
                reason: String::from("prova"),
            },
            ServiceError::TaxiiPasswordRefused {
                reason: String::from("prova"),
            },
            ServiceError::TaxiiInExercise,
            ServiceError::SigningCertificateMissing,
            ServiceError::SigningCertificateRefused {
                reason: String::from("prova"),
            },
            ServiceError::SigningInExercise,
            ServiceError::BackupScheduleRefused {
                reason: String::from("prova"),
            },
            ServiceError::OverviewRefused {
                reason: String::from("prova"),
            },
            ServiceError::ConsultationLogRefused {
                reason: String::from("prova"),
            },
            ServiceError::SnapshotDownloadRefused {
                reason: String::from("prova"),
            },
            ServiceError::UpdateSignerRefused {
                reason: String::from("prova"),
            },
            ServiceError::Connector(TelegramError::Closed),
        ] {
            assert!(!error.operator_message().is_empty());
            assert!(!error.kind().is_empty());
        }
    }

    #[test]
    fn every_dictionary_message_tells_the_operator_what_to_do_next() {
        // Un messaggio che si limita a constatare il rifiuto lascia l'operatore
        // fermo: ciascuno di questi deve nominare la via d'uscita.
        let cases = [
            (ServiceError::BuiltInDictionaryIsReadOnly, "Duplica"),
            (ServiceError::DictionaryHasNoPublishedVersion, "pubblicare"),
            (ServiceError::EmptyDictionaryVersion, "Aggiungere"),
            (ServiceError::PublishedVersionIsImmutable, "Nuova versione"),
        ];

        for (error, expected) in cases {
            let message = error.operator_message();
            assert!(
                message.contains(expected),
                "il messaggio '{message}' non indica la via d'uscita '{expected}'"
            );
        }
    }

    #[test]
    fn only_the_storage_errors_the_operator_can_act_on_get_their_own_message() {
        use lisi_storage::StorageError;

        use super::from_storage;

        assert!(matches!(
            from_storage(StorageError::DuplicateDictionary),
            ServiceError::DictionaryNameAlreadyUsed
        ));
        assert!(matches!(
            from_storage(StorageError::BuiltInDictionaryIsReadOnly),
            ServiceError::BuiltInDictionaryIsReadOnly
        ));
        assert!(matches!(
            from_storage(StorageError::PublishedVersionIsImmutable),
            ServiceError::PublishedVersionIsImmutable
        ));
        assert!(matches!(
            from_storage(StorageError::AuditIsAppendOnly),
            ServiceError::Storage(StorageError::AuditIsAppendOnly)
        ));
    }

    #[test]
    fn the_operator_message_never_contains_technical_jargon() {
        // Un operatore non tecnico non deve leggere nomi di stati interni.
        let message = ServiceError::CommandNotAllowed {
            command: "submit_code",
            state: "waiting_for_phone_number",
        }
        .operator_message();

        assert!(!message.contains("submit_code"));
        assert!(!message.contains("waiting_for_phone_number"));
    }

    #[test]
    fn a_rejected_code_is_correctable_while_a_revoked_session_is_not() {
        assert!(ServiceError::CodeRejected.is_correctable_by_operator());
        assert!(ServiceError::PasswordRejected.is_correctable_by_operator());
        assert!(!ServiceError::SessionRevoked.is_correctable_by_operator());
        assert!(!ServiceError::NetworkUnavailable.is_correctable_by_operator());
    }

    #[test]
    fn connector_errors_that_matter_to_the_operator_are_translated() {
        assert!(matches!(
            from_connector(TelegramError::CodeRejected),
            ServiceError::CodeRejected
        ));
        assert!(matches!(
            from_connector(TelegramError::PasswordRejected),
            ServiceError::PasswordRejected
        ));
        assert!(matches!(
            from_connector(TelegramError::SessionRevoked),
            ServiceError::SessionRevoked
        ));
        assert!(matches!(
            from_connector(TelegramError::NetworkUnavailable),
            ServiceError::NetworkUnavailable
        ));
        assert!(matches!(
            from_connector(TelegramError::Timeout { millis: 10 }),
            ServiceError::TimedOut
        ));
    }

    #[test]
    fn an_unclassified_connector_error_keeps_its_detail() {
        assert!(matches!(
            from_connector(TelegramError::Closed),
            ServiceError::Connector(TelegramError::Closed)
        ));
    }

    #[test]
    fn no_operator_message_leaks_a_secret_shaped_value() {
        // I messaggi sono costanti: nessuno interpola un valore ricevuto.
        let message = ServiceError::CodeRejected.operator_message();
        assert!(!message.contains("12345"));
    }

    /// Un campo obbligatorio lasciato vuoto (per esempio il nome di un
    /// profilo API o di un account, in `crates/lisi-app/src/account.rs`) deve
    /// dire all'operatore che cosa correggere, non nascondersi dietro il
    /// messaggio tecnico generico riservato ai guasti di connettore e
    /// persistenza: era il difetto osservato nel collaudo manuale M3B.1d.
    #[test]
    fn an_empty_required_field_gets_a_specific_message_instead_of_the_generic_technical_one() {
        let error = ServiceError::Domain(DomainError::Empty {
            field: "nome_visualizzato",
        });
        let message = error.operator_message();

        assert!(
            message.contains("vuoto"),
            "il messaggio '{message}' non dice all'operatore che il campo era vuoto"
        );
        assert!(
            !message.contains("problema tecnico"),
            "il messaggio '{message}' non deve essere il generico messaggio tecnico"
        );
    }

    #[test]
    fn a_too_long_field_reports_the_admitted_length() {
        let error = ServiceError::Domain(DomainError::TooLong {
            field: "nome_visualizzato",
            max: 256,
            actual: 300,
        });
        let message = error.operator_message();

        assert!(
            message.contains("256"),
            "il messaggio '{message}' non riporta il limite"
        );
    }

    /// Un API ID non numerico digitato nella schermata Account (per esempio
    /// `abc`) mostrava «i dati di accesso non sono leggibili, usare Ripristina
    /// accesso»: un messaggio estraneo al problema reale e che rimanda a
    /// un'azione che in quella schermata non esiste. Era il secondo difetto
    /// osservato nel collaudo manuale M3B.1d, della stessa natura del
    /// precedente: il messaggio deve nominare il campo e la ragione.
    #[test]
    fn an_invalid_secret_field_names_the_field_and_the_reason_instead_of_the_session_message() {
        let error = ServiceError::Connector(TelegramError::InvalidSecret {
            field: "api_id",
            reason: "deve essere un numero intero",
        });
        let message = error.operator_message();

        assert!(
            message.contains("API ID"),
            "il messaggio '{message}' non nomina il campo"
        );
        assert!(
            message.contains("numero intero"),
            "il messaggio '{message}' non riporta la ragione"
        );
        assert!(!message.contains("Ripristina accesso"));
    }

    #[test]
    fn domain_errors_the_operator_cannot_act_on_keep_the_generic_technical_message() {
        // L'orologio di sistema non e' un campo che l'operatore ha digitato:
        // per questi casi il messaggio tecnico generico resta corretto.
        let error = ServiceError::Domain(DomainError::ClockBeforeEpoch);
        assert!(error.operator_message().contains("problema tecnico"));
    }
}

//! Errori dell'integrazione con il sistema.

/// Esito di un'operazione di piattaforma.
pub type PlatformResult<T> = Result<T, PlatformError>;

/// Errore dell'integrazione con il sistema.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// L'URL non ha uno schema web (`http`/`https`).
    ///
    /// È la rete di sicurezza del crate: anche un chiamante diretto non può far
    /// aprire `file://`, `javascript:` o un handler di protocollo arbitrario.
    #[error("schema non ammesso: solo http e https")]
    UnsupportedScheme,

    /// L'URL contiene spazi o caratteri di controllo.
    ///
    /// Parte della stessa rete di sicurezza: l'assenza di spazi è ciò che
    /// neutralizza l'iniezione di argomenti verso l'handler del browser. Non si
    /// riecheggia l'URL, solo il fatto.
    #[error("indirizzo malformato: contiene spazi o caratteri di controllo")]
    MalformedUrl,

    /// L'apertura non è riuscita, con il codice restituito dal sistema.
    ///
    /// Il codice **non** riporta l'URL: un valore ostile non deve scegliere il
    /// testo di un messaggio.
    #[error("apertura non riuscita (codice {code})")]
    LaunchFailed {
        /// Codice restituito dall'API di sistema.
        code: isize,
    },

    /// Il gestore dei servizi o le sessioni di Windows non hanno risposto
    /// (ADR-0203), con il codice del sistema.
    #[error("servizio in background non raggiungibile (codice {code})")]
    BackgroundService {
        /// Codice restituito dall'API di sistema.
        code: u32,
    },

    /// L'operazione non è supportata su questa piattaforma.
    #[error("operazione non supportata su questa piattaforma")]
    Unsupported,

    /// Il sistema ha rifiutato la richiesta sullo stato di sospensione.
    ///
    /// **Non è fatale**: significa che la postazione potrà sospendersi, non che
    /// il monitoraggio sia compromesso. Al risveglio riprende, e il recupero
    /// della cronologia colma il vuoto.
    #[error("il sistema non ha accettato la richiesta di restare sveglio")]
    WakefulnessRefused,

    /// Nessuna applicazione è associata allo schema richiesto.
    ///
    /// **Non è un guasto**: è la risposta del sistema quando il programma non è
    /// installato, e permette a chi chiama di ripiegare su un'altra strada
    /// invece di riportare un errore. È la differenza fra «apri Telegram se
    /// c'è, altrimenti il browser» e un clic che non produce nulla.
    #[error("nessuna applicazione associata")]
    NoAssociatedApplication,

    /// La finestra non è disponibile: l'handle ricevuto non è valido.
    ///
    /// Il messaggio **non** riporta il valore ricevuto: non c'è nulla di utile
    /// da dire su un handle nullo, e un messaggio che ripete il proprio input è
    /// il modo in cui un dato non fidato finisce sotto gli occhi di qualcuno.
    #[error("finestra non disponibile")]
    WindowUnavailable,

    /// Il gestore delle finestre ha rifiutato l'attributo richiesto.
    ///
    /// È il caso di un sistema che non conosce l'attributo — su Windows la
    /// modalità scura della barra del titolo esiste dalla versione 1809. **Non
    /// è fatale**: è un difetto estetico, e l'applicazione funziona comunque.
    #[error("il gestore delle finestre ha rifiutato l'attributo")]
    WindowAttributeRefused,

    /// Il registro non ha accettato la lettura o la scrittura dell'avvio
    /// automatico.
    ///
    /// **Non è fatale**: l'applicazione funziona, e semplicemente non si
    /// avvierà da sola. Il codice è quello restituito dal sistema; zero indica
    /// che l'ostacolo è a monte della chiamata — il percorso dell'eseguibile
    /// non è determinabile — e non un rifiuto di Windows.
    #[error("avvio automatico non configurabile (codice {code})")]
    AutostartUnavailable {
        /// Codice restituito dal registro, oppure zero.
        code: i64,
    },

    /// Windows ha rifiutato la dichiarazione di identita' dell'applicazione.
    ///
    /// **Non e' fatale**: l'applicazione funziona, e semplicemente gli avvisi
    /// nativi non le vengono attribuiti. Il codice e' l'HRESULT restituito.
    #[error("identita' dell'applicazione non dichiarabile (codice {code})")]
    AppIdentityRefused {
        /// HRESULT restituito dal sistema.
        code: i32,
    },

    /// Windows non ha mostrato il riquadro di avviso.
    ///
    /// **Non è fatale, ed è il caso normale fuori dall'installazione.** Windows
    /// mostra un avviso solo a un'applicazione che ha un collegamento nel menu
    /// Start con il proprio `AppUserModelID`: l'eseguibile avviato da una
    /// cartella di sviluppo non ce l'ha, e il sistema rifiuta. Chi chiama deve
    /// ripiegare — la decisione di notificare è già stata presa e registrata, e
    /// perderla perché il riquadro non compare sarebbe perdere il fatto invece
    /// della sua resa.
    ///
    /// Il messaggio **non** riporta titolo né corpo dell'avviso: contengono un
    /// estratto di materiale acquisito, e un errore non è il posto dove farlo
    /// comparire.
    #[error("il sistema non ha mostrato l'avviso (codice {code})")]
    ToastRefused {
        /// HRESULT restituito dal sistema.
        code: i32,
    },

    /// Il percorso da aprire non è una cartella esistente con un percorso
    /// assoluto (ADR-0137).
    ///
    /// È la rete di sicurezza di `folder::open`: aprire con il verbo `open` un
    /// file eseguibile lo **avvierebbe**. Il messaggio non riporta il
    /// percorso, che contiene il nome dell'account Windows.
    #[error("il percorso non e' una cartella esistente")]
    NotAFolder,
}

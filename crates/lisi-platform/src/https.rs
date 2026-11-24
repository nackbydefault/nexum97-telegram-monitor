// DECIMO modulo del crate autorizzato a contenere `unsafe`, dopo `browser`,
// `window_chrome`, `wakefulness`, `autostart`, `title_bar`, `signature`,
// `disk_space`, `app_identity` e `tray`. Vedere ADR-0003 per la regola e
// ADR-0067 per la decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Una sola porta verso la rete, e va in un posto solo.
//!
//! # Che cosa è successo il giorno in cui questo modulo è nato
//!
//! Fino a UPDATE-02 **il prodotto non poteva parlare con nessuno**. Non era una
//! regola: era un'assenza di capacità — nel grafo delle dipendenze non c'erano
//! client HTTP, né pile TLS in Rust, né runtime asincroni. Questo modulo apre
//! quella porta, e ADR-0067 decide com'è fatta.
//!
//! # Perché la rete è quella di Windows e non una libreria Rust
//!
//! **L'archivio dei certificati.** WinHTTP verifica la catena TLS con quello di
//! Windows, lo stesso su cui poggia Authenticode (ADR-0037). Una pila TLS in
//! Rust porterebbe **un secondo insieme di radici di fiducia**, che nessun
//! amministratore dell'ufficio governa e che diverge dal sistema senza che
//! nessuno se ne accorga.
//!
//! **Il proxy dell'ufficio.** Ci sono uffici le cui postazioni escono solo
//! attraverso ciò che è stato autorizzato (ADR-0040). WinHTTP conosce quella
//! configurazione perché è quella del sistema; una libreria Rust, lì, non arriva
//! da nessuna parte — e il prodotto direbbe «il canale non risponde» quando la
//! verità è «questa postazione esce solo dal proxy».
//!
//! **La superficie.** Un client HTTPS in Rust porta decine di crate transitive
//! per fare **una richiesta GET**.
//!
//! # Il solo invio: TAXII (ADR-0179)
//!
//! Da TAXII-01 la porta sa anche **mandare**, verso una destinazione sola: una
//! collezione TAXII 2.1 scritta dall'amministratore. Un `POST` con il tipo
//! TAXII, un corpo composto dal programma ed entro un limite chiuso,
//! l'autenticazione Basic composta qui; nessun'altra intestazione, nessun altro
//! verbo. Le altre regole restano quelle delle letture.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non decide **se** scaricare o mandare: si muove quando qualcuno preme. Non sa che cosa
//! sta scaricando: restituisce byte, e chi li ha chiesti li tratta come **dato
//! non fidato** (ADR-0040). Non ha idea dell'esistenza di Telegram, dei
//! contenuti monitorati, o dell'archivio.
//!
//! # Le invarianti dell'FFI
//!
//! 1. **Tre maniglie, chiuse in ordine inverso.** Sessione, connessione e
//!    richiesta sono maniglie di WinHTTP. Ciascuna è chiusa da `Maniglia`, che
//!    le possiede: un ritorno anticipato non ne perde nessuna, e chiuderle in
//!    ordine inverso è ciò che WinHTTP si aspetta.
//! 2. **Ogni stringa passata a WinHTTP è UTF-16 terminata da zero, e vive più
//!    a lungo della chiamata.** I vettori che le contengono sono variabili
//!    locali dichiarate **prima** della chiamata che le usa, e nessuna di esse
//!    viene spostata mentre WinHTTP la legge.
//! 3. **`URL_COMPONENTS` non possiede le stringhe che indica.** Con i campi
//!    `lpsz*` a zero e i campi `dw*Length` a `u32::MAX`, `WinHttpCrackUrl`
//!    riempie i puntatori **dentro** l'URL passato, che quindi deve restare vivo
//!    e immobile finché quei puntatori vengono letti. Il vettore dell'URL è
//!    dichiarato all'inizio della funzione e non viene mai riassegnato.
//! 4. **Il corpo si legge a blocchi, con il limite applicato PRIMA di
//!    allocare.** `WinHttpReadData` scrive al massimo quanto gli si dice, e il
//!    blocco è un buffer di dimensione fissa sullo stack del vettore: un corpo
//!    enorme non può far crescere la memoria oltre il limite più un blocco.
//! 5. **Nessun puntatore esce da questo modulo.** Ciò che esce sono byte
//!    copiati e un esito; nessuna maniglia, nessun puntatore, nessuna struttura
//!    di Windows attraversa il confine del modulo.
//! 6. **`WinHttpSetOption` riceve un puntatore a un `u32` locale** — la maschera
//!    delle funzioni disabilitate, e i protocolli ammessi — e WinHTTP lo copia
//!    durante la chiamata: la variabile non deve sopravvivere alla chiamata, ma
//!    deve esistere **durante** di essa, e per questo è una variabile e non un
//!    letterale.
//! 7. **`autorita` legge l'indirizzo senza WinHTTP**, perché il rifiuto delle
//!    credenziali deve avvenire **prima** che qualunque maniglia esista: non
//!    tocca memoria non sua e lavora su `&str`.

/// Il limite del corpo scaricabile, in byte.
///
/// È lo stesso limite che il prodotto applica a un manifesto letto da file: un
/// manifesto è qualche riga di testo, e ciò che arriva dalla rete non ha diritto
/// a più spazio di ciò che arriva da un file scelto a mano.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Quanto si aspetta ciascuna fase, in millisecondi.
///
/// Un server che accetta la connessione e poi tace è il modo più economico per
/// bloccare un programma. Non deve poterlo fare.
const TIMEOUT_MS: i32 = 15_000;

/// Il tetto del prodotto per un artefatto, in byte.
///
/// # Perché un tetto oltre a quello dichiarato dal manifesto
///
/// La dimensione dichiarata viene da un documento **non fidato**: da sola non è
/// un limite, è un'affermazione. Il tetto è più grande di qualunque installatore
/// che questo prodotto abbia prodotto, e più piccolo di ciò che riempie un disco
/// d'ufficio (ADR-0068).
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

/// Il limite di un dizionario scaricato, in byte (DICT-NET-01, ADR-0178).
///
/// È il limite di un dizionario importato da file: ciò che arriva dalla rete
/// non ha più spazio di ciò che arriva da un file scelto a mano. Questo crate
/// non conosce il dominio, e una prova dei servizi verifica che i due numeri
/// restino uguali.
pub const MAX_DICTIONARY_BYTES: usize = 10 * 1024 * 1024;

/// Il limite di un catalogo pubblico scaricato, in byte (SNAP-NET-01,
/// ADR-0186): il catalogo KEV di CISA, che oggi pesa meno di due megabyte.
pub const MAX_CATALOGUE_BYTES: usize = 16 * 1024 * 1024;

/// Il limite di una risposta RDAP, in byte (WHOIS-01, ADR-0205, decisione 3):
/// chi ha registrato un nome o un indirizzo, in JSON. Qualche decina di KiB
/// anche per i registri più loquaci.
pub const MAX_REGISTRATION_BYTES: usize = 256 * 1024;

/// Quanto può essere grande un documento tenuto in memoria.
///
/// # Perché un insieme chiuso e non un numero
///
/// Un parametro numerico sarebbe il modo in cui un giorno qualcuno scarica
/// qualunque cosa (ADR-0067). I limiti sono questi, ciascuno con la sua
/// ragione, e un limite nuovo è una decisione che passa da qui (ADR-0178,
/// decisione 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLimit {
    /// Un documento di qualche riga: il manifesto degli aggiornamenti, la
    /// firma separata di un dizionario. [`MAX_BODY_BYTES`].
    Small,
    /// Un dizionario. [`MAX_DICTIONARY_BYTES`].
    Dictionary,
    /// Un catalogo pubblico, come quello KEV o gli elenchi RDAP di IANA.
    /// [`MAX_CATALOGUE_BYTES`].
    Catalogue,
    /// La risposta di un registro RDAP. [`MAX_REGISTRATION_BYTES`].
    Registration,
}

impl BodyLimit {
    /// Il limite, in byte.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Small => MAX_BODY_BYTES,
            Self::Dictionary => MAX_DICTIONARY_BYTES,
            Self::Catalogue => MAX_CATALOGUE_BYTES,
            Self::Registration => MAX_REGISTRATION_BYTES,
        }
    }
}

/// La lunghezza massima ammessa per l'indirizzo.
///
/// È lo stesso limite che il prodotto applica all'indirizzo dell'artefatto
/// dentro un manifesto: un indirizzo più lungo di così non è un indirizzo, è un
/// tentativo.
pub const MAX_URL_CHARS: usize = 2048;

/// Il limite del corpo mandato a un server TAXII, in byte (TAXII-01,
/// ADR-0179, decisione 6).
///
/// Un pacchetto STIX di un monitoraggio sta in poche decine di KiB; il limite
/// c'è perché un corpo senza limite è un corpo che qualcuno un giorno gonfia.
pub const MAX_TAXII_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Il tipo dei documenti TAXII 2.1, in andata e in risposta.
pub const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";

/// Nome e parola d'ordine per l'autenticazione HTTP Basic di un server TAXII.
///
/// La porta compone da sé l'intestazione: chi chiama non scrive intestazioni,
/// perché un'intestazione libera sarebbe il modo in cui un giorno ne esce
/// un'altra (ADR-0179, decisione 6).
#[derive(Clone, Copy)]
pub struct BasicCredentials<'a> {
    /// Il nome utente. Non può contenere i due punti (RFC 7617).
    pub user: &'a str,
    /// La parola d'ordine.
    pub password: &'a str,
}

impl core::fmt::Debug for BasicCredentials<'_> {
    // La parola d'ordine non si stampa, nemmeno in una prova che fallisce.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BasicCredentials")
            .field("user", &self.user)
            .field("password", &"…")
            .finish()
    }
}

/// Che cosa è successo mandando oggetti a un server TAXII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    /// Il server ha risposto `202`: questa è la sua risorsa di stato, **dato
    /// non fidato**, entro [`MAX_BODY_BYTES`].
    Accepted(Vec<u8>),
    /// Non è arrivato, o non è stato accettato, e il motivo è questo.
    Refused(FetchRefusal),
}

/// Che cosa è successo chiedendo un documento alla rete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// Il documento è arrivato per intero.
    Body(Vec<u8>),
    /// Non è arrivato, e il motivo è questo.
    Refused(FetchRefusal),
}

/// Che cosa è successo scaricando un artefatto su disco.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Downloaded {
    /// È sceso per intero, ed è esattamente grande quanto era dichiarato.
    Saved {
        /// Byte scritti.
        bytes: u64,
    },
    /// Non è sceso, e il motivo è questo.
    ///
    /// **Ciò che era stato scritto è stato tolto**: un file parziale in una
    /// cartella è un file che qualcuno può scambiare per completo.
    Refused(FetchRefusal),
}

/// Perché un documento non è arrivato.
///
/// I motivi sono distinti apposta: appiattirli in «non riuscito» toglierebbe a
/// chi indaga l'unica cosa utile. Un `404` e un `500` non sono la stessa cosa, e
/// un reindirizzamento non è un'origine irraggiungibile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchRefusal {
    /// L'indirizzo non comincia con `https://`.
    NotHttps,
    /// L'indirizzo è troppo lungo, o non si legge.
    UnusableUrl,
    /// Il server ha risposto con un reindirizzamento.
    ///
    /// **Non si segue.** Un `3xx` è un'altra destinazione decisa da qualcun
    /// altro, e la destinazione la decide la configurazione (ADR-0067).
    Redirected {
        /// Lo stato restituito.
        status: u32,
    },
    /// Il server ha risposto con uno stato diverso da `200`.
    Status {
        /// Lo stato restituito.
        status: u32,
    },
    /// Il corpo supera il limite.
    TooLarge {
        /// Il limite, in byte.
        max: usize,
    },
    /// La richiesta non è arrivata a destinazione.
    ///
    /// Porta con sé il codice di Windows, perché le ragioni sono molte — nome
    /// che non si risolve, connessione rifiutata, TLS non attendibile, proxy che
    /// non autorizza — e appiattirle in una parola sola non aiuta nessuno.
    Unreachable {
        /// Il codice restituito da Windows.
        code: u32,
    },
    /// Il server ha mandato più byte di quanti il manifesto ne dichiarasse.
    ///
    /// **Sta mentendo su uno dei due**, e la differenza non si accomoda: o il
    /// documento dichiara il falso, o il server serve qualcos'altro. In
    /// entrambi i casi quei byte non sono l'artefatto descritto.
    Oversized {
        /// I byte che il manifesto dichiarava.
        declared: u64,
    },
    /// Il server ha chiuso prima di mandare quanto dichiarato.
    ///
    /// Un file incompleto **non si tiene** e non si riprende: un file assemblato
    /// da due risposte è un file di cui nessuno può dire che le due metà
    /// appartengano allo stesso artefatto (ADR-0068).
    Incomplete {
        /// I byte arrivati.
        received: u64,
        /// I byte che il manifesto dichiarava.
        declared: u64,
    },
    /// Il file non si è potuto scrivere su disco.
    ///
    /// Il motivo è testo del sistema, non del server: nulla di ciò che è
    /// arrivato dalla rete entra in questa frase.
    NotWritten {
        /// Che cosa il sistema ha detto.
        reason: String,
    },
    /// Questo binario non gira su Windows.
    ///
    /// Non è un errore dell'utente: è una costruzione fuori dal bersaglio
    /// dichiarato, e lo dice invece di fingere un guasto di rete.
    NotWindows,
    /// Il corpo da mandare è vuoto o supera [`MAX_TAXII_BODY_BYTES`].
    UnusableBody,
    /// Nome o parola d'ordine non si possono mandare: vuoti, con caratteri di
    /// controllo, o un nome con i due punti.
    UnusableCredentials,
}

impl core::fmt::Display for FetchRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotHttps => write!(
                formatter,
                "l'indirizzo non comincia con «https://»: in chiaro, chi controlla \
                 la rete può sostituire il documento"
            ),
            Self::UnusableUrl => write!(formatter, "l'indirizzo non è utilizzabile"),
            Self::Redirected { status } => write!(
                formatter,
                "l'origine ha risposto {status}, cioè ha rimandato altrove: il \
                 rimando non si segue, perché la destinazione la decide la \
                 configurazione e non chi risponde"
            ),
            Self::Status { status } => {
                write!(formatter, "l'origine ha risposto {status}")
            }
            Self::TooLarge { max } => write!(
                formatter,
                "la risposta supera {max} byte e non è stata letta oltre il limite"
            ),
            Self::Unreachable { code } => write!(
                formatter,
                "l'origine non è stata raggiunta (codice di Windows {code})"
            ),
            Self::Oversized { declared } => write!(
                formatter,
                "la risposta supera i {declared} byte che il documento dichiarava: \
                 o il documento dichiara il falso, o il computer che risponde manda qualcos'altro"
            ),
            Self::Incomplete { received, declared } => write!(
                formatter,
                "sono arrivati {received} byte dei {declared} dichiarati: quello che \
                 era sceso è stato tolto, perché un file incompleto non si tiene \
                 e non si riprende"
            ),
            Self::NotWritten { reason } => {
                write!(formatter, "il file non si è potuto scrivere: {reason}")
            }
            Self::NotWindows => write!(
                formatter,
                "questa costruzione non gira su Windows e non ha una rete di sistema"
            ),
            Self::UnusableBody => write!(
                formatter,
                "il pacchetto da mandare è vuoto o supera {MAX_TAXII_BODY_BYTES} byte"
            ),
            Self::UnusableCredentials => write!(
                formatter,
                "il nome o la parola d'ordine mancano, contengono un a capo o segni \
                 speciali, o il nome ha i due punti"
            ),
        }
    }
}

/// Scarica un documento in `GET` da un indirizzo `https`.
///
/// # Che cosa non è negoziabile
///
/// Solo `https`, solo `GET`, nessun corpo nella richiesta, nessun
/// reindirizzamento seguito, nessun cookie, nessuna autenticazione automatica,
/// un limite applicato **durante** la lettura e un timeout su ogni fase.
/// Nessuna di queste è un parametro: sono ADR-0067, e un parametro sarebbe il
/// modo in cui un giorno smetterebbero di valere.
#[must_use]
pub fn fetch(url: &str) -> Fetched {
    fetch_within(url, BodyLimit::Small)
}

/// Come [`fetch`], con uno dei limiti chiusi di [`BodyLimit`].
///
/// Tutto il resto è uguale e non negoziabile: lo schema, il `GET`, i rimandi
/// non seguiti, i tempi. Cambia soltanto quanto si tiene in memoria.
#[must_use]
pub fn fetch_within(url: &str, limit: BodyLimit) -> Fetched {
    if let Some(motivo) = indirizzo_inaccettabile(url) {
        return Fetched::Refused(motivo);
    }

    fetch_impl(url, limit.bytes())
}

/// Scarica un artefatto su disco, e si ferma lì.
///
/// # Che cosa questa funzione NON fa
///
/// Non verifica nulla: non l'impronta, non la firma, non il contenuto. Ciò che
/// scrive sono **byte arrivati dalla rete**, e chi li ha chiesti lo sa
/// (ADR-0068). La verifica è UPDATE-04, e finché non esiste quel file non va
/// eseguito da nessuno.
///
/// # Il limite è quello dichiarato, e c'è anche un tetto
///
/// `declared_bytes` viene dal manifesto, che è dato non fidato: da solo non è un
/// limite, è un'affermazione. Vale insieme a [`MAX_ARTIFACT_BYTES`], e chi chiama
/// deve aver già rifiutato una dimensione oltre il tetto **prima** di arrivare
/// qui — questa funzione lo ricontrolla comunque, perché un controllo che sta in
/// un posto solo è un controllo che un giorno qualcuno aggira.
///
/// Un server che manda **più** byte di quanti dichiarati sta mentendo su uno dei
/// due; uno che ne manda **meno** produce un file incompleto. In entrambi i casi
/// ciò che era stato scritto **viene tolto**.
#[must_use]
pub fn fetch_to_file(url: &str, destination: &std::path::Path, declared_bytes: u64) -> Downloaded {
    if let Some(motivo) = indirizzo_inaccettabile(url) {
        return Downloaded::Refused(motivo);
    }
    if declared_bytes == 0 || declared_bytes > MAX_ARTIFACT_BYTES {
        return Downloaded::Refused(FetchRefusal::TooLarge {
            max: usize::try_from(MAX_ARTIFACT_BYTES).unwrap_or(usize::MAX),
        });
    }

    fetch_to_file_impl(url, destination, declared_bytes)
}

/// Manda oggetti a una collezione TAXII 2.1, e legge la risposta di stato.
///
/// # Il solo invio della porta (ADR-0179, decisione 6)
///
/// `POST` con il tipo TAXII e un corpo che il programma ha composto, entro
/// [`MAX_TAXII_BODY_BYTES`]; l'intestazione `Authorization: Basic` composta qui
/// da nome e parola d'ordine; nessun'altra intestazione. Restano le regole di
/// [`fetch`]: soltanto `https`, nessun rimando seguito, nessun cookie, nessuna
/// autenticazione automatica di Windows, i tempi su ogni fase. Si accetta
/// soltanto `202`, e la risposta si legge entro [`MAX_BODY_BYTES`].
///
/// Questa funzione non sa che cosa manda: riceve byte, e a decidere che sono
/// soltanto gli oggetti di un'esportazione STIX è chi la chiama.
#[must_use]
pub fn send_taxii(url: &str, envelope: &[u8], credentials: &BasicCredentials<'_>) -> Sent {
    if let Some(motivo) = indirizzo_inaccettabile(url) {
        return Sent::Refused(motivo);
    }
    if envelope.is_empty() || envelope.len() > MAX_TAXII_BODY_BYTES {
        return Sent::Refused(FetchRefusal::UnusableBody);
    }
    let Some(intestazioni) = taxii_headers(credentials) else {
        return Sent::Refused(FetchRefusal::UnusableCredentials);
    };

    match send_impl(url, envelope, &intestazioni) {
        Fetched::Body(stato) => Sent::Accepted(stato),
        Fetched::Refused(motivo) => Sent::Refused(motivo),
    }
}

/// Le intestazioni di un invio TAXII, o `None` se le credenziali non si
/// possono mandare.
///
/// Tre righe, sempre le stesse: il tipo accettato, il tipo mandato,
/// l'autenticazione. Un carattere di controllo in un nome o in una parola
/// d'ordine aprirebbe una riga nuova nell'intestazione, cioè un'intestazione
/// scelta da chi ha scritto il nome: si rifiuta.
fn taxii_headers(credentials: &BasicCredentials<'_>) -> Option<String> {
    let BasicCredentials { user, password } = *credentials;
    if user.is_empty()
        || password.is_empty()
        || user.contains(':')
        || user.chars().any(char::is_control)
        || password.chars().any(char::is_control)
    {
        return None;
    }
    let coppia = base64(format!("{user}:{password}").as_bytes());
    Some(format!(
        "Accept: {TAXII_MEDIA_TYPE}\r\nContent-Type: {TAXII_MEDIA_TYPE}\r\nAuthorization: Basic {coppia}"
    ))
}

/// Base64 standard con riempimento (RFC 4648, §4), per l'autenticazione Basic.
///
/// Non è crittografia: è il modo in cui RFC 7617 vuole scritti nome e parola
/// d'ordine. Il segreto lo protegge TLS.
fn base64(byte: &[u8]) -> String {
    const ALFABETO: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut uscita = String::with_capacity(byte.len().div_ceil(3) * 4);
    for gruppo in byte.chunks(3) {
        let primo = u32::from(gruppo[0]);
        let secondo = gruppo.get(1).copied().map_or(0, u32::from);
        let terzo = gruppo.get(2).copied().map_or(0, u32::from);
        let tre = (primo << 16) | (secondo << 8) | terzo;
        let cifra = |spostamento: u32| char::from(ALFABETO[((tre >> spostamento) & 0x3f) as usize]);
        uscita.push(cifra(18));
        uscita.push(cifra(12));
        uscita.push(if gruppo.len() > 1 { cifra(6) } else { '=' });
        uscita.push(if gruppo.len() > 2 { cifra(0) } else { '=' });
    }
    uscita
}

/// Che cosa la porta chiede al server.
///
/// Un insieme chiuso: il `GET` delle letture e il `POST` di TAXII. Un verbo
/// nuovo è una decisione che passa da un ADR, non un valore.
#[cfg_attr(not(windows), allow(dead_code))]
enum Richiesta<'a> {
    /// Leggere, senza corpo e senza intestazioni; si accetta `200`.
    Lettura,
    /// Mandare a TAXII; si accetta `202`.
    InvioTaxii {
        /// Il corpo, composto dal programma.
        corpo: &'a [u8],
        /// Le tre righe di [`taxii_headers`].
        intestazioni: &'a str,
    },
}

/// Perché un indirizzo non è utilizzabile, se non lo è.
///
/// # Perché i controlli stanno qui e non in due posti
///
/// Sono gli stessi per il manifesto e per l'artefatto, e due copie sono due
/// copie che un giorno divergono — e quella che diverge è quella meno letta.
fn indirizzo_inaccettabile(url: &str) -> Option<FetchRefusal> {
    // Il controllo dello schema sta PRIMA di qualunque apertura: un indirizzo in
    // chiaro non deve nemmeno far nascere una sessione.
    if !url.starts_with("https://") {
        return Some(FetchRefusal::NotHttps);
    }
    if url.chars().count() > MAX_URL_CHARS {
        return Some(FetchRefusal::UnusableUrl);
    }
    // Un indirizzo con caratteri di controllo finirebbe in una riga di registro,
    // e lì significherebbe altro.
    if url.chars().any(char::is_control) {
        return Some(FetchRefusal::UnusableUrl);
    }
    // CREDENZIALI NELL'INDIRIZZO: si rifiuta, non si ignora.
    //
    // `WinHttpCrackUrl` le separerebbe e questo modulo non le userebbe, quindi
    // la richiesta partirebbe **senza** autenticazione. Sarebbe la cosa
    // peggiore: chi ha scritto quell'indirizzo si aspetta che servano, e
    // vedrebbe un rifiuto del server invece di capire che il prodotto non
    // autentica. Non c'è nulla da autenticare qui: si scarica un file pubblico.
    if autorita(url).contains('@') {
        return Some(FetchRefusal::UnusableUrl);
    }

    None
}

/// L'host di un indirizzo, in minuscolo, per confrontarlo con un altro.
///
/// # Perché esiste
///
/// L'indirizzo dell'artefatto viene dal **manifesto**, non dalla configurazione:
/// chi controlla il manifesto sceglierebbe dove la postazione va a bussare. Il
/// vincolo di ADR-0068 è che stia sullo stesso host dell'origine configurata, e
/// il confronto va fatto sull'**host**, non sulla stringa intera.
///
/// La porta non lo applica da sé: lo applica chi conosce la configurazione. Qui
/// c'è solo il modo di leggerlo, perché leggerlo in due posti diversi
/// significherebbe leggerlo in due modi diversi.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    if !url.starts_with("https://") {
        return None;
    }
    let autorita = autorita(url);
    if autorita.is_empty() || autorita.contains('@') {
        return None;
    }
    // La porta non fa parte dell'host, ed è l'unica parte che può mancare.
    let host = autorita.split(':').next().unwrap_or(autorita);
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// La parte dell'indirizzo fra `https://` e la prima barra.
///
/// Si legge **senza** WinHTTP perché il controllo deve avvenire prima di aprire
/// qualunque cosa.
fn autorita(url: &str) -> &str {
    let resto = url.strip_prefix("https://").unwrap_or(url);
    resto.split('/').next().unwrap_or(resto)
}

#[cfg(not(windows))]
fn fetch_impl(_url: &str, _massimo: usize) -> Fetched {
    Fetched::Refused(FetchRefusal::NotWindows)
}

#[cfg(not(windows))]
fn fetch_to_file_impl(_url: &str, _destinazione: &std::path::Path, _attesi: u64) -> Downloaded {
    Downloaded::Refused(FetchRefusal::NotWindows)
}

#[cfg(not(windows))]
fn send_impl(_url: &str, _corpo: &[u8], _intestazioni: &str) -> Fetched {
    Fetched::Refused(FetchRefusal::NotWindows)
}

/// Legge un documento piccolo tenendolo in memoria.
#[cfg(windows)]
fn fetch_impl(url: &str, massimo: usize) -> Fetched {
    ricevi(url, &Richiesta::Lettura, massimo)
}

/// Manda a TAXII e legge la risposta di stato, entro il limite piccolo.
#[cfg(windows)]
fn send_impl(url: &str, corpo: &[u8], intestazioni: &str) -> Fetched {
    ricevi(
        url,
        &Richiesta::InvioTaxii {
            corpo,
            intestazioni,
        },
        MAX_BODY_BYTES,
    )
}

/// Apre la richiesta e tiene in memoria la risposta, entro il limite.
#[cfg(windows)]
fn ricevi(url: &str, richiesta: &Richiesta<'_>, massimo: usize) -> Fetched {
    let aperta = match apri(url, richiesta) {
        Ok(aperta) => aperta,
        Err(motivo) => return Fetched::Refused(motivo),
    };

    // INVARIANTE 4: il corpo si legge a blocchi, e il limite si applica prima di
    // far crescere il vettore. Il tetto della memoria è il limite più un blocco.
    let mut corpo: Vec<u8> = Vec::new();
    let mut blocco = [0_u8; BLOCCO];
    loop {
        let quanti = match aperta.leggi(&mut blocco) {
            Ok(quanti) => quanti,
            Err(motivo) => return Fetched::Refused(motivo),
        };
        if quanti == 0 {
            break;
        }

        if corpo.len() + quanti > massimo {
            return Fetched::Refused(FetchRefusal::TooLarge { max: massimo });
        }
        corpo.extend_from_slice(&blocco[..quanti]);
    }

    Fetched::Body(corpo)
}

/// Scarica un documento grande scrivendolo su disco mentre arriva.
///
/// # Perché non si tiene in memoria
///
/// Un artefatto è decine di megabyte. Tenerlo in memoria per poi scriverlo
/// significherebbe che il tetto della memoria è il tetto dell'artefatto, e su
/// una postazione d'ufficio quel tetto lo decide chi serve il file.
#[cfg(windows)]
fn fetch_to_file_impl(url: &str, destinazione: &std::path::Path, attesi: u64) -> Downloaded {
    use std::io::Write;

    let aperta = match apri(url, &Richiesta::Lettura) {
        Ok(aperta) => aperta,
        Err(motivo) => return Downloaded::Refused(motivo),
    };

    let file = std::fs::File::create(destinazione);
    let Ok(file) = file else {
        return Downloaded::Refused(FetchRefusal::NotWritten {
            reason: String::from("la cartella di destinazione non accetta il file"),
        });
    };
    let mut file = std::io::BufWriter::new(file);

    let mut scritti: u64 = 0;
    let mut blocco = [0_u8; BLOCCO];
    loop {
        let quanti = match aperta.leggi(&mut blocco) {
            Ok(quanti) => quanti,
            Err(motivo) => return rinuncia(file, destinazione, motivo),
        };
        if quanti == 0 {
            break;
        }

        // IL LIMITE AGISCE PRIMA DI SCRIVERE, non dopo: un file che supera il
        // dichiarato non deve arrivare sul disco nemmeno per un istante.
        let dopo = scritti.saturating_add(quanti as u64);
        if dopo > attesi {
            return rinuncia(
                file,
                destinazione,
                FetchRefusal::Oversized { declared: attesi },
            );
        }

        if file.write_all(&blocco[..quanti]).is_err() {
            return rinuncia(
                file,
                destinazione,
                FetchRefusal::NotWritten {
                    reason: String::from("la scrittura si è interrotta"),
                },
            );
        }
        scritti = dopo;
    }

    if scritti != attesi {
        return rinuncia(
            file,
            destinazione,
            FetchRefusal::Incomplete {
                received: scritti,
                declared: attesi,
            },
        );
    }

    if file.flush().is_err() {
        return rinuncia(
            file,
            destinazione,
            FetchRefusal::NotWritten {
                reason: String::from("la chiusura del file non è riuscita"),
            },
        );
    }

    Downloaded::Saved { bytes: scritti }
}

/// Abbandona uno scaricamento, e **toglie ciò che era stato scritto**.
///
/// Un file parziale in una cartella è un file che qualcuno può scambiare per
/// completo, e nessuno guarda la data di modifica prima di fidarsi.
#[cfg(windows)]
fn rinuncia(
    file: std::io::BufWriter<std::fs::File>,
    destinazione: &std::path::Path,
    motivo: FetchRefusal,
) -> Downloaded {
    drop(file);
    // Se la rimozione non riesce, il rifiuto resta quello vero: dire «non si è
    // potuto cancellare» al posto di «il server ha mentito» nasconderebbe il
    // fatto che conta.
    let _ = std::fs::remove_file(destinazione);
    Downloaded::Refused(motivo)
}

/// La dimensione di un blocco di lettura.
#[cfg(windows)]
const BLOCCO: usize = 8 * 1024;

/// Una richiesta aperta, con la risposta già accettata.
///
/// # Perché esiste
///
/// Le due letture — quella in memoria e quella su file — hanno **la stessa**
/// apertura: schema, sessione, connessione, richiesta, opzioni, invio, stato.
/// Scriverla due volte significherebbe due copie di codice `unsafe`, e la
/// seconda sarebbe quella che un giorno non riceve una correzione.
///
/// INVARIANTE 1: i campi si rilasciano **nell'ordine in cui sono dichiarati**,
/// quindi la richiesta si chiude per prima, poi la connessione, poi la
/// sessione — che è ciò che WinHTTP si aspetta. **Non riordinare i campi.**
#[cfg(windows)]
struct Aperta {
    richiesta: Maniglia,
    _connessione: Maniglia,
    _sessione: Maniglia,
}

#[cfg(windows)]
impl Aperta {
    /// Legge il prossimo blocco, e restituisce quanti byte sono arrivati.
    ///
    /// Zero significa **finita**, non «riprova»: è così che WinHTTP dichiara la
    /// fine della risposta.
    fn leggi(&self, blocco: &mut [u8; BLOCCO]) -> Result<usize, FetchRefusal> {
        use windows_sys::Win32::Networking::WinHttp::WinHttpReadData;

        let mut letti: u32 = 0;
        // SAFETY: il buffer è un array della dimensione `BLOCCO`, e a WinHTTP si
        // dichiara esattamente quella dimensione; la maniglia è viva finché vive
        // `self`.
        let ok = unsafe {
            WinHttpReadData(
                self.richiesta.grezza(),
                blocco.as_mut_ptr().cast(),
                u32::try_from(BLOCCO).unwrap_or(0),
                std::ptr::from_mut::<u32>(&mut letti),
            )
        };
        if ok == 0 {
            return Err(FetchRefusal::Unreachable {
                code: ultimo_errore(),
            });
        }

        Ok(usize::try_from(letti).unwrap_or(0).min(BLOCCO))
    }
}

/// Apre la richiesta e accetta la risposta, o dice perché no.
///
/// Restituisce soltanto risposte con lo stato atteso — `200` per una lettura,
/// `202` per un invio TAXII: un rimando e uno stato diverso sono rifiuti, e
/// sono rifiuti **diversi** (ADR-0067).
#[cfg(windows)]
fn apri(url: &str, cosa: &Richiesta<'_>) -> Result<Aperta, FetchRefusal> {
    use windows_sys::Win32::Networking::WinHttp::{
        URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_DISABLE_AUTHENTICATION,
        WINHTTP_DISABLE_COOKIES, WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE,
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
        WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_QUERY_STATUS_CODE, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen,
        WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReceiveResponse, WinHttpSendRequest,
        WinHttpSetOption, WinHttpSetTimeouts,
    };

    // INVARIANTE 3: questo vettore contiene l'indirizzo, e `WinHttpCrackUrl`
    // riempirà `componenti` con puntatori DENTRO di esso. Non va mai
    // riassegnato né spostato finché quei puntatori si leggono.
    let indirizzo = wide(url);

    let mut componenti = URL_COMPONENTS {
        dwStructSize: u32::try_from(core::mem::size_of::<URL_COMPONENTS>()).unwrap_or(0),
        ..Default::default()
    };
    // I campi `lpsz*` restano nulli e i `dw*Length` valgono `u32::MAX`: è il modo
    // in cui si chiede a WinHTTP di indicare dentro la stringa invece di
    // copiare. Senza, servirebbero buffer nostri per ogni pezzo.
    componenti.dwHostNameLength = u32::MAX;
    componenti.dwUrlPathLength = u32::MAX;
    componenti.dwExtraInfoLength = u32::MAX;

    // SAFETY: `indirizzo` è UTF-16 terminata da zero e vive per tutta la
    // funzione (invariante 2 e 3); `componenti` è una struttura posseduta qui,
    // con `dwStructSize` dichiarata.
    let letto = unsafe {
        WinHttpCrackUrl(
            indirizzo.as_ptr(),
            0,
            0,
            std::ptr::from_mut::<URL_COMPONENTS>(&mut componenti),
        )
    };
    if letto == 0 {
        return Err(FetchRefusal::UnusableUrl);
    }

    let host = porzione(&componenti.lpszHostName, componenti.dwHostNameLength);
    let percorso = {
        let mut percorso = porzione(&componenti.lpszUrlPath, componenti.dwUrlPathLength);
        percorso.extend(porzione(
            &componenti.lpszExtraInfo,
            componenti.dwExtraInfoLength,
        ));
        percorso
    };
    if host.is_empty() {
        return Err(FetchRefusal::UnusableUrl);
    }
    let host = wide_from(&host);
    // Un indirizzo senza percorso — «https://host» — lascia il percorso vuoto.
    // WinHTTP vuole comunque una risorsa: la radice.
    let percorso = if percorso.is_empty() {
        wide("/")
    } else {
        wide_from(&percorso)
    };

    let agente = wide(concat!("NEXUM97/", env!("CARGO_PKG_VERSION")));

    // SAFETY: `agente` è UTF-16 terminata da zero e vive fino alla fine della
    // chiamata; i due puntatori di proxy sono nulli, che è il valore previsto
    // per l'accesso automatico.
    let sessione = unsafe {
        WinHttpOpen(
            agente.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    let Some(sessione) = Maniglia::nuova(sessione) else {
        return Err(FetchRefusal::Unreachable {
            code: ultimo_errore(),
        });
    };

    // SAFETY: la maniglia è valida per tutta la vita di `sessione`.
    unsafe {
        WinHttpSetTimeouts(
            sessione.grezza(),
            TIMEOUT_MS,
            TIMEOUT_MS,
            TIMEOUT_MS,
            TIMEOUT_MS,
        );
    }

    // SOLO TLS 1.2 E 1.3.
    //
    // WinHTTP negozia da sé ciò che il sistema consente, e su una postazione
    // aggiornata è già questo. Dirlo esplicitamente toglie di mezzo il caso in
    // cui una politica di macchina riabiliti versioni più vecchie: la richiesta
    // partirebbe comunque, e nessuno se ne accorgerebbe. È la stessa scelta già
    // fatta negli script di acquisizione.
    let protocolli: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    // SAFETY: il puntatore indica una variabile locale viva per tutta la
    // chiamata, e la lunghezza dichiarata è quella del suo tipo.
    unsafe {
        WinHttpSetOption(
            sessione.grezza(),
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            std::ptr::from_ref::<u32>(&protocolli).cast(),
            u32::try_from(core::mem::size_of::<u32>()).unwrap_or(4),
        );
    }

    // SAFETY: `host` è UTF-16 terminata da zero e vive fino alla fine della
    // funzione; la porta viene da `WinHttpCrackUrl`.
    let connessione =
        unsafe { WinHttpConnect(sessione.grezza(), host.as_ptr(), componenti.nPort, 0) };
    let Some(connessione) = Maniglia::nuova(connessione) else {
        return Err(FetchRefusal::Unreachable {
            code: ultimo_errore(),
        });
    };

    // I VERBI SONO DUE, E NON VENGONO DA FUORI (ADR-0067, ADR-0179).
    let verbo = match cosa {
        Richiesta::Lettura => wide("GET"),
        Richiesta::InvioTaxii { .. } => wide("POST"),
    };
    // SAFETY: `verbo` e `percorso` sono UTF-16 terminate da zero e vivono fino
    // alla fine della funzione; versione, referente e tipi accettati sono nulli,
    // che è il valore previsto per «i predefiniti».
    let richiesta = unsafe {
        WinHttpOpenRequest(
            connessione.grezza(),
            verbo.as_ptr(),
            percorso.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        )
    };
    let Some(richiesta) = Maniglia::nuova(richiesta) else {
        return Err(FetchRefusal::Unreachable {
            code: ultimo_errore(),
        });
    };

    // INVARIANTE 6: la maschera è una variabile perché WinHTTP la legge durante
    // la chiamata. Le tre funzioni disabilitate sono ADR-0067: nessun rimando
    // seguito, nessun cookie, nessuna autenticazione automatica.
    let disabilitate: u32 =
        WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    // SAFETY: il puntatore indica una variabile locale viva per tutta la
    // chiamata, e la lunghezza dichiarata è quella del suo tipo.
    let impostata = unsafe {
        WinHttpSetOption(
            richiesta.grezza(),
            WINHTTP_OPTION_DISABLE_FEATURE,
            std::ptr::from_ref::<u32>(&disabilitate).cast(),
            u32::try_from(core::mem::size_of::<u32>()).unwrap_or(4),
        )
    };
    if impostata == 0 {
        // Se non si possono disabilitare rimandi, cookie e autenticazione, la
        // richiesta NON si fa: farla comunque significherebbe farla con
        // proprietà che ADR-0067 vieta.
        return Err(FetchRefusal::Unreachable {
            code: ultimo_errore(),
        });
    }

    // INVARIANTE 2: le intestazioni sono UTF-16 terminate da zero, e lunghezza
    // `u32::MAX` dice a WinHTTP di misurarle da sé; il corpo è un prestito che
    // vive più a lungo della chiamata. Una lettura non ha né l'uno né l'altro.
    let intestazioni_larghe;
    let (intestazioni, lunghezza_intestazioni, corpo, lunghezza_corpo) = match cosa {
        Richiesta::Lettura => (std::ptr::null(), 0, std::ptr::null(), 0),
        Richiesta::InvioTaxii {
            corpo,
            intestazioni,
        } => {
            intestazioni_larghe = wide(intestazioni);
            let Ok(lunghezza) = u32::try_from(corpo.len()) else {
                return Err(FetchRefusal::UnusableBody);
            };
            (
                intestazioni_larghe.as_ptr(),
                u32::MAX,
                corpo.as_ptr().cast::<core::ffi::c_void>(),
                lunghezza,
            )
        }
    };
    // SAFETY: per una lettura tutti i puntatori sono nulli con lunghezza zero,
    // che è la forma prevista; per un invio indicano le intestazioni e il corpo
    // qui sopra, vivi fino alla fine della funzione, con le lunghezze vere.
    let spedita = unsafe {
        WinHttpSendRequest(
            richiesta.grezza(),
            intestazioni,
            lunghezza_intestazioni,
            corpo,
            lunghezza_corpo,
            lunghezza_corpo,
            0,
        )
    };
    if spedita == 0 {
        return Err(FetchRefusal::Unreachable {
            code: ultimo_errore(),
        });
    }

    // SAFETY: la maniglia è valida; il secondo parametro è riservato e nullo.
    let ricevuta = unsafe { WinHttpReceiveResponse(richiesta.grezza(), std::ptr::null_mut()) };
    if ricevuta == 0 {
        return Err(FetchRefusal::Unreachable {
            code: ultimo_errore(),
        });
    }

    let mut stato: u32 = 0;
    let mut lunghezza = u32::try_from(core::mem::size_of::<u32>()).unwrap_or(4);
    // SAFETY: il buffer è una variabile locale della dimensione dichiarata in
    // `lunghezza`; con `WINHTTP_QUERY_FLAG_NUMBER` WinHTTP scrive un `u32`.
    let interrogata = unsafe {
        WinHttpQueryHeaders(
            richiesta.grezza(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            std::ptr::null(),
            std::ptr::from_mut::<u32>(&mut stato).cast(),
            std::ptr::from_mut::<u32>(&mut lunghezza),
            std::ptr::null_mut(),
        )
    };
    if interrogata == 0 {
        return Err(FetchRefusal::Unreachable {
            code: ultimo_errore(),
        });
    }

    if (300..400).contains(&stato) {
        return Err(FetchRefusal::Redirected { status: stato });
    }
    let atteso = match cosa {
        Richiesta::Lettura => 200,
        Richiesta::InvioTaxii { .. } => 202,
    };
    if stato != atteso {
        return Err(FetchRefusal::Status { status: stato });
    }

    Ok(Aperta {
        richiesta,
        _connessione: connessione,
        _sessione: sessione,
    })
}

/// Una maniglia di WinHTTP che si chiude da sé.
///
/// INVARIANTE 1: le tre maniglie vivono in variabili locali dichiarate in
/// ordine — sessione, connessione, richiesta — e Rust le rilascia in ordine
/// **inverso**, che è ciò che WinHTTP si aspetta. Un ritorno anticipato non ne
/// perde nessuna.
#[cfg(windows)]
struct Maniglia(*mut core::ffi::c_void);

#[cfg(windows)]
impl Maniglia {
    /// Prende in carico una maniglia, se WinHTTP l'ha davvero creata.
    fn nuova(grezza: *mut core::ffi::c_void) -> Option<Self> {
        if grezza.is_null() {
            return None;
        }
        Some(Self(grezza))
    }

    /// La maniglia da passare a WinHTTP.
    const fn grezza(&self) -> *mut core::ffi::c_void {
        self.0
    }
}

#[cfg(windows)]
impl Drop for Maniglia {
    fn drop(&mut self) {
        // SAFETY: `self.0` è non nullo per costruzione e non è stato chiuso
        // altrove: nessun altro punto del modulo chiama `WinHttpCloseHandle`.
        unsafe {
            windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(self.0);
        }
    }
}

/// L'ultimo errore di Windows, come numero.
#[cfg(windows)]
fn ultimo_errore() -> u32 {
    // SAFETY: `GetLastError` non ha parametri e non tocca memoria nostra.
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

/// Una stringa UTF-16 terminata da zero.
#[cfg(windows)]
fn wide(testo: &str) -> Vec<u16> {
    testo.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Una stringa UTF-16 terminata da zero, da unità già in UTF-16.
#[cfg(windows)]
fn wide_from(unita: &[u16]) -> Vec<u16> {
    let mut copia = unita.to_vec();
    copia.push(0);
    copia
}

/// Copia una porzione indicata da `WinHttpCrackUrl`.
///
/// INVARIANTE 3: i puntatori indicano **dentro** l'indirizzo passato, che è
/// vivo. La porzione viene **copiata** subito, così nessun puntatore sopravvive
/// alla funzione.
#[cfg(windows)]
fn porzione(inizio: &windows_sys::core::PWSTR, lunghezza: u32) -> Vec<u16> {
    if inizio.is_null() || lunghezza == 0 || lunghezza == u32::MAX {
        return Vec::new();
    }
    let quante = usize::try_from(lunghezza).unwrap_or(0);
    // SAFETY: WinHTTP ha scritto puntatore e lunghezza indicando dentro
    // l'indirizzo, che è vivo e non è stato spostato (invariante 3).
    let porzione = unsafe { core::slice::from_raw_parts(*inizio, quante) };
    porzione.to_vec()
}

#[cfg(test)]
mod tests {
    use super::{
        BasicCredentials, BodyLimit, Downloaded, FetchRefusal, Fetched, MAX_ARTIFACT_BYTES,
        MAX_BODY_BYTES, MAX_DICTIONARY_BYTES, MAX_REGISTRATION_BYTES, MAX_TAXII_BODY_BYTES,
        MAX_URL_CHARS, Sent, TAXII_MEDIA_TYPE, base64, fetch, fetch_to_file, fetch_within, host_of,
        send_taxii, taxii_headers,
    };

    /// Credenziali di prova: nessun server vero le conosce.
    const PROVA: BasicCredentials<'static> = BasicCredentials {
        user: "ufficio",
        password: "parola di prova",
    };

    /// **Un invio passa dagli stessi controlli dell'indirizzo, prima della
    /// rete** (TAXII-01, ADR-0179, decisione 6).
    #[test]
    fn un_invio_in_chiaro_o_con_credenziali_nell_indirizzo_non_parte() {
        let corpo = br#"{"objects":[]}"#;
        assert_eq!(
            send_taxii(
                "http://taxii.esempio.test/api/collections/a/objects/",
                corpo,
                &PROVA
            ),
            Sent::Refused(FetchRefusal::NotHttps)
        );
        assert_eq!(
            send_taxii("https://chi:parola@taxii.esempio.test/api/", corpo, &PROVA),
            Sent::Refused(FetchRefusal::UnusableUrl)
        );
        assert_eq!(
            send_taxii("https://taxii.esempio.test/a\nb", corpo, &PROVA),
            Sent::Refused(FetchRefusal::UnusableUrl)
        );
    }

    /// **Un corpo vuoto o oltre il limite non parte.**
    #[test]
    fn un_corpo_vuoto_o_oltre_il_limite_non_parte() {
        let indirizzo = "https://taxii.esempio.test/api/collections/a/objects/";
        assert_eq!(
            send_taxii(indirizzo, b"", &PROVA),
            Sent::Refused(FetchRefusal::UnusableBody)
        );
        let grande = vec![b' '; MAX_TAXII_BODY_BYTES + 1];
        assert_eq!(
            send_taxii(indirizzo, &grande, &PROVA),
            Sent::Refused(FetchRefusal::UnusableBody)
        );
        // Il limite dell'invio resta sotto quello di qualunque lettura grande.
        const { assert!(MAX_TAXII_BODY_BYTES < MAX_DICTIONARY_BYTES) };
    }

    /// **Credenziali che aprirebbero un'intestazione nuova non partono.**
    ///
    /// Un a capo nel nome o nella parola d'ordine scriverebbe una riga
    /// dell'intestazione scelta da chi li ha scritti.
    #[test]
    fn credenziali_inutilizzabili_non_partono() {
        let indirizzo = "https://taxii.esempio.test/api/collections/a/objects/";
        for (user, password) in [
            ("", "parola"),
            ("ufficio", ""),
            ("uff:icio", "parola"),
            ("ufficio\r\nX-Altro: si", "parola"),
            ("ufficio", "parola\r\nX-Altro: si"),
        ] {
            assert_eq!(
                send_taxii(indirizzo, b"{}", &BasicCredentials { user, password }),
                Sent::Refused(FetchRefusal::UnusableCredentials),
                "«{user}» non deve partire"
            );
        }
        // Nemmeno una prova che fallisce stampa la parola d'ordine.
        assert!(!format!("{PROVA:?}").contains("parola di prova"));
    }

    /// **L'intestazione è di tre righe, sempre le stesse** (RFC 7617, §2).
    #[test]
    fn l_intestazione_dice_il_tipo_taxii_e_l_autenticazione_basic() {
        let Some(intestazioni) = taxii_headers(&BasicCredentials {
            user: "Aladdin",
            password: "open sesame",
        }) else {
            panic!("credenziali buone devono comporre l'intestazione");
        };
        let righe: Vec<&str> = intestazioni.split("\r\n").collect();
        assert_eq!(
            righe,
            vec![
                format!("Accept: {TAXII_MEDIA_TYPE}").as_str(),
                format!("Content-Type: {TAXII_MEDIA_TYPE}").as_str(),
                "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            ]
        );
        assert_eq!(TAXII_MEDIA_TYPE, "application/taxii+json;version=2.1");
    }

    /// **La codifica è quella dello standard** (RFC 4648, §10).
    #[test]
    fn la_codifica_e_quella_dello_standard() {
        for (chiaro, codificato) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(chiaro.as_bytes()), codificato);
        }
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }

    /// Il sorgente di questo modulo, letto a tempo di compilazione.
    const QUESTO_MODULO: &str = include_str!("https.rs");

    /// Il solo codice di produzione di questo modulo.
    ///
    /// Serve alle prove che vietano PAROLE: su tutto il modulo troverebbero se
    /// stesse, e diventerebbero rosse sulla propria spiegazione.
    fn produzione() -> &'static str {
        let Some((prima, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita: la guardia va riscritta insieme");
        };
        prima
    }

    /// **I limiti sono un insieme chiuso, e il dizionario non cambia le regole**
    /// (DICT-NET-01, ADR-0178, decisione 7).
    ///
    /// Il limite più grande vale soltanto per un dizionario; ogni lettura passa
    /// dagli stessi controlli dell'indirizzo, prima di aprire qualcosa.
    #[test]
    fn i_limiti_sono_chiusi_e_il_dizionario_passa_dagli_stessi_controlli() {
        assert_eq!(BodyLimit::Small.bytes(), MAX_BODY_BYTES);
        assert_eq!(BodyLimit::Dictionary.bytes(), MAX_DICTIONARY_BYTES);
        assert!(MAX_DICTIONARY_BYTES < usize::try_from(MAX_ARTIFACT_BYTES).unwrap_or(0));
        assert_eq!(BodyLimit::Registration.bytes(), MAX_REGISTRATION_BYTES);
        const { assert!(MAX_BODY_BYTES < MAX_REGISTRATION_BYTES) };
        for limite in [
            BodyLimit::Small,
            BodyLimit::Dictionary,
            BodyLimit::Catalogue,
            BodyLimit::Registration,
        ] {
            assert_eq!(
                fetch_within("http://esempio.test/d.json", limite),
                Fetched::Refused(FetchRefusal::NotHttps)
            );
            assert_eq!(
                fetch_within("https://chi:parola@esempio.test/d.json", limite),
                Fetched::Refused(FetchRefusal::UnusableUrl)
            );
        }
        // Il manifesto resta dov'era: `fetch` è il limite piccolo, non un altro.
        assert!(
            produzione().contains("fetch_within(url, BodyLimit::Small)"),
            "«fetch» deve restare la lettura con il limite di un manifesto"
        );
        // E nessun limite si sceglie con un numero.
        assert!(
            !produzione().contains("pub fn fetch_within(url: &str, limit: usize"),
            "il limite di una lettura non deve diventare un numero libero"
        );
    }

    /// **In chiaro non si esce, e il rifiuto arriva prima di aprire qualcosa.**
    #[test]
    fn un_indirizzo_in_chiaro_non_apre_nemmeno_una_sessione() {
        for indirizzo in [
            "http://esempio.test/m.json",
            "ftp://esempio.test/m.json",
            "file:///C:/m.json",
            "esempio.test/m.json",
            "",
        ] {
            assert_eq!(
                fetch(indirizzo),
                Fetched::Refused(FetchRefusal::NotHttps),
                "«{indirizzo}» non deve poter uscire"
            );
        }
    }

    #[test]
    fn un_indirizzo_smisurato_o_con_caratteri_di_controllo_si_rifiuta() {
        let lungo = format!("https://esempio.test/{}", "a".repeat(MAX_URL_CHARS));
        assert_eq!(
            fetch(&lungo),
            Fetched::Refused(FetchRefusal::UnusableUrl),
            "un indirizzo oltre il limite non deve essere usato"
        );

        assert_eq!(
            fetch("https://esempio.test/m\u{0}.json"),
            Fetched::Refused(FetchRefusal::UnusableUrl)
        );
        assert_eq!(
            fetch("https://esempio.test/m\n.json"),
            Fetched::Refused(FetchRefusal::UnusableUrl)
        );
    }

    /// **Le credenziali nell'indirizzo si rifiutano, non si ignorano.**
    ///
    /// `WinHttpCrackUrl` le separerebbe e la richiesta partirebbe SENZA
    /// autenticazione: chi ha scritto quell'indirizzo si aspetta che servano, e
    /// vedrebbe un rifiuto del server invece di capire che il prodotto non
    /// autentica. Qui non c'e' nulla da autenticare: si scarica un file
    /// pubblico.
    #[test]
    fn un_indirizzo_con_credenziali_si_rifiuta() {
        for indirizzo in [
            "https://utente:parola@esempio.test/m.json",
            "https://utente@esempio.test/m.json",
        ] {
            assert_eq!(
                fetch(indirizzo),
                Fetched::Refused(FetchRefusal::UnusableUrl),
                "«{indirizzo}» porta credenziali e non deve partire"
            );
        }

        // Una chiocciola nel PERCORSO non e' una credenziale, e non deve
        // trasformare un indirizzo buono in un rifiuto.
        assert_ne!(
            super::autorita("https://esempio.test/a@b.json"),
            "esempio.test/a@b.json",
            "l'autorita' si ferma alla prima barra"
        );
        assert_eq!(
            super::autorita("https://esempio.test/a@b.json"),
            "esempio.test"
        );
    }

    /// **Solo TLS 1.2 e 1.3.**
    ///
    /// WinHTTP negozia da se' cio' che il sistema consente. Dirlo esplicitamente
    /// toglie di mezzo il caso in cui una politica di macchina riabiliti versioni
    /// piu' vecchie: la richiesta partirebbe comunque, e nessuno se ne
    /// accorgerebbe.
    #[test]
    fn le_versioni_di_tls_ammesse_sono_dichiarate() {
        assert!(
            QUESTO_MODULO.contains("WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2")
                && QUESTO_MODULO.contains("WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3"),
            "le versioni di TLS ammesse si dichiarano, non si ereditano in silenzio"
        );
        // SI GUARDA SOLO IL CODICE DI PRODUZIONE, e non per comodita': questa
        // prova NOMINA le versioni che vieta, e su tutto il modulo troverebbe
        // se stessa. E' la stessa lezione gia' imparata tre volte in questo
        // progetto — una guardia che vieta parole vietera' anche la spiegazione
        // di cio' che vieta.
        let produzione = produzione();
        for vecchia in ["PROTOCOL_SSL3", "PROTOCOL_TLS1_1"] {
            assert!(
                !produzione.contains(vecchia),
                "{vecchia} non deve comparire nel codice di questo modulo"
            );
        }
    }

    /// **La porta sa fare una cosa sola, e le tre proprietà che la tengono
    /// stretta non sono parametri.**
    ///
    /// Sono ADR-0067, e un parametro sarebbe il modo in cui un giorno
    /// smetterebbero di valere: basterebbe un chiamante che passa l'altro
    /// valore, e nessuna prova lo vedrebbe.
    #[test]
    fn rimandi_cookie_e_autenticazione_restano_disabilitati() {
        assert!(
            QUESTO_MODULO.contains("WINHTTP_DISABLE_REDIRECTS")
                && QUESTO_MODULO.contains("WINHTTP_DISABLE_COOKIES")
                && QUESTO_MODULO.contains("WINHTTP_DISABLE_AUTHENTICATION"),
            "le tre funzioni disabilitate sono ADR-0067: se una sparisce, sparisce \
             senza che nessuno se ne accorga"
        );

        // La firma di `fetch` prende UN parametro: l'indirizzo. Se un giorno ne
        // prendesse un secondo, sarebbe il momento di rileggere ADR-0067 prima
        // di cambiarla.
        assert!(
            QUESTO_MODULO.contains("pub fn fetch(url: &str) -> Fetched {"),
            "la porta deve prendere l'indirizzo e nient'altro"
        );
    }

    /// **Due verbi: `GET` per leggere, `POST` soltanto per TAXII** (ADR-0179,
    /// decisione 6).
    #[test]
    fn i_verbi_sono_due_e_il_secondo_e_soltanto_di_taxii() {
        assert_eq!(
            QUESTO_MODULO.matches("wide(\"GET\")").count(),
            1,
            "il verbo si scrive una volta sola, e non viene da fuori"
        );
        assert_eq!(
            produzione()
                .matches("Richiesta::InvioTaxii { .. } => wide(\"POST\")")
                .count(),
            1,
            "il POST nasce soltanto da un invio TAXII"
        );
        assert_eq!(produzione().matches("\"POST\"").count(), 1);
        // Il solo modo di arrivarci è la funzione pubblica, con le sue
        // credenziali: niente verbo, niente intestazioni come parametri.
        assert!(produzione().contains(
            "pub fn send_taxii(url: &str, envelope: &[u8], credentials: &BasicCredentials<'_>) -> Sent {"
        ));
        assert_eq!(produzione().matches("Richiesta::InvioTaxii {\n").count(), 2);
        for verbo in ["\"PUT\"", "\"DELETE\"", "\"PATCH\""] {
            assert!(
                !QUESTO_MODULO.contains(verbo),
                "{verbo} non deve esistere in questo modulo"
            );
        }
    }

    /// **Anche l'artefatto non esce in chiaro, e il rifiuto arriva prima.**
    #[test]
    fn un_artefatto_in_chiaro_non_si_scarica() {
        let destinazione = std::path::Path::new("non-deve-esistere.scaricato");
        assert_eq!(
            fetch_to_file("http://esempio.test/a.exe", destinazione, 1024),
            Downloaded::Refused(FetchRefusal::NotHttps)
        );
        assert!(
            !destinazione.exists(),
            "un rifiuto prima della rete non deve creare nulla su disco"
        );
    }

    /// **Una dimensione dichiarata oltre il tetto si rifiuta prima di uscire.**
    ///
    /// La dimensione viene dal manifesto, che e' dato non fidato: da sola non e'
    /// un limite, e' un'affermazione. Il tetto del prodotto e' quello che vale
    /// (ADR-0068).
    #[test]
    fn una_dimensione_oltre_il_tetto_non_fa_nemmeno_partire_la_richiesta() {
        let destinazione = std::path::Path::new("non-deve-esistere-2.scaricato");
        assert_eq!(
            fetch_to_file(
                "https://esempio.test/a.exe",
                destinazione,
                MAX_ARTIFACT_BYTES + 1
            ),
            Downloaded::Refused(FetchRefusal::TooLarge {
                max: usize::try_from(MAX_ARTIFACT_BYTES).unwrap_or(usize::MAX)
            })
        );
        assert!(!destinazione.exists());
    }

    /// **Zero byte dichiarati non sono un artefatto.**
    ///
    /// Non e' un caso limite teorico: un manifesto che dichiara zero farebbe
    /// scendere un file vuoto che risulterebbe «completo», perche' zero byte
    /// ricevuti su zero attesi tornano.
    #[test]
    fn una_dimensione_dichiarata_di_zero_si_rifiuta() {
        let destinazione = std::path::Path::new("non-deve-esistere-3.scaricato");
        assert!(matches!(
            fetch_to_file("https://esempio.test/a.exe", destinazione, 0),
            Downloaded::Refused(FetchRefusal::TooLarge { .. })
        ));
        assert!(!destinazione.exists());
    }

    /// **L'host si legge in un modo solo.**
    ///
    /// Serve a confrontare l'indirizzo dell'artefatto — che viene dal manifesto —
    /// con quello dell'origine configurata. Leggerlo in due posti diversi
    /// significherebbe leggerlo in due modi diversi, e la differenza si
    /// scoprirebbe il giorno in cui uno dei due sbaglia.
    #[test]
    fn l_host_si_legge_senza_porta_e_senza_maiuscole() {
        assert_eq!(
            host_of("https://Esempio.TEST/percorso/a.exe").as_deref(),
            Some("esempio.test")
        );
        assert_eq!(
            host_of("https://esempio.test:8443/a.exe").as_deref(),
            Some("esempio.test")
        );
        assert_eq!(
            host_of("https://esempio.test").as_deref(),
            Some("esempio.test")
        );

        // Niente host da cio' che non e' https, da cio' che non ha autorita', e
        // da cio' che porta credenziali.
        assert_eq!(host_of("http://esempio.test/a"), None);
        assert_eq!(host_of("https:///a"), None);
        assert_eq!(host_of("https://utente@esempio.test/a"), None);
    }

    /// **Sul file il limite agisce PRIMA di scrivere, non dopo.**
    ///
    /// Scrivere e poi accorgersi significa aver messo sul disco byte che non
    /// dovevano arrivarci, e su un artefatto sono megabyte.
    #[test]
    fn sul_file_il_limite_agisce_prima_di_scrivere() {
        let Some(corpo) = QUESTO_MODULO
            .split("fn fetch_to_file_impl(url: &str")
            .nth(1)
        else {
            panic!("lo scaricamento su file non si trova: la guardia va riscritta insieme");
        };
        let Some(corpo) = corpo.split("\n}\n").next() else {
            panic!("il corpo dello scaricamento non si delimita");
        };

        let Some(controllo) = corpo.find("if dopo > attesi {") else {
            panic!("il limite non si applica piu' dentro il ciclo di scrittura");
        };
        let Some(scrittura) = corpo.find("file.write_all(") else {
            panic!("la scrittura non si trova piu' dentro il ciclo");
        };
        assert!(
            controllo < scrittura,
            "il limite deve essere verificato PRIMA che i byte finiscano sul disco"
        );
    }

    /// **Ogni rifiuto toglie cio' che era stato scritto.**
    ///
    /// Un file parziale in una cartella e' un file che qualcuno puo' scambiare
    /// per completo, e nessuno guarda la data di modifica prima di fidarsi.
    #[test]
    fn ogni_rifiuto_dopo_l_apertura_del_file_toglie_il_parziale() {
        let Some(corpo) = QUESTO_MODULO
            .split("fn fetch_to_file_impl(url: &str")
            .nth(1)
        else {
            panic!("lo scaricamento su file non si trova");
        };
        let Some(corpo) = corpo.split("\n}\n").next() else {
            panic!("il corpo dello scaricamento non si delimita");
        };

        // Dopo che il file esiste, l'UNICO modo di rifiutare e' `rinuncia`, che
        // lo toglie. Un `Downloaded::Refused` diretto lascerebbe il parziale.
        let dopo_apertura = corpo
            .split_once("let mut file = std::io::BufWriter::new(file);")
            .map(|(_, dopo)| dopo);
        let Some(dopo_apertura) = dopo_apertura else {
            panic!("l'apertura del file non si trova");
        };
        assert!(
            !dopo_apertura.contains("Downloaded::Refused("),
            "dopo che il file esiste, ogni rifiuto deve passare da «rinuncia», \
             che toglie il parziale"
        );
        assert!(
            QUESTO_MODULO.contains("let _ = std::fs::remove_file(destinazione);"),
            "«rinuncia» deve togliere il file"
        );
    }

    /// **Il limite si applica durante la lettura, non dopo.**
    ///
    /// Misurare un corpo dopo averlo letto vuol dire averlo già allocato: un
    /// server ostile lo saprebbe.
    #[test]
    fn il_limite_agisce_prima_di_far_crescere_la_memoria() {
        let Some(ciclo) = QUESTO_MODULO
            .split("let mut blocco = [0_u8; BLOCCO];")
            .nth(1)
        else {
            panic!("il ciclo di lettura non si trova: la guardia va riscritta insieme");
        };
        let Some(ciclo) = ciclo.split("Fetched::Body(corpo)").next() else {
            panic!("il ciclo di lettura non si delimita");
        };

        let Some(controllo) = ciclo.find("corpo.len() + quanti > massimo") else {
            panic!("il limite non si applica piu' dentro il ciclo di lettura");
        };
        let Some(crescita) = ciclo.find("corpo.extend_from_slice") else {
            panic!("la crescita del corpo non si trova piu' dentro il ciclo");
        };
        assert!(
            controllo < crescita,
            "il limite deve essere verificato PRIMA che il corpo cresca"
        );
    }
}

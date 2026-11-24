//! Il collegamento a un messaggio, e quello alla fonte: due cose diverse.
//!
//! # Che cosa il congelamento chiede, alla lettera
//!
//! «`getMessageLink` **ufficiale** di TDLib dove disponibile; ripiego **Apri
//! fonte** quando il collegamento diretto non esiste. Collegamento al messaggio
//! e collegamento alla fonte restano **distinti**, e **non si fabbrica** un
//! collegamento che Telegram non fornisce.»
//!
//! # Che cosa il prodotto faceva prima, e perché smette
//!
//! Componeva l'indirizzo da sé, dai due identificativi che l'aggiornamento
//! portava con sé: `t.me/c/<chat>/<messaggio>`, secondo una convenzione di
//! Telegram documentata e stabile. Funzionava — **per i membri di quella
//! conversazione**.
//!
//! Il problema non è che non funzionasse. È che quell'indirizzo **finiva
//! nell'archivio**, nel campo che dice dove sta il messaggio, accanto al testo
//! acquisito e all'istante dichiarato dalla fonte. In un archivio che ha valore
//! probatorio, un indirizzo composto da noi sta nella stessa colonna di ciò che
//! la fonte ha detto, e nessuna riga distingue i due.
//!
//! Un collegamento composto è una **deduzione**, non un fatto osservato. La
//! stessa disciplina che tiene separati il dato originale, l'analisi
//! deterministica e la valutazione dell'operatore vale qui: si conserva ciò che
//! Telegram ha dato, e ciò che non ha dato **non si inventa**.
//!
//! # La garanzia strutturale: un collegamento non si costruisce da un numero
//!
//! [`MessageLink`] ha il campo **privato** e **un solo costruttore**, che prende
//! l'indirizzo **restituito da Telegram**. Non esiste una funzione che lo
//! ricavi da un identificativo di chat e uno di messaggio: non è una regola da
//! rispettare, è una forma che non si può scrivere.
//!
//! # E la fonte è un'altra cosa
//!
//! [`SourceLink`] non è un [`MessageLink`] e **non può diventarlo**: nessuna
//! conversione, nessun `From`, nessun accessore che restituisca l'altro tipo.
//! Aprire la fonte porta al canale; aprire il messaggio porta al messaggio. Chi
//! consegna un rapporto deve poter dire quale dei due sta citando, e due
//! stringhe indistinguibili non glielo permetterebbero.
//!
//! È la stessa forma di garanzia di REPLAY-01, dove un'ipotesi non può
//! diventare un fatto perché il tipo non passa.

use std::fmt;

/// Il prefisso con cui Telegram serve i propri collegamenti.
const TELEGRAM_LINK_PREFIX: &str = "https://t.me/";

/// Un collegamento a un messaggio, **come Telegram lo ha fornito**.
///
/// # Perché il campo è privato e il costruttore è uno solo
///
/// Perché il solo modo lecito di ottenerne uno è **chiederlo a Telegram**. Un
/// costruttore che prendesse un identificativo di chat e uno di messaggio
/// rimetterebbe in piedi la composizione locale, che è precisamente ciò che
/// questa milestone toglie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageLink {
    /// L'indirizzo, così come Telegram lo ha restituito.
    url: String,
    /// Se Telegram lo dichiara utilizzabile **da chiunque**.
    ///
    /// Un collegamento non pubblico si apre soltanto per i membri della
    /// conversazione. La differenza conta in un rapporto: un indirizzo che il
    /// destinatario non può aprire è peggio di un indirizzo assente, perché
    /// sembra una prova verificabile e non lo è.
    is_public: bool,
}

impl MessageLink {
    /// L'unico modo di ottenere un collegamento: **quello che Telegram dà**.
    ///
    /// Restituisce `None` quando l'indirizzo non ha la forma di un
    /// collegamento Telegram utilizzabile. La verifica non è una formalità:
    /// l'indirizzo finisce in un `ContentUrl` e, da lì, nel browser
    /// dell'operatore (ADR-0018). Uno spazio o un carattere di controllo in
    /// mezzo lo farebbe sparire in silenzio a valle, o peggio.
    #[must_use]
    pub fn from_telegram(url: &str, is_public: bool) -> Option<Self> {
        let url = url.trim();

        if !url.starts_with(TELEGRAM_LINK_PREFIX) {
            return None;
        }
        if url.len() <= TELEGRAM_LINK_PREFIX.len() {
            return None;
        }
        if url.chars().any(|carattere| {
            carattere.is_whitespace() || carattere.is_control() || carattere == '"'
        }) {
            return None;
        }

        Some(Self {
            url: url.to_owned(),
            is_public,
        })
    }

    /// L'indirizzo.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Se Telegram lo dichiara utilizzabile da chiunque.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.is_public
    }

    /// Che cosa il collegamento apre, e per chi.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.is_public {
            format!(
                "Collegamento al messaggio, fornito da Telegram: {}. \u{c8} pubblico: si apre \
                 per chiunque.",
                self.url
            )
        } else {
            format!(
                "Collegamento al messaggio, fornito da Telegram: {}. Non \u{e8} pubblico: si \
                 apre soltanto per chi \u{e8} membro di quella conversazione.",
                self.url
            )
        }
    }
}

impl fmt::Display for MessageLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.url)
    }
}

/// Perché non c'è un collegamento al messaggio.
///
/// # Perché quattro ragioni e non una
///
/// Perché sono quattro cose diverse, e chi legge deve poterle distinguere:
/// «Telegram dice che non esiste» non è «Telegram non ha risposto», e nessuna
/// delle due è «il programma non era collegato».
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkGap {
    /// Telegram ha risposto che per questo messaggio non c'è un collegamento.
    ///
    /// Succede nei gruppi semplici e nelle conversazioni private, che non hanno
    /// indirizzi permanenti.
    NotOfferedByTelegram,
    /// Telegram ha rifiutato la richiesta.
    Refused {
        /// Codice dichiarato da Telegram.
        code: i32,
        /// Messaggio dichiarato da Telegram.
        message: String,
    },
    /// Nessuna risposta entro il termine.
    NoAnswer {
        /// Quanto si è aspettato.
        waited_ms: i64,
    },
    /// Non c'era alcun collegamento attivo a Telegram a cui chiederlo.
    ConnectorUnavailable,
}

impl LinkGap {
    /// Perché il collegamento non c'è, detto a chi legge.
    ///
    /// Ogni frase finisce indicando il ripiego, che è **aprire la fonte**: è
    /// ciò che il congelamento prescrive, e non è la stessa cosa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let ripiego = " Resta la fonte: aprirla porta al canale, non al messaggio.";

        match self {
            Self::NotOfferedByTelegram => format!(
                "Telegram non fornisce un collegamento per questo messaggio: le conversazioni \
                 private e i gruppi semplici non ne hanno.{ripiego}"
            ),
            Self::Refused { code, message } => format!(
                "Telegram ha rifiutato di fornire il collegamento: {code} {message}.{ripiego}"
            ),
            Self::NoAnswer { waited_ms } => format!(
                "Telegram non ha risposto entro {waited_ms} ms. Non significa che il \
                 collegamento non esista: significa che non \u{e8} arrivato.{ripiego}"
            ),
            Self::ConnectorUnavailable => format!(
                "Non c'\u{e8} un collegamento attivo a Telegram a cui chiederlo. Il \
                 collegamento al messaggio si ottiene al momento, e non viene conservato: \
                 nell'archivio finisce solo ci\u{f2} che Telegram ha dato.{ripiego}"
            ),
        }
    }
}

/// L'esito della richiesta del collegamento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    /// Telegram lo ha fornito.
    Provided(MessageLink),
    /// Telegram non lo ha fornito, e si dice perché.
    ///
    /// **Non porta alcun indirizzo.** Un esito negativo che portasse comunque
    /// una stringa sarebbe l'invito a usarla.
    NotProvided(LinkGap),
}

impl LinkOutcome {
    /// Il collegamento, quando c'è.
    #[must_use]
    pub const fn link(&self) -> Option<&MessageLink> {
        match self {
            Self::Provided(link) => Some(link),
            Self::NotProvided(_) => None,
        }
    }

    /// Che cosa è successo, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Provided(link) => link.as_sentence(),
            Self::NotProvided(gap) => gap.as_sentence(),
        }
    }
}

/// Il collegamento alla **fonte**, che è un'altra cosa.
///
/// # Perché non è un [`MessageLink`]
///
/// Perché apre il canale, non il messaggio. Nessuna conversione fra i due, in
/// nessuna direzione: chi consegna un rapporto deve poter dire quale dei due
/// stia citando, e due stringhe indistinguibili non glielo permetterebbero.
///
/// Questo **si compone**, ed è lecito: `t.me/<nome>` è l'indirizzo pubblico di
/// una fonte che ha un nome pubblico, e non pretende di indicare alcun
/// messaggio. Ciò che il congelamento vieta è fabbricare il collegamento a un
/// **messaggio** che Telegram non fornisce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLink(String);

impl SourceLink {
    /// Il collegamento alla fonte con quel nome pubblico.
    ///
    /// Restituisce `None` quando il nome non è utilizzabile in un indirizzo:
    /// una fonte senza nome pubblico non ha un collegamento, e inventarne uno
    /// porterebbe a una pagina che non esiste.
    #[must_use]
    pub fn of(public_name: &str) -> Option<Self> {
        let nome = public_name.trim().trim_start_matches('@');

        if nome.is_empty() {
            return None;
        }
        if !nome
            .chars()
            .all(|carattere| carattere.is_ascii_alphanumeric() || carattere == '_')
        {
            return None;
        }

        Some(Self(format!("{TELEGRAM_LINK_PREFIX}{nome}")))
    }

    /// L'indirizzo della fonte.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Che cosa apre, detto senza confonderlo con il messaggio.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Collegamento alla fonte: {}. Apre il canale, non il messaggio.",
            self.0
        )
    }
}

impl fmt::Display for SourceLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkGap, LinkOutcome, MessageLink, SourceLink};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("link.rs");

    /// Il codice di produzione senza i commenti.
    ///
    /// # Perché verifica anche che dopo le prove non ci sia altro
    ///
    /// Perché legge soltanto ciò che **precede** il blocco di prova, e in Rust
    /// nulla vieta di mettere codice di produzione dopo. Una funzione aggiunta
    /// là in fondo sarebbe **invisibile** a ogni guardia di questo modulo, che
    /// continuerebbe a passare dichiarando cose non più vere.
    ///
    /// Non è un'ipotesi: provando a introdurre una conversione fra i due
    /// collegamenti, il controllo negativo è rimasto **verde** proprio perché
    /// la conversione era finita in coda al file.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        // Dentro il blocco di prova ogni riga e' indentata: una dichiarazione a
        // COLONNA ZERO dopo `mod tests {` e' codice di produzione messo in
        // coda, e nessuna guardia di questo modulo lo vedrebbe.
        //
        // La prima scrittura di questo controllo cercava l'ultima graffa a
        // colonna zero: con un `impl` aggiunto in fondo, l'ultima graffa
        // diventava la SUA, e il controllo passava. Cercare la fine non
        // funziona; cercare le dichiarazioni si'.
        for riga in prove.lines() {
            for dichiarazione in [
                "impl ",
                "pub fn ",
                "fn ",
                "pub struct ",
                "struct ",
                "pub enum ",
                "enum ",
                "pub const ",
                "const ",
                "use ",
            ] {
                assert!(
                    !riga.starts_with(dichiarazione),
                    "dopo il blocco di prove non deve esserci codice di produzione: sarebbe \
                     invisibile a ogni guardia di questo modulo — trovato: «{riga}»"
                );
            }
        }

        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco di una dichiarazione, dal nome alla graffa che la chiude.
    ///
    /// Nessun ripiego: se la fine non c'è, fallisce. Un estrattore che allarga
    /// in silenzio è peggio di uno che non trova niente (SIM-01).
    fn blocco_di(nome: &str) -> String {
        let produzione = codice_senza_commenti();
        let Some(inizio) = produzione.find(nome) else {
            panic!("il modulo deve dichiarare {nome}");
        };
        let resto = &produzione[inizio..];
        let Some(fine) = resto.find("\n}\n") else {
            panic!("la dichiarazione {nome} deve chiudersi");
        };
        resto[..fine].to_owned()
    }

    /// **Un collegamento al messaggio non si costruisce da un numero.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che qualcuno rimetta in piedi la composizione locale — `t.me/c/<chat>/
    /// <messaggio>` dai due identificativi — che è precisamente ciò che questa
    /// milestone toglie. Il congelamento lo scrive: **non si fabbrica** un
    /// collegamento che Telegram non fornisce.
    #[test]
    fn un_collegamento_al_messaggio_non_si_costruisce_da_un_numero() {
        let produzione = codice_senza_commenti();

        // Nessuna composizione a partire da identificativi.
        for composizione in ["t.me/c/", "chat_id", "message_id", "1 << 20", "<< 20"] {
            assert!(
                !produzione.contains(composizione),
                "«{composizione}» rimetterebbe in piedi la composizione locale"
            );
        }

        // E il solo costruttore prende cio' che Telegram ha restituito.
        let blocco = blocco_di("impl MessageLink {");
        assert!(
            blocco.contains("pub fn from_telegram(url: &str"),
            "il costruttore deve prendere l'indirizzo restituito da Telegram"
        );
        for altro in ["pub fn of(", "pub fn new(", "pub const fn new("] {
            assert!(
                !blocco.contains(altro),
                "«{altro}» sarebbe un secondo modo di ottenere un collegamento"
            );
        }
    }

    /// **Il collegamento alla fonte non è quello al messaggio, e non lo diventa.**
    ///
    /// Nessuna conversione, in nessuna direzione: chi consegna un rapporto deve
    /// poter dire quale dei due stia citando.
    #[test]
    fn la_fonte_e_il_messaggio_non_si_convertono_l_uno_nell_altro() {
        let produzione = codice_senza_commenti();

        for conversione in [
            "impl From<SourceLink> for MessageLink",
            "impl From<MessageLink> for SourceLink",
            "fn into_message_link",
            "fn into_source_link",
            "fn as_message_link",
        ] {
            assert!(
                !produzione.contains(conversione),
                "«{conversione}» permetterebbe di scambiare i due collegamenti"
            );
        }
    }

    /// Il collegamento che Telegram fornisce si accetta e si conserva.
    #[test]
    fn il_collegamento_fornito_da_telegram_si_accetta() {
        let Some(link) = MessageLink::from_telegram("https://t.me/canale/42", true) else {
            panic!("un collegamento Telegram valido deve essere accettato");
        };

        assert_eq!(link.as_str(), "https://t.me/canale/42");
        assert!(link.is_public());
        assert!(link.as_sentence().contains("si apre per chiunque"));
    }

    /// **Un collegamento non pubblico lo dichiara.**
    ///
    /// In un rapporto, un indirizzo che il destinatario non può aprire è peggio
    /// di un indirizzo assente: sembra una prova verificabile e non lo è.
    #[test]
    fn un_collegamento_non_pubblico_lo_dichiara() {
        let Some(link) = MessageLink::from_telegram("https://t.me/c/1234567890/1", false) else {
            panic!("il collegamento deve essere accettato");
        };

        assert!(!link.is_public());
        let frase = link.as_sentence();
        assert!(frase.contains("Non \u{e8} pubblico"), "{frase}");
        assert!(frase.contains("membro di quella conversazione"), "{frase}");
    }

    /// Un indirizzo che non è di Telegram non si accetta.
    #[test]
    fn un_indirizzo_che_non_e_di_telegram_non_si_accetta() {
        assert_eq!(
            MessageLink::from_telegram("https://esempio.invalid/42", true),
            None
        );
        assert_eq!(
            MessageLink::from_telegram("http://t.me/canale/42", true),
            None
        );
        assert_eq!(MessageLink::from_telegram("", true), None);
        assert_eq!(MessageLink::from_telegram("https://t.me/", true), None);
    }

    /// **Uno spazio o un carattere di controllo non passano.**
    ///
    /// L'indirizzo finisce in un `ContentUrl` e, da lì, nel browser
    /// dell'operatore (ADR-0018): sparirebbe in silenzio a valle, o peggio.
    #[test]
    fn uno_spazio_o_un_carattere_di_controllo_non_passano() {
        assert_eq!(
            MessageLink::from_telegram("https://t.me/canale/4 2", true),
            None
        );
        assert_eq!(
            MessageLink::from_telegram("https://t.me/canale\n/42", true),
            None,
            "un a capo IN MEZZO non e' uno spazio ai bordi"
        );
        assert_eq!(
            MessageLink::from_telegram("https://t.me/canale\u{7}/42", true),
            None
        );
        assert_eq!(
            MessageLink::from_telegram("https://t.me/canale\"/42", true),
            None
        );
    }

    /// Gli spazi ai bordi si tolgono: sono della risposta, non dell'indirizzo.
    #[test]
    fn gli_spazi_ai_bordi_si_tolgono() {
        let Some(link) = MessageLink::from_telegram("  https://t.me/canale/42  ", true) else {
            panic!("il collegamento deve essere accettato");
        };
        assert_eq!(link.as_str(), "https://t.me/canale/42");
    }

    /// **Un esito negativo non porta alcun indirizzo.**
    ///
    /// Un esito che portasse comunque una stringa sarebbe l'invito a usarla.
    #[test]
    fn un_esito_negativo_non_porta_alcun_indirizzo() {
        let esito = LinkOutcome::NotProvided(LinkGap::NotOfferedByTelegram);
        assert_eq!(esito.link(), None);

        let blocco = blocco_di("pub enum LinkOutcome {");
        assert!(
            !blocco.contains("url"),
            "la variante negativa non deve poter portare un indirizzo"
        );
    }

    /// **Le quattro ragioni sono quattro, e dicono cose diverse.**
    #[test]
    fn le_quattro_ragioni_dicono_cose_diverse() {
        let frasi = [
            LinkGap::NotOfferedByTelegram.as_sentence(),
            LinkGap::Refused {
                code: 400,
                message: String::from("MESSAGE_ID_INVALID"),
            }
            .as_sentence(),
            LinkGap::NoAnswer { waited_ms: 5_000 }.as_sentence(),
            LinkGap::ConnectorUnavailable.as_sentence(),
        ];

        for frase in &frasi {
            assert_eq!(
                frasi.iter().filter(|altra| *altra == frase).count(),
                1,
                "due ragioni non possono dire la stessa cosa: «{frase}»"
            );
            // OGNI ragione indica il ripiego, che e' aprire la fonte.
            assert!(frase.contains("Resta la fonte"), "{frase}");
            assert!(frase.contains("non al messaggio"), "{frase}");
        }
    }

    /// **Nessuna risposta non è «il collegamento non esiste».**
    #[test]
    fn nessuna_risposta_non_e_il_collegamento_non_esiste() {
        let frase = LinkGap::NoAnswer { waited_ms: 5_000 }.as_sentence();

        assert!(
            frase.contains("Non significa che il collegamento non esista"),
            "{frase}"
        );
    }

    /// Il collegamento alla fonte si compone dal nome pubblico, e lo dichiara.
    #[test]
    fn il_collegamento_alla_fonte_apre_il_canale_e_lo_dice() {
        let Some(fonte) = SourceLink::of("@canale_di_prova") else {
            panic!("il collegamento alla fonte deve comporsi");
        };

        assert_eq!(fonte.as_str(), "https://t.me/canale_di_prova");
        let frase = fonte.as_sentence();
        assert!(frase.contains("Collegamento alla fonte"), "{frase}");
        assert!(frase.contains("non il messaggio"), "{frase}");
    }

    /// Una fonte senza nome pubblico non ha un collegamento.
    #[test]
    fn una_fonte_senza_nome_pubblico_non_ha_collegamento() {
        assert_eq!(SourceLink::of(""), None);
        assert_eq!(SourceLink::of("@"), None);
        assert_eq!(SourceLink::of("   "), None);
        // Un identificativo numerico non e' un nome pubblico utilizzabile in un
        // indirizzo: -1001234567890 non apre nulla.
        assert_eq!(SourceLink::of("-1001234567890"), None);
        assert_eq!(SourceLink::of("nome con spazi"), None);
        assert_eq!(SourceLink::of("nome/con/barre"), None);
    }
}

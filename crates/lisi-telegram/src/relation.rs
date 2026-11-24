//! A che cosa un messaggio si lega, **secondo Telegram**.
//!
//! Un messaggio non sta mai da solo: risponde a un altro, è stato inoltrato da
//! altrove, appartiene a una discussione, è stato modificato dopo la
//! pubblicazione. Il congelamento chiede che queste relazioni si vedano —
//! «risposta, inoltro e origine dell'inoltro, argomento/thread, autore, nome
//! utente, istante, stato di modifica, stato di cancellazione osservato».
//!
//! # La prima garanzia: una relazione è un puntatore, non un contenuto
//!
//! [`ReplyTo`] è `Copy`. Non è una scelta di stile: un tipo `Copy` **non può
//! contenere un testo**, perché una `String` non è `Copy` e il progetto non
//! compilerebbe più.
//!
//! È la difesa contro la cosa più naturale che qualcuno vorrebbe fare qui:
//! mostrare, accanto alla prova, il testo *attuale* del messaggio a cui essa
//! risponde. Quel testo verrebbe letto **adesso**, potrebbe essere stato
//! riscritto dopo, e finirebbe a due centimetri da un contenuto acquisito e
//! immutabile. Il congelamento lo vieta: «lo stato remoto corrente non
//! sostituisce mai in silenzio la prova storica».
//!
//! Qui la relazione dice **a quale messaggio** si risponde. Che cosa dicesse
//! quel messaggio è un'altra domanda, e ha un'altra risposta.
//!
//! # La seconda garanzia: chi si è nascosto resta nascosto
//!
//! Quando qualcuno inoltra un messaggio da un mittente che ha scelto di non
//! comparire, Telegram consegna **un nome da mostrare e nient'altro**: nessun
//! identificativo, di proposito. È una decisione di chi ha scritto, e il
//! prodotto la rispetta.
//!
//! [`ForwardOrigin::Hidden`] non ha alcun accessore che restituisca un
//! identificativo: [`ForwardOrigin::person_identifier`] dà `None`, e non esiste
//! una seconda strada. Attribuire quel messaggio a una persona sarebbe
//! un'attribuzione **inventata** in un archivio che ha valore probatorio.
//!
//! # La terza garanzia: niente di tutto questo entra nell'archivio
//!
//! Queste relazioni si leggono **adesso**, insieme al contorno, e non si
//! conservano. [`crate::IncomingMessage`] — il tipo che attraversa
//! l'acquisizione e diventa un contenuto archiviato — non ha alcun campo di
//! relazione, e una prova lo verifica elencandone i campi.
//!
//! Non è una dimenticanza: è la stessa regola di LINK-01. Si conserva ciò che
//! la fonte ha detto **al momento in cui lo si è acquisito**, non ciò che dice
//! oggi. Che cosa valga la pena fotografare lo deciderà CTX-06, che avrà la
//! fotografia esplicita con provenienza e integrità.
//!
//! # Che cosa questo modulo NON dice
//!
//! **Il nome dell'argomento.** Telegram consegna l'identificativo della
//! discussione; il titolo richiede un'altra richiesta con risposta da
//! correlare. Un identificativo senza titolo è poco, ma è vero.
//!
//! **Che un messaggio sia stato cancellato.** Un messaggio che non torna può
//! essere stato cancellato, o essere fuori dalla finestra, o non essere
//! visibile a questo account. Quella distinzione la fa il servizio del
//! contesto, e la fa dicendo che cosa ha osservato — non che cosa è successo.

use lisi_core::Timestamp;

use crate::identifier::{ChatId, MessageId};

/// Il messaggio a cui questo risponde.
///
/// # Perché è `Copy`, e perché conta
///
/// Perché un tipo `Copy` non può contenere una `String`. Il giorno in cui
/// qualcuno aggiungesse qui il testo del messaggio a cui si risponde — la cosa
/// più naturale del mondo, e la più sbagliata — **il progetto non
/// compilerebbe**.
///
/// È una garanzia più forte di una prova: una prova dice che qualcosa è andato
/// storto dopo che è stato scritto; questo impedisce di scriverlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyTo {
    /// La conversazione, quando la risposta attraversa due conversazioni.
    ///
    /// `None` significa «la stessa di questo messaggio», che è il caso
    /// ordinario.
    chat_id: Option<ChatId>,
    /// Il messaggio a cui si risponde.
    message_id: MessageId,
}

impl ReplyTo {
    /// Una risposta a un messaggio della **stessa** conversazione.
    #[must_use]
    pub const fn in_the_same_conversation(message_id: MessageId) -> Self {
        Self {
            chat_id: None,
            message_id,
        }
    }

    /// Una risposta a un messaggio di **un'altra** conversazione.
    ///
    /// Telegram lo permette, ed è una relazione diversa: il messaggio a cui si
    /// risponde non sta nel contorno che si sta guardando, e cercarvelo sarebbe
    /// cercarlo dove non è.
    #[must_use]
    pub const fn in_another_conversation(chat_id: ChatId, message_id: MessageId) -> Self {
        Self {
            chat_id: Some(chat_id),
            message_id,
        }
    }

    /// Il messaggio a cui si risponde.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.message_id
    }

    /// L'altra conversazione, quando la risposta la attraversa.
    #[must_use]
    pub const fn other_conversation(self) -> Option<ChatId> {
        self.chat_id
    }

    /// Che relazione è, detta a chi legge.
    #[must_use]
    pub fn as_sentence(self) -> String {
        match self.chat_id {
            None => format!(
                "In risposta al messaggio {} di questa conversazione.",
                self.message_id.get()
            ),
            Some(chat) => format!(
                "In risposta al messaggio {} di un'altra conversazione ({}): non sta in questo \
                 contorno.",
                self.message_id.get(),
                chat.get()
            ),
        }
    }
}

/// Da dove viene un messaggio inoltrato, **quando Telegram lo dichiara**.
///
/// # Perché un mittente nascosto è una variante a sé
///
/// Perché non è «un mittente di cui non conosciamo l'identificativo»: è un
/// mittente che **ha scelto** di non mostrarlo, e Telegram consegna di
/// proposito soltanto un nome da esporre. Trattarlo come gli altri
/// inviterebbe, prima o poi, a colmare il vuoto — e colmarlo sarebbe inventare
/// un'attribuzione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardOrigin {
    /// Una persona, con l'identificativo che Telegram dichiara.
    Person {
        /// L'identificativo presso Telegram.
        identifier: String,
    },
    /// Un canale, e il messaggio d'origine quando c'è.
    Channel {
        /// La conversazione d'origine.
        chat_id: ChatId,
        /// Il messaggio d'origine, quando Telegram lo dichiara.
        message_id: Option<MessageId>,
    },
    /// Un gruppo.
    Chat {
        /// La conversazione d'origine.
        chat_id: ChatId,
    },
    /// Un mittente che ha scelto di non mostrarsi.
    ///
    /// **Porta un nome, non un'identità.** Il nome è ciò che quella persona ha
    /// deciso di far vedere: chiunque può sceglierne uno uguale a quello di
    /// qualcun altro.
    Hidden {
        /// Il nome che Telegram mostra al posto del mittente.
        shown_name: String,
    },
}

impl ForwardOrigin {
    /// L'identificativo della **persona** d'origine, quando Telegram lo dice.
    ///
    /// # Perché un mittente nascosto dà `None`
    ///
    /// Perché non ne esiste uno da dare. Chi ha inoltrato quel messaggio ha
    /// scelto di non mostrarsi, e il nome esposto non è un identificativo:
    /// non è unico, non è stabile, e non appartiene a nessuno in modo
    /// verificabile.
    ///
    /// **Non esiste un secondo accessore** che restituisca qualcosa in quel
    /// caso: è il punto di questa funzione.
    #[must_use]
    pub fn person_identifier(&self) -> Option<&str> {
        match self {
            Self::Person { identifier } => Some(identifier.as_str()),
            Self::Channel { .. } | Self::Chat { .. } | Self::Hidden { .. } => None,
        }
    }

    /// La conversazione d'origine, quando l'origine è una conversazione.
    #[must_use]
    pub const fn conversation(&self) -> Option<ChatId> {
        match self {
            Self::Channel { chat_id, .. } | Self::Chat { chat_id } => Some(*chat_id),
            Self::Person { .. } | Self::Hidden { .. } => None,
        }
    }

    /// Da dove viene, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Person { identifier } => {
                format!("Inoltrato da un messaggio della persona {identifier}.")
            }
            Self::Channel {
                chat_id,
                message_id: Some(message),
            } => format!(
                "Inoltrato dal messaggio {} del canale {}.",
                message.get(),
                chat_id.get()
            ),
            Self::Channel {
                chat_id,
                message_id: None,
            } => format!("Inoltrato dal canale {}.", chat_id.get()),
            Self::Chat { chat_id } => format!("Inoltrato dalla conversazione {}.", chat_id.get()),
            Self::Hidden { shown_name } => format!(
                "Inoltrato da un mittente che ha scelto di non mostrarsi, e che Telegram indica \
                 come «{shown_name}»: \u{e8} un nome, non un'identit\u{e0}."
            ),
        }
    }
}

/// Che questo messaggio è stato inoltrato, e da dove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarded {
    /// Da dove, quando Telegram lo dichiara in una forma riconoscibile.
    ///
    /// `None` non significa «da nessuna parte»: significa che Telegram ha detto
    /// che il messaggio è un inoltro senza dire, in una forma che questo
    /// prodotto sappia leggere, da dove.
    origin: Option<ForwardOrigin>,
    /// Quando il messaggio d'origine era stato pubblicato, se dichiarato.
    published_at: Option<Timestamp>,
}

impl Forwarded {
    /// Un inoltro con l'origine che Telegram ha dichiarato.
    #[must_use]
    pub const fn new(origin: Option<ForwardOrigin>, published_at: Option<Timestamp>) -> Self {
        Self {
            origin,
            published_at,
        }
    }

    /// Da dove viene, quando si sa.
    #[must_use]
    pub const fn origin(&self) -> Option<&ForwardOrigin> {
        self.origin.as_ref()
    }

    /// Quando l'originale era stato pubblicato, quando è dichiarato.
    #[must_use]
    pub const fn published_at(&self) -> Option<Timestamp> {
        self.published_at
    }

    /// Che cosa si sa dell'inoltro, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let da_dove = self.origin.as_ref().map_or_else(
            || {
                String::from(
                    "Inoltrato: Telegram non ha dichiarato da dove in una forma leggibile.",
                )
            },
            ForwardOrigin::as_sentence,
        );

        match self.published_at {
            None => da_dove,
            Some(quando) => format!(
                "{da_dove} L'originale risulta pubblicato il {}.",
                quando.to_readable_utc()
            ),
        }
    }
}

/// La discussione a cui un messaggio appartiene.
///
/// # Perché soltanto un identificativo
///
/// Perché il titolo dell'argomento non sta nel messaggio: richiede un'altra
/// richiesta a Telegram, con risposta da correlare. Un identificativo senza
/// titolo dice poco, ma dice il vero — e permette di riconoscere che due
/// messaggi appartengono alla stessa discussione, che è la domanda che il
/// contorno pone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thread {
    identifier: i64,
}

impl Thread {
    /// La discussione con l'identificativo dichiarato.
    ///
    /// Rifiuta lo zero, che in TDLib significa «nessuna discussione»: un
    /// [`Thread`] esiste solo se ce n'è davvero una.
    #[must_use]
    pub const fn new(identifier: i64) -> Option<Self> {
        if identifier == 0 {
            return None;
        }
        Some(Self { identifier })
    }

    /// L'identificativo della discussione.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        self.identifier
    }

    /// A che discussione appartiene, detto a chi legge.
    #[must_use]
    pub fn as_sentence(self) -> String {
        format!(
            "Appartiene alla discussione {} di questa conversazione. Il titolo dell'argomento non \
             \u{e8} stato chiesto.",
            self.identifier
        )
    }
}

/// Tutto ciò a cui un messaggio si lega, come Telegram lo dichiara adesso.
///
/// # Perché non sta in `IncomingMessage`
///
/// Perché [`crate::IncomingMessage`] è il tipo che attraversa l'acquisizione e
/// diventa un contenuto **archiviato**. Un campo aggiunto lì finirebbe nella
/// colonna dei fatti, accanto al testo acquisito e all'istante dichiarato dalla
/// fonte — e queste relazioni sono lette **adesso**, non al momento
/// dell'acquisizione.
///
/// Tenerle in un tipo separato non è pulizia: è l'impossibilità di confonderle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageRelations {
    /// A quale messaggio risponde, se risponde.
    pub reply_to: Option<ReplyTo>,
    /// Da dove è stato inoltrato, se lo è stato.
    pub forwarded: Option<Forwarded>,
    /// A quale discussione appartiene, se a una.
    pub thread: Option<Thread>,
    /// Quando è stato modificato dopo la pubblicazione, se lo è stato.
    ///
    /// È lo **stato di modifica** che il congelamento chiede. Riguarda il
    /// messaggio come si legge adesso: che il contenuto acquisito sia stato
    /// modificato dopo l'acquisizione è un'altra cosa, e la dice CTX-01.
    pub edited_at: Option<Timestamp>,
}

impl MessageRelations {
    /// Se non c'è alcuna relazione da mostrare.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.reply_to.is_none()
            && self.forwarded.is_none()
            && self.thread.is_none()
            && self.edited_at.is_none()
    }

    /// Le relazioni, dette a chi legge, in una frase sola.
    ///
    /// `None` quando non ce n'è nessuna: una riga vuota sotto un messaggio
    /// direbbe che si è guardato e non si è trovato, che qui non è il caso.
    #[must_use]
    pub fn as_sentence(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }

        let mut parti: Vec<String> = Vec::new();
        if let Some(risposta) = self.reply_to {
            parti.push(risposta.as_sentence());
        }
        if let Some(inoltro) = self.forwarded.as_ref() {
            parti.push(inoltro.as_sentence());
        }
        if let Some(discussione) = self.thread {
            parti.push(discussione.as_sentence());
        }
        if let Some(modificato) = self.edited_at {
            parti.push(format!(
                "Modificato dopo la pubblicazione, il {}.",
                modificato.to_readable_utc()
            ));
        }

        Some(parti.join(" "))
    }
}

/// Un messaggio del contorno: quello che Telegram mostra, e a che cosa si lega.
///
/// # Perché due campi e non uno
///
/// Perché il primo è il tipo che l'acquisizione conosce e che può diventare un
/// contenuto archiviato; il secondo è ciò che si è letto **adesso** e che non
/// si conserva. Metterli insieme in una struttura sola porterebbe le relazioni
/// dentro la porta dell'archivio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextMessage {
    /// Il messaggio, nella forma che tutto il prodotto conosce.
    pub message: crate::event::IncomingMessage,
    /// A che cosa si lega, secondo Telegram, adesso.
    pub relations: MessageRelations,
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::{ContextMessage, ForwardOrigin, Forwarded, MessageRelations, ReplyTo, Thread};
    use crate::identifier::{ChatId, MessageId};

    /// Questo modulo, per le guardie testuali.
    const THIS_MODULE: &str = include_str!("relation.rs");

    /// Il tipo che entra nell'archivio.
    const EVENT: &str = include_str!("event.rs");

    fn chat(raw: i64) -> ChatId {
        let Ok(chat) = ChatId::try_new(raw) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        chat
    }

    fn message(raw: i64) -> MessageId {
        let Ok(message) = MessageId::try_new(raw) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        message
    }

    /// **Una risposta non può portare un testo, e lo impone il compilatore.**
    ///
    /// # Perché questa prova non può fallire in esecuzione
    ///
    /// Perché non deve. Se qualcuno aggiungesse a [`ReplyTo`] il testo del
    /// messaggio a cui si risponde, `ReplyTo` smetterebbe di essere `Copy` e
    /// **questa riga non compilerebbe**. La prova non serve a diventare rossa:
    /// serve a dire, a chi legge, che il vincolo è del compilatore e non di una
    /// convenzione.
    #[test]
    fn una_risposta_non_puo_portare_un_testo() {
        const fn richiede_copy<T: Copy>() {}
        richiede_copy::<ReplyTo>();
        richiede_copy::<Thread>();
    }

    /// **Chi ha scelto di non mostrarsi non riceve un identificativo.**
    #[test]
    fn un_mittente_nascosto_non_diventa_una_persona() {
        let nascosto = ForwardOrigin::Hidden {
            shown_name: String::from("Anonimo"),
        };
        assert_eq!(nascosto.person_identifier(), None);
        assert_eq!(nascosto.conversation(), None);
        assert!(
            nascosto.as_sentence().contains("non un'identit"),
            "la frase deve dire che quel nome non identifica nessuno"
        );
    }

    /// **Una persona dichiarata da Telegram, invece, si legge.**
    #[test]
    fn una_persona_dichiarata_si_legge() {
        let persona = ForwardOrigin::Person {
            identifier: String::from("777000"),
        };
        assert_eq!(persona.person_identifier(), Some("777000"));
        assert_eq!(persona.conversation(), None);
    }

    /// **Un canale è una conversazione, non una persona.**
    #[test]
    fn un_canale_non_e_una_persona() {
        let canale = ForwardOrigin::Channel {
            chat_id: chat(-1_001),
            message_id: Some(message(42)),
        };
        assert_eq!(canale.person_identifier(), None);
        assert_eq!(canale.conversation(), Some(chat(-1_001)));
    }

    /// **Nessun accessore, in nessuna variante, restituisce un identificativo
    /// per un mittente nascosto.**
    ///
    /// La prova precedente guarda una variante; questa guarda il **tipo**:
    /// elenca gli accessori dichiarati e pretende che siano due, quelli che
    /// questo modulo ha esaminato. Un terzo aggiunto domani la fa fallire, e
    /// chi lo aggiunge deve dire che cosa restituisce per `Hidden`.
    #[test]
    fn il_tipo_non_ha_una_seconda_strada_verso_un_identificativo() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("impl ForwardOrigin {") else {
            panic!("l'implementazione deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("l'implementazione deve chiudersi");
        };
        let blocco = &produzione[inizio..inizio + fine];

        let accessori: Vec<&str> = blocco
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("pub fn ") || riga.starts_with("pub const fn "))
            .collect();
        assert_eq!(
            accessori.len(),
            3,
            "l'origine di un inoltro dichiara {} funzioni pubbliche invece di tre: chi ne \
             aggiunge una deve dire che cosa restituisce per un mittente nascosto \u{2014} {accessori:?}",
            accessori.len()
        );
    }

    /// **Il tipo che entra nell'archivio non ha alcun campo di relazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una relazione letta **adesso** finisca nella colonna dei fatti,
    /// accanto a un testo acquisito ieri. `IncomingMessage` è la porta
    /// dell'archivio: ciò che passa di lì diventa un contenuto conservato.
    ///
    /// Le relazioni si leggono al momento e non si conservano. Che cosa valga
    /// la pena fotografare lo deciderà CTX-06.
    #[test]
    fn il_tipo_che_entra_nell_archivio_non_porta_relazioni() {
        let Some(inizio) = EVENT.find("pub struct IncomingMessage {") else {
            panic!("il tipo dell'acquisizione deve esistere");
        };
        let Some(fine) = EVENT[inizio..].find("\n}\n") else {
            panic!("il tipo deve chiudersi");
        };
        let campi: Vec<&str> = EVENT[inizio..inizio + fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("pub ") && riga.contains(':'))
            .collect();
        assert!(!campi.is_empty(), "il tipo deve dichiarare dei campi");

        for campo in campi {
            for relazione in [
                "reply", "forward", "thread", "topic", "edit", "relation", "risposta", "inoltro",
            ] {
                assert!(
                    !campo.contains(relazione),
                    "il tipo che entra nell'archivio dichiara «{campo}»: una relazione letta \
                     adesso finirebbe nella colonna dei fatti, accanto a un testo acquisito \
                     prima"
                );
            }
        }
    }

    /// **Senza relazioni non c'è una frase.**
    #[test]
    fn senza_relazioni_non_si_scrive_una_riga_vuota() {
        assert_eq!(MessageRelations::default().as_sentence(), None);
        assert!(MessageRelations::default().is_empty());
    }

    /// **Le relazioni che ci sono si leggono tutte, in una frase sola.**
    #[test]
    fn le_relazioni_presenti_si_leggono_tutte() {
        let relazioni = MessageRelations {
            reply_to: Some(ReplyTo::in_the_same_conversation(message(7))),
            forwarded: Some(Forwarded::new(
                Some(ForwardOrigin::Channel {
                    chat_id: chat(-1_002),
                    message_id: None,
                }),
                Some(Timestamp::from_millis(1_700_000_000_000)),
            )),
            thread: Thread::new(99),
            edited_at: Some(Timestamp::from_millis(1_700_000_100_000)),
        };

        let Some(frase) = relazioni.as_sentence() else {
            panic!("con quattro relazioni la frase deve esserci");
        };
        assert!(frase.contains("In risposta al messaggio 7"), "{frase}");
        assert!(frase.contains("Inoltrato dal canale -1002"), "{frase}");
        assert!(frase.contains("discussione 99"), "{frase}");
        assert!(
            frase.contains("Modificato dopo la pubblicazione"),
            "{frase}"
        );
    }

    /// **Una risposta che attraversa due conversazioni lo dice.**
    ///
    /// # Perché conta
    ///
    /// Perché il messaggio a cui si risponde **non sta nel contorno** che si
    /// sta guardando. Chi legge cercherebbe una riga che non c'è, e non
    /// saprebbe perché.
    #[test]
    fn una_risposta_che_esce_dalla_conversazione_lo_dichiara() {
        let altrove = ReplyTo::in_another_conversation(chat(-1_003), message(5));
        assert_eq!(altrove.other_conversation(), Some(chat(-1_003)));
        assert!(
            altrove.as_sentence().contains("non sta in questo contorno"),
            "chi legge deve sapere perche' quella riga non c'e'"
        );
    }

    /// **Una discussione con identificativo zero non esiste.**
    ///
    /// In TDLib lo zero significa «nessuna discussione». Costruire un
    /// [`Thread`] da uno zero direbbe che ce n'è una.
    #[test]
    fn una_discussione_inesistente_non_si_costruisce() {
        assert_eq!(Thread::new(0), None);
        assert!(Thread::new(1).is_some());
    }

    /// **Un inoltro senza origine dichiarata non inventa un'origine.**
    #[test]
    fn un_inoltro_senza_origine_non_ne_inventa_una() {
        let inoltro = Forwarded::new(None, None);
        assert_eq!(inoltro.origin(), None);
        assert!(
            inoltro
                .as_sentence()
                .contains("non ha dichiarato da dove in una forma leggibile"),
            "la frase deve distinguere «non l'ha detto» da «non viene da nessuna parte»"
        );
    }

    /// **Il messaggio del contorno tiene le due cose in due campi.**
    #[test]
    fn il_messaggio_del_contorno_tiene_separate_le_due_cose() {
        let Some(inizio) = THIS_MODULE.find("pub struct ContextMessage {") else {
            panic!("il tipo deve esistere");
        };
        let Some(fine) = THIS_MODULE[inizio..].find("\n}\n") else {
            panic!("il tipo deve chiudersi");
        };
        let campi: Vec<&str> = THIS_MODULE[inizio..inizio + fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("pub ") && riga.contains(':'))
            .collect();
        assert_eq!(
            campi.len(),
            2,
            "il messaggio del contorno deve avere due campi: il messaggio e le relazioni \
             \u{2014} {campi:?}"
        );

        // E il tipo esiste davvero, con quei due campi.
        let costruito = ContextMessage {
            message: crate::event::IncomingMessage {
                chat_id: chat(-1_001),
                message_id: message(11),
                author: None,
                author_identifier: None,
                author_username: None,
                text: String::from("ciao"),
                published_at_millis: 1_700_000_000_000,
                url: None,
                attachment: None,
            },
            relations: MessageRelations::default(),
        };
        assert!(costruito.relations.is_empty());
    }
}

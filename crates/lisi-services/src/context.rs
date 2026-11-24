//! Che cosa c'era attorno a un messaggio — e che cosa **c'è adesso**.
//!
//! # Le due cose che questo modulo tiene separate
//!
//! Un contenuto nell'archivio è una **prova**: è stato acquisito in un certo
//! istante, con un certo testo, e non cambia. Ciò che Telegram mostra oggi
//! attorno a quel messaggio è un'altra cosa: è lo **stato corrente della
//! conversazione**, letto adesso, che può essere stato modificato, cancellato o
//! riscritto da chi lo ha pubblicato.
//!
//! Il congelamento lo chiede per esteso: «contesto acquisito ≠ contesto
//! corrente ... lo stato remoto corrente **non sostituisce mai in silenzio** la
//! prova storica». Ed è la stessa disciplina che il prodotto applica ovunque:
//! il dato originale, l'analisi automatica e la valutazione della persona
//! restano tre cose distinte.
//!
//! # La garanzia strutturale: ciò che si vede non può diventare ciò che è stato
//!
//! [`AnchorMessage`] viene **dall'archivio**; [`ObservedMessage`] viene **da
//! Telegram, adesso**. Sono due tipi diversi, senza alcuna conversione fra
//! loro: nessun `From`, nessun accessore che restituisca l'altro. Non si può
//! passare un messaggio osservato dove si attende la prova.
//!
//! È la forma di garanzia di REPLAY-01 — un'ipotesi non diventa un fatto — e di
//! LINK-01 — un collegamento composto non diventa uno fornito.
//!
//! # Guardare non scrive niente
//!
//! Questo servizio **legge** l'ancora dall'archivio e **legge** il contorno da
//! Telegram. Non scrive: né nell'archivio, né nell'audit. Il congelamento lo
//! dice per la milestone che verrà — «scorrere la vista **non** trasforma ciò
//! che si vede in prova operativa» (CTX-06) — e il modo di non tradirlo è non
//! avere, qui, alcun modo di scrivere.
//!
//! Una prova lo impone.
//!
//! # Il confronto, da CTX-05
//!
//! Fino a CTX-04 questo modulo teneva le due cose **una accanto all'altra**,
//! distinte e non mescolate, e non le confrontava: dirlo era compito di CTX-05,
//! che ha il modello per farlo.
//!
//! Ora quel modello esiste — [`lisi_core::model::context_state`] — e il
//! confronto si fa qui, ma **la nozione non è di questo modulo**: si chiama
//! `ContextComparison::between`, che riusa la relazione esatta di ADR-0051 e
//! pretende i due testi in **due tipi diversi**, così che non si possano
//! scambiare. Una seconda nozione di differenza scritta qui — anche un solo
//! `==` a mano — sarebbe la duplicazione che quella milestone esiste per
//! evitare, e una prova la cerca nel sorgente.
//!
//! # Che cosa questo modulo NON fa, e perché
//!
//! **Non conserva il confronto.** È un'osservazione fatta adesso, e rifarla
//! domani può dare un altro esito. Fotografarla è un gesto esplicito, ed è
//! CTX-06.

use lisi_core::model::context_state::{AcquiredText, ContextComparison, CurrentText};
use lisi_core::{ContentId, Timestamp};
use lisi_storage::Database;
use lisi_telegram::{ChatId, MessageId, TelegramConnector};

use crate::error::{ServiceError, ServiceResult};

/// Quanti messaggi si chiedono prima e dopo l'ancora, per volta.
///
/// # Perché un numero e non «tutti»
///
/// Perché il contesto si legge, e una pagina che non finisce non si legge. Il
/// congelamento chiede un **caricamento progressivo**: si comincia da una
/// finestra piccola, e chi vuole vedere oltre lo chiede.
///
/// **Venti prima e venti dopo**: abbastanza da capire di che cosa si parlava,
/// poco abbastanza da stare su uno schermo.
pub const DEFAULT_WINDOW: u32 = 20;

/// Quanti messaggi al massimo si possono chiedere per lato.
///
/// TDLib non consegna finestre arbitrariamente grandi, e una richiesta più
/// larga del massimo non ne otterrebbe di più: otterrebbe **meno**, senza
/// dirlo. Il limite è dichiarato e la richiesta si restringe da sé.
pub const MAX_WINDOW: u32 = 50;

/// Il messaggio scelto, **come l'archivio lo conserva**.
///
/// # Perché è un tipo a sé
///
/// Perché è la **prova**: acquisita in un certo istante, con un certo testo, e
/// immutabile. Un messaggio osservato adesso non può prenderne il posto, e il
/// modo di garantirlo è che non esista alcuna conversione fra i due tipi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorMessage {
    /// Quale contenuto dell'archivio.
    pub content_id: ContentId,
    /// Identificativo del messaggio presso Telegram.
    pub remote_message_id: String,
    /// Il testo **acquisito**, che non cambia.
    pub body: String,
    /// Istante dichiarato dalla fonte al momento dell'acquisizione.
    pub published_at: Timestamp,
    /// Istante in cui NEXUM lo ha acquisito.
    pub acquired_at: Timestamp,
}

impl AnchorMessage {
    /// Che cosa questo messaggio è, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Contenuto {} dell'archivio, acquisito il {}: \u{e8} la prova, e non cambia.",
            self.content_id.get(),
            self.acquired_at.to_readable_local()
        )
    }
}

/// Un messaggio del contorno, **come Telegram lo mostra adesso**.
///
/// # Perché non è una prova
///
/// Perché è stato letto ora, e ora è tutto ciò che se ne sa. Può essere stato
/// modificato dopo la pubblicazione, può sparire un istante dopo, e nessuno lo
/// ha acquisito con la disciplina con cui il prodotto acquisisce.
///
/// **Non esiste alcuna conversione verso [`AnchorMessage`]**, e non deve
/// esistere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedMessage {
    /// Identificativo del messaggio presso Telegram.
    pub remote_message_id: String,
    /// Il testo, come si legge adesso.
    pub text: String,
    /// Istante di pubblicazione dichiarato adesso.
    pub published_at: Timestamp,
    /// Se è il messaggio attorno a cui il contesto è stato chiesto.
    ///
    /// Anche quando lo è, **non sostituisce l'ancora**: sta accanto, e chi
    /// legge vede due righe invece di una che le fonde.
    pub is_anchor: bool,
    /// Chi lo ha scritto, **come Telegram lo dichiara adesso**, in una frase.
    ///
    /// # Perché c'è sempre una frase
    ///
    /// Perché una riga senza autore si legge come «scritto da nessuno», mentre
    /// il caso ordinario è un altro: nei canali il mittente **è il canale**, e
    /// non c'è una persona da nominare. La differenza fra «non lo si sa» e «non
    /// c'è» va detta, non lasciata a uno spazio bianco (ADR-0053).
    pub who: String,
    /// A che cosa si lega, in una frase sola: risposta, inoltro, discussione,
    /// modifica.
    ///
    /// `None` quando non si lega a nulla — che è diverso da una riga vuota.
    pub relations: Option<String>,
    /// Quando **Telegram dichiara** che il messaggio è stato modificato.
    ///
    /// # Perché questa, sola fra le relazioni, prosegue come struttura
    ///
    /// CTX-04 ha fermato la struttura al servizio: la schermata riceve frasi
    /// già composte, perché una schermata che ricevesse la struttura la
    /// ricomporrebbe a modo suo. La regola vale ancora, e questo campo non la
    /// viola: **non va a una schermata, va a un confronto**.
    ///
    /// CTX-05 deve distinguere «i testi differiscono e Telegram dichiara una
    /// modifica» da «i testi differiscono e Telegram non dichiara nulla». Sono
    /// due affermazioni diverse, e la seconda va detta senza insinuare nulla.
    /// Per distinguerle serve l'istante, non la frase che lo contiene:
    /// rileggerlo da una frase sarebbe analizzare un testo che noi stessi
    /// abbiamo scritto, ed è il modo in cui una nozione si duplica.
    ///
    /// Resta **ciò che Telegram dichiara**, e non ciò che si osserva: le due
    /// cose non si mescolano nemmeno nel nome del campo.
    pub declared_edit: Option<Timestamp>,
    /// Il genere dell'allegato, quando Telegram lo dichiara: «documento»,
    /// «foto». Serve alla riga di un messaggio senza testo (OBS-CONV-1).
    pub attachment_kind: Option<&'static str>,
}

impl ObservedMessage {
    /// Il testo da mostrare: quello del messaggio, oppure che cosa è un
    /// messaggio che non ne ha.
    ///
    /// # Perché non si lascia la riga vuota
    ///
    /// Un documento senza didascalia compariva come una riga bianca
    /// (FULL-OPERATIONAL-VALIDATION-01, OBS-CONV-1), che si legge «testo
    /// cancellato» o «errore». Il campo `text` resta quello di Telegram: lo
    /// confronta CTX-05, e una frase nostra al suo posto sarebbe una modifica
    /// inventata.
    #[must_use]
    pub fn text_to_show(&self) -> String {
        if !self.text.trim().is_empty() {
            return self.text.clone();
        }
        match self.attachment_kind {
            Some(genere) => {
                let mut lettere = genere.chars();
                let iniziale = lettere.next().map(|c| c.to_uppercase().collect::<String>());
                format!(
                    "{}{} senza testo.",
                    iniziale.unwrap_or_default(),
                    lettere.as_str()
                )
            }
            None => String::from("Messaggio senza testo: Telegram non dice che cosa contiene."),
        }
    }
}

/// Se il messaggio scelto è tornato fra quelli che Telegram mostra adesso.
///
/// # Perché non si chiama «cancellato»
///
/// Perché non si è osservata una cancellazione: si è osservato che un messaggio
/// **non è tornato**. Può essere stato rimosso da chi lo ha scritto, può non
/// essere più visibile a questo account, può essere caduto fuori dalla finestra
/// che Telegram ha deciso di consegnare.
///
/// Il congelamento chiede lo «stato di cancellazione **osservato**», e la
/// parola che conta è l'ultima. Un archivio che scrivesse «cancellato» dove ha
/// visto «assente» direbbe una cosa che non sa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorPresence {
    /// È tornato: Telegram lo mostra ancora.
    Returned,
    /// Non è tornato, pur essendo la finestra centrata su di esso.
    NotReturned,
}

impl AnchorPresence {
    /// Che cosa si è osservato, detto a chi legge.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::Returned => "Telegram mostra ancora questo messaggio nella conversazione.",
            Self::NotReturned => {
                "Telegram non ha restituito questo messaggio fra quelli attorno, pur avendo \
                 centrato la finestra su di esso. Non significa che sia stato cancellato. Pu\u{f2} \
                 essere stato rimosso, o non essere pi\u{f9} visibile a questo account. Oppure \
                 pu\u{f2} essere rimasto fuori dalla finestra consegnata. Ci\u{f2} che si \u{e8} \
                 osservato \u{e8} che non \u{e8} tornato \u{2014} il contenuto dell'archivio resta \
                 quello che \u{e8}."
            }
        }
    }
}

/// Perché il contorno non c'è.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextGap {
    /// Non c'era alcun collegamento attivo a Telegram a cui chiederlo.
    ConnectorUnavailable,
    /// Telegram non ha restituito alcun messaggio.
    ///
    /// **Non è «non c'era nulla attorno»**: è «non è arrivato nulla». La
    /// conversazione può essere stata svuotata, la richiesta rifiutata, o la
    /// risposta non arrivata: da qui non si distingue, e dirlo per certo
    /// sarebbe inventare.
    NothingReturned,
    /// La richiesta a Telegram è partita e **non è riuscita**: tempo scaduto,
    /// rete assente, fonte non più accessibile, accesso revocato (ADR-0151).
    ///
    /// **Non è «non è arrivato nulla»**: è «non si è potuto chiedere fino in
    /// fondo». Il perché lo dice la pagina della conversazione, che ha
    /// l'errore; qui si dice soltanto che il contorno manca per questo.
    RequestFailed,
    /// Il contenuto non porta identificativi con cui Telegram ritrovi il
    /// messaggio, e **a Telegram non si è chiesto nulla** (COLLAUDO-FIX-01,
    /// CU01-013, DEC-508).
    ///
    /// **Non è «non è arrivato nulla»**: dirlo scriverebbe una risposta che non
    /// c'è stata, e una fotografia la conserverebbe.
    NotAddressable,
}

impl ContextGap {
    /// Che cosa manca, detto a chi legge.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::ConnectorUnavailable => {
                "Non c'\u{e8} un collegamento attivo a Telegram: il contorno si legge al momento, \
                 e adesso non si pu\u{f2} leggere. Il contenuto dell'archivio resta quello che \u{e8}."
            }
            Self::NothingReturned => {
                "Telegram non ha restituito alcun messaggio attorno a questo. Non significa che \
                 non ce ne fossero: significa che non \u{e8} arrivato nulla. La conversazione \
                 pu\u{f2} essere stata svuotata, la richiesta rifiutata, o la risposta non \
                 arrivata."
            }
            Self::RequestFailed => {
                "La richiesta a Telegram non \u{e8} riuscita, e il contorno non si \u{e8} potuto \
                 leggere adesso. Il contenuto dell'archivio resta quello che \u{e8}."
            }
            Self::NotAddressable => {
                "Questo contenuto non porta i numeri con cui Telegram ritrova un messaggio: il \
                 contorno non si pu\u{f2} chiedere. Il contenuto dell'archivio resta quello che \
                 \u{e8}."
            }
        }
    }
}

/// Il contesto di un messaggio: la prova, e ciò che le sta attorno adesso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageContext {
    /// Il messaggio scelto, dall'archivio. **È la prova.**
    pub anchor: AnchorMessage,
    /// Ciò che Telegram mostra attorno, adesso. **Non è una prova.**
    ///
    /// Dal più vecchio al più recente: `getChatHistory` risponde in ordine
    /// inverso, e riordinare **una volta sola**, qui, è meglio che lasciare a
    /// ogni schermata il compito di ricordarsene.
    pub surrounding: Vec<ObservedMessage>,
    /// Quando il contorno è stato letto.
    pub observed_at: Timestamp,
    /// Perché il contorno non c'è, quando non c'è.
    pub gap: Option<ContextGap>,
    /// Se il messaggio scelto è tornato fra quelli che Telegram mostra.
    ///
    /// `None` quando non c'è alcun contorno: non avendo guardato nulla, non si
    /// è osservato nulla. **«Non misurato» non è «assente»** (ADR-0053).
    pub anchor_presence: Option<AnchorPresence>,
    /// In che relazione stanno la prova e ciò che Telegram mostra adesso.
    ///
    /// `None` quando il confronto **non è stato fatto**, e sono due i casi:
    /// non c'era contorno, oppure l'ancora non è tornata e non c'è nulla con
    /// cui confrontare. Non è «i testi coincidono»: quello è
    /// [`lisi_core::model::context_state::Divergence::None`], ed è un esito
    /// diverso (ADR-0053).
    pub comparison: Option<ContextComparison>,
}

impl MessageContext {
    /// Se il contorno è stato letto davvero.
    #[must_use]
    pub const fn has_surroundings(&self) -> bool {
        self.gap.is_none()
    }

    /// Se Telegram è stato chiesto e **ha risposto**, anche con niente.
    ///
    /// È ciò che una fotografia presuppone (DEC-508): conserva ciò che
    /// Telegram mostrava, e senza una risposta non c'è nulla che mostrasse.
    /// Ogni lacuna nuova deve dire da che parte sta: per questo non c'è un
    /// ramo `_`.
    #[must_use]
    pub const fn telegram_answered(&self) -> bool {
        match self.gap {
            None | Some(ContextGap::NothingReturned) => true,
            Some(
                ContextGap::ConnectorUnavailable
                | ContextGap::RequestFailed
                | ContextGap::NotAddressable,
            ) => false,
        }
    }

    /// Che cosa si sta guardando, e che cosa non è.
    ///
    /// # Perché la frase dice sempre che il contorno non è una prova
    ///
    /// Perché è l'unica cosa che distingue questa schermata da un archivio, e
    /// chi la guarda a lungo smette di ricordarsene. Il congelamento lo chiede
    /// per CTX-06; la frase lo dice già da qui.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let contorno = match (self.gap, self.surrounding.len()) {
            (Some(gap), _) => gap.as_sentence().to_owned(),
            (None, 0) => String::from(
                "Telegram non mostra alcun messaggio attorno a questo in questo momento.",
            ),
            (None, 1) => String::from("Telegram mostra un messaggio attorno a questo."),
            (None, quanti) => {
                format!("Telegram mostra {quanti} messaggi attorno a questo.")
            }
        };

        // Che il messaggio scelto sia tornato o no si dice **soltanto quando lo
        // si e' guardato**: senza contorno non c'e' osservazione, e tacere e'
        // l'unica cosa vera.
        let presenza = self.anchor_presence.map_or_else(String::new, |presenza| {
            format!(" {}", presenza.as_sentence())
        });

        // Il confronto si dice **soltanto quando e' stato fatto**. Tacere,
        // quando non c'e' nulla con cui confrontare, e' l'unica cosa vera:
        // «non e' stato confrontato» non e' «coincidono» (ADR-0053).
        let confronto = self.comparison.map_or_else(String::new, |confronto| {
            format!(" {}", confronto.as_sentence())
        });

        format!(
            "{} {contorno}{presenza}{confronto} Ci\u{f2} che si vede qui \u{e8} lo stato della \
             conversazione al {}: non \u{e8} una prova, e guardarlo non lo rende tale.",
            self.anchor.as_sentence(),
            self.observed_at.to_readable_local()
        )
    }
}

/// Legge il contesto di un contenuto dell'archivio.
///
/// # Che cosa legge, e da dove
///
/// L'**ancora** dall'archivio, che è la prova; il **contorno** da Telegram, che
/// è lo stato corrente. Le due cose restano separate: nessuna sostituisce
/// l'altra, e nessun tipo permette di scambiarle.
///
/// # Non scrive nulla
///
/// Né nell'archivio né nell'audit. Guardare un contesto non è un atto di cui
/// qualcuno risponda, e non trasforma in prova ciò che si vede.
///
/// # Errori
///
/// Restituisce un errore se la lettura dell'archivio non riesce, e
/// [`ServiceError::Connector`] se Telegram **rifiuta** la richiesta o il tempo
/// massimo scade: la pagina della conversazione ne fa
/// [`ContextGap::RequestFailed`] con il perché (ADR-0151). Una risposta
/// **vuota**, o un contenuto senza identificativi remoti utilizzabili, non è un
/// errore: è un contorno assente, e [`ContextGap`] dice quale.
pub fn read(
    database: &Database,
    connector: Option<&mut dyn TelegramConnector>,
    content_id: ContentId,
    before: u32,
    after: u32,
    now: Timestamp,
) -> ServiceResult<MessageContext> {
    let content = database.content(content_id)?;
    let source = database.source(content.source_id)?;

    let anchor = AnchorMessage {
        content_id,
        remote_message_id: content.remote_message_id.as_str().to_owned(),
        body: content.body.as_str().to_owned(),
        published_at: content.published_at,
        acquired_at: content.acquired_at,
    };

    let Some(connector) = connector else {
        return Ok(MessageContext {
            anchor,
            surrounding: Vec::new(),
            observed_at: now,
            anchor_presence: None,
            comparison: None,
            gap: Some(ContextGap::ConnectorUnavailable),
        });
    };

    // Gli identificativi remoti sono numeri, conservati come testo. Uno che non
    // si legge non e' un guasto dell'archivio: e' un contenuto che non si puo'
    // ritrovare su Telegram, e va detto invece di far fallire la lettura.
    // E va detto per quello che e': a Telegram non si chiede nulla, e
    // «non ha restituito niente» sarebbe una risposta mai avuta (CU01-013).
    let (Ok(chat_raw), Ok(message_raw)) = (
        source.identifier.as_str().parse::<i64>(),
        anchor.remote_message_id.parse::<i64>(),
    ) else {
        return Ok(MessageContext {
            anchor,
            surrounding: Vec::new(),
            observed_at: now,
            anchor_presence: None,
            comparison: None,
            gap: Some(ContextGap::NotAddressable),
        });
    };

    let (Ok(chat_id), Ok(around)) = (ChatId::try_new(chat_raw), MessageId::try_new(message_raw))
    else {
        return Ok(MessageContext {
            anchor,
            surrounding: Vec::new(),
            observed_at: now,
            anchor_presence: None,
            comparison: None,
            gap: Some(ContextGap::NotAddressable),
        });
    };

    let letti = connector
        .fetch_context(
            chat_id,
            around,
            before.min(MAX_WINDOW),
            after.min(MAX_WINDOW),
        )
        .map_err(ServiceError::Connector)?;

    if letti.is_empty() {
        return Ok(MessageContext {
            anchor,
            surrounding: Vec::new(),
            observed_at: now,
            anchor_presence: None,
            comparison: None,
            gap: Some(ContextGap::NothingReturned),
        });
    }

    let mut surrounding: Vec<ObservedMessage> = letti
        .into_iter()
        .map(|letto| observe(letto, message_raw))
        .collect();

    // `getChatHistory` risponde dal piu' recente al piu' vecchio. Si riordina
    // **una volta sola**, qui: lasciarlo a ogni schermata significherebbe che
    // la prima che se ne dimentica mostra la conversazione al contrario.
    surrounding.sort_by_key(|messaggio| messaggio.published_at.as_millis());

    // LO STATO DI CANCELLAZIONE **OSSERVATO**.
    //
    // La finestra era centrata sull'ancora: se non e' tornata, e' un fatto
    // osservato. Che cosa significhi non lo si sa, e la frase lo dice.
    let ancora_osservata = surrounding.iter().find(|messaggio| messaggio.is_anchor);
    let anchor_presence = Some(if ancora_osservata.is_some() {
        AnchorPresence::Returned
    } else {
        AnchorPresence::NotReturned
    });

    // IL CONFRONTO, E I DUE TIPI CHE NON SI POSSONO SCAMBIARE (CTX-05).
    //
    // `AcquiredText` viene dall'archivio, `CurrentText` da Telegram adesso.
    // Scambiarli non compilerebbe — ed e' l'unico modo in cui questo confronto
    // potrebbe mentire, perche' la relazione fra due testi dipende da quale sia
    // il primo: «e' stato aggiunto» e «e' stato accorciato» sono la stessa
    // coppia di testi nei due ordini.
    //
    // Se l'ancora non e' tornata non c'e' nulla con cui confrontare, e `None`
    // dice «non e' stato fatto» — che non e' «coincidono».
    let comparison = ancora_osservata.map(|osservata| {
        ContextComparison::between(
            AcquiredText::from_the_archive(anchor.body.as_str()),
            CurrentText::read_now(osservata.text.as_str()),
            anchor.acquired_at,
            now,
            osservata.declared_edit,
        )
    });

    Ok(MessageContext {
        anchor,
        surrounding,
        observed_at: now,
        gap: None,
        anchor_presence,
        comparison,
    })
}

/// Un messaggio letto adesso, come la vista lo mostra.
///
/// # Perché sta in una funzione sola
///
/// Perché la stessa conversione serve all'apertura e a ogni pagina caricata
/// dopo (ADR-0151): due conversioni scritte in due posti direbbero, il giorno
/// in cui una cambia, la stessa riga con due frasi diverse.
pub(crate) fn observe(letto: lisi_telegram::ContextMessage, anchor_raw: i64) -> ObservedMessage {
    ObservedMessage {
        is_anchor: letto.message.message_id.get() == anchor_raw,
        remote_message_id: letto.message.message_id.get().to_string(),
        who: chi_ha_scritto(&letto.message),
        // LA FRASE LA COMPONE IL SERVIZIO, NON LA SCHERMATA (DEC-252).
        //
        // Qui arriva una struttura; da qui esce una frase. La struttura
        // **non prosegue**: se proseguisse, prima o poi una schermata la
        // ricomporrebbe a modo suo, e due schermate direbbero la stessa
        // relazione con parole diverse.
        relations: letto.relations.as_sentence(),
        // L'ISTANTE, NON LA FRASE CHE LO CONTIENE.
        //
        // Serve al confronto di CTX-05, che deve distinguere «differiscono
        // e Telegram dichiara una modifica» da «differiscono e Telegram non
        // dichiara nulla». Rileggerlo dalla frase qui sopra significherebbe
        // analizzare un testo scritto da noi, ed e' il modo in cui una
        // nozione si duplica.
        declared_edit: letto.relations.edited_at,
        attachment_kind: letto
            .message
            .attachment
            .as_ref()
            .map(|allegato| allegato.kind.label()),
        text: letto.message.text,
        published_at: Timestamp::from_millis(letto.message.published_at_millis),
    }
}

/// Chi ha scritto un messaggio del contorno, detto a chi legge.
///
/// # Perché non restituisce `Option`
///
/// Perché uno spazio bianco al posto dell'autore si legge come «scritto da
/// nessuno». Il caso ordinario, in un canale, è che il mittente **sia il
/// canale**: non c'è una persona da nominare, e dirlo è diverso dal tacerlo.
///
/// # Perché lo username non basta
///
/// Perché uno username può essere rilasciato e ripreso da qualcun altro.
/// Compare perché serve a **ritrovare** una persona su Telegram oggi, e accanto
/// c'è l'identificativo numerico, che è ciò che regge nel tempo.
pub(crate) fn chi_ha_scritto(messaggio: &lisi_telegram::IncomingMessage) -> String {
    let nome = messaggio.author.as_deref().filter(|nome| !nome.is_empty());
    let username = messaggio
        .author_username
        .as_deref()
        .filter(|nome| !nome.is_empty());

    let Some(identificativo) = messaggio.author_identifier.as_deref() else {
        return String::from(
            "Telegram non dichiara una persona come mittente: nei canali il mittente \u{e8} il \
             canale stesso.",
        );
    };

    match (nome, username) {
        (Some(nome), Some(username)) => format!(
            "Scritto da {nome} (@{username}, identificativo {identificativo}). Lo username pu\u{f2} \
             cambiare; l'identificativo no."
        ),
        (Some(nome), None) => {
            format!("Scritto da {nome} (identificativo {identificativo}).")
        }
        (None, Some(username)) => format!(
            "Scritto da @{username} (identificativo {identificativo}). Lo username pu\u{f2} \
             cambiare; l'identificativo no."
        ),
        (None, None) => format!(
            "Scritto dalla persona con identificativo {identificativo}: Telegram non ne ha \
             dichiarato il nome."
        ),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{AcquisitionOrigin, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{Actor, ContentBody, DisplayName, RemoteMessageId, SourceIdentifier};
    use lisi_core::{ContentId, Timestamp};
    use lisi_storage::Database;
    use lisi_telegram::{
        AccessibleChat, AuthorizationState, ChatId, ClientParameters, ConnectionState,
        ConnectorEvent, ContextMessage, IncomingMessage, LinkGap, LinkOutcome, LoginCode,
        MessageId, MessageRelations, PhoneNumber, TelegramConnector, TelegramResult,
        TwoFactorPassword,
    };

    use lisi_core::model::content_history::VersionChange;
    use lisi_core::model::context_state::Divergence;

    use super::{AnchorPresence, ContextGap, MAX_WINDOW, read};
    use crate::analysis::{AnalysisService, NewContentDraft};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("context.rs");

    const ORA_ZERO: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Il codice di produzione senza i commenti.
    ///
    /// Rifiuta anche il codice messo **dopo** il blocco di prova: là sarebbe
    /// invisibile a ogni guardia di questo modulo (la lezione di LINK-01).
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

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

    /// Un connettore che risponde con i messaggi indicati.
    #[derive(Debug, Default)]
    struct ContornoFinto {
        risposta: Vec<ContextMessage>,
        /// Che cosa e' stato chiesto: per verificare la finestra.
        chiesto: Option<(i64, i64, u32, u32)>,
    }

    impl TelegramConnector for ContornoFinto {
        fn start(&mut self, _parameters: &ClientParameters) -> TelegramResult<()> {
            Ok(())
        }
        fn submit_phone_number(&mut self, _phone: &PhoneNumber) -> TelegramResult<()> {
            Ok(())
        }
        fn submit_code(&mut self, _code: &LoginCode) -> TelegramResult<()> {
            Ok(())
        }
        fn submit_password(&mut self, _password: &TwoFactorPassword) -> TelegramResult<()> {
            Ok(())
        }
        fn poll_event(
            &mut self,
            _timeout: std::time::Duration,
        ) -> TelegramResult<Option<ConnectorEvent>> {
            Ok(None)
        }
        fn accessible_chats(&mut self) -> TelegramResult<Vec<AccessibleChat>> {
            Ok(Vec::new())
        }
        fn fetch_history(
            &mut self,
            _chat_id: ChatId,
            _from_message_id: i64,
            _limit: u32,
        ) -> TelegramResult<Vec<IncomingMessage>> {
            Ok(Vec::new())
        }
        fn fetch_context(
            &mut self,
            chat_id: ChatId,
            around: MessageId,
            before: u32,
            after: u32,
        ) -> TelegramResult<Vec<ContextMessage>> {
            self.chiesto = Some((chat_id.get(), around.get(), before, after));
            Ok(self.risposta.clone())
        }
        fn message_link(
            &mut self,
            _chat_id: ChatId,
            _message_id: MessageId,
        ) -> TelegramResult<LinkOutcome> {
            Ok(LinkOutcome::NotProvided(LinkGap::ConnectorUnavailable))
        }
        fn authorization_state(&self) -> AuthorizationState {
            AuthorizationState::Ready
        }
        fn connection_state(&self) -> ConnectionState {
            ConnectionState::Online
        }
        fn shutdown(&mut self) -> TelegramResult<()> {
            Ok(())
        }
    }

    fn messaggio(id: i64, testo: &str, millis: i64) -> ContextMessage {
        messaggio_con(id, testo, millis, MessageRelations::default())
    }

    /// Un messaggio del contorno con le relazioni indicate.
    fn messaggio_con(
        id: i64,
        testo: &str,
        millis: i64,
        relations: MessageRelations,
    ) -> ContextMessage {
        let (Ok(chat_id), Ok(message_id)) = (ChatId::try_new(-1001), MessageId::try_new(id)) else {
            panic!("gli identificativi di prova devono essere validi");
        };
        ContextMessage {
            message: IncomingMessage {
                chat_id,
                message_id,
                author: None,
                author_identifier: None,
                author_username: None,
                text: testo.to_owned(),
                published_at_millis: millis,
                url: None,
                attachment: None,
            },
            relations,
        }
    }

    /// **Un vicino senza testo dice che cos'è** (OBS-CONV-1): un documento
    /// senza didascalia era una riga bianca. Il testo di Telegram resta vuoto,
    /// perché lo confronta CTX-05.
    #[test]
    fn un_vicino_senza_testo_dice_che_cos_e() {
        let mut letto = messaggio_con(7, "", 1_000, MessageRelations::default());
        letto.message.attachment = Some(Box::new(
            lisi_telegram::attachment::AttachmentDescriptor::of_kind(
                lisi_telegram::attachment::AttachmentKind::Document,
            ),
        ));
        let documento = super::observe(letto, 1);
        assert!(documento.text.is_empty());
        assert_eq!(documento.text_to_show(), "Documento senza testo.");

        let ignoto = super::observe(
            messaggio_con(8, "  ", 1_000, MessageRelations::default()),
            1,
        );
        assert!(ignoto.text_to_show().contains("Telegram non dice"));

        let scritto = super::observe(
            messaggio_con(9, "ciao", 1_000, MessageRelations::default()),
            1,
        );
        assert_eq!(scritto.text_to_show(), "ciao");
    }

    /// Un archivio con un contenuto acquisito, e il suo identificativo.
    fn archivio_con_contenuto() -> (Database, ContentId) {
        // L'identificativo della fonte e' quello di Telegram: un numero.
        archivio_con_contenuto_della_fonte("-1001")
    }

    /// Lo stesso archivio, con la fonte indicata come si vuole.
    fn archivio_con_contenuto_della_fonte(fonte: &str) -> (Database, ContentId) {
        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(title), Ok(label), Ok(attore)) = (
            SourceIdentifier::try_new(fonte),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: attore.clone(),
                active: true,
            },
            istante(ORA_ZERO),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: attore.clone(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            istante(ORA_ZERO),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new("500"),
            ContentBody::try_new("il testo acquisito, che non cambia"),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };

        let mut analysis = AnalysisService::new(database);
        let Ok(record) = analysis.analyse_and_record(
            &NewContentDraft {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body,
                url: None,
                published_at: istante(ORA_ZERO),
                acquired_at: istante(ORA_ZERO),
                origin: AcquisitionOrigin::Observed,
            },
            &lisi_core::model::dictionary::ResolvedDictionaryConfiguration::from_terms(Vec::new()),
            &attore,
            istante(ORA_ZERO),
        ) else {
            panic!("l'analisi deve riuscire");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto doveva essere registrato");
        };

        (analysis.into_database(), content_id)
    }

    /// **Ciò che si vede non può diventare ciò che è stato.**
    ///
    /// Nessuna conversione fra il messaggio dell'archivio e quello osservato
    /// adesso: non si può passare il secondo dove si attende il primo.
    #[test]
    fn cio_che_si_vede_non_puo_diventare_cio_che_e_stato() {
        let produzione = codice_senza_commenti();

        for conversione in [
            "impl From<ObservedMessage> for AnchorMessage",
            "impl From<AnchorMessage> for ObservedMessage",
            "fn into_anchor",
            "fn as_anchor",
            "fn into_observed",
        ] {
            assert!(
                !produzione.contains(conversione),
                "«{conversione}» permetterebbe di scambiare la prova con ciò che si vede"
            );
        }
    }

    /// **Guardare un contesto non scrive niente.**
    #[test]
    fn guardare_un_contesto_non_scrive_niente() {
        let produzione = codice_senza_commenti();

        for scrittura in [
            "insert_",
            "append_audit",
            "update_",
            "delete_",
            "save_",
            "&mut Database",
        ] {
            assert!(
                !produzione.contains(scrittura),
                "«{scrittura}»: guardare un contesto non è un atto di cui qualcuno risponda"
            );
        }
    }

    /// **Il contorno arriva, e l'ancora resta quella dell'archivio.**
    #[test]
    fn il_contorno_arriva_e_l_ancora_resta_quella_dell_archivio() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![
                messaggio(501, "il messaggio dopo", ORA_ZERO + 60_000),
                messaggio(500, "il testo COME SI LEGGE ADESSO", ORA_ZERO),
                messaggio(499, "il messaggio prima", ORA_ZERO - 60_000),
            ],
            chiesto: None,
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 3_600_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        // L'ANCORA E' QUELLA DELL'ARCHIVIO, non quella letta adesso.
        assert_eq!(contesto.anchor.body, "il testo acquisito, che non cambia");
        assert_eq!(contesto.surrounding.len(), 3);

        // E il messaggio con lo stesso identificativo sta ACCANTO, non al posto
        // suo: due righe, non una che le fonde.
        let Some(osservato) = contesto
            .surrounding
            .iter()
            .find(|messaggio| messaggio.is_anchor)
        else {
            panic!("l'ancora deve comparire anche nel contorno");
        };
        assert_eq!(osservato.text, "il testo COME SI LEGGE ADESSO");
        assert_ne!(osservato.text, contesto.anchor.body);
    }

    /// **Il contorno si legge dal più vecchio al più recente.**
    ///
    /// `getChatHistory` risponde al contrario, e riordinare una volta sola qui
    /// evita che la prima schermata che se ne dimentica mostri la
    /// conversazione all'indietro.
    #[test]
    fn il_contorno_si_legge_dal_piu_vecchio_al_piu_recente() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![
                messaggio(501, "dopo", ORA_ZERO + 60_000),
                messaggio(500, "ancora", ORA_ZERO),
                messaggio(499, "prima", ORA_ZERO - 60_000),
            ],
            chiesto: None,
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let testi: Vec<&str> = contesto
            .surrounding
            .iter()
            .map(|messaggio| messaggio.text.as_str())
            .collect();
        assert_eq!(testi, vec!["prima", "ancora", "dopo"]);
    }

    /// **Senza connettore il contesto lo dichiara, e l'archivio resta.**
    #[test]
    fn senza_connettore_il_contesto_lo_dichiara() {
        let (database, content_id) = archivio_con_contenuto();

        let Ok(contesto) = read(&database, None, content_id, 5, 5, istante(ORA_ZERO)) else {
            panic!("la lettura deve riuscire anche senza connettore");
        };

        assert_eq!(contesto.gap, Some(ContextGap::ConnectorUnavailable));
        assert!(!contesto.has_surroundings());
        assert!(contesto.surrounding.is_empty());
        // L'ancora c'e' comunque: e' nell'archivio.
        assert_eq!(contesto.anchor.body, "il testo acquisito, che non cambia");
        assert!(
            contesto.as_sentence().contains("resta quello che \u{e8}"),
            "{}",
            contesto.as_sentence()
        );
    }

    /// **Un contorno vuoto non è «non c'era nulla attorno».**
    #[test]
    fn un_contorno_vuoto_non_e_non_c_era_nulla_attorno() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto::default();

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO),
        ) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(contesto.gap, Some(ContextGap::NothingReturned));
        let frase = contesto.as_sentence();
        assert!(frase.contains("Non significa che"), "{frase}");
        assert!(frase.contains("non \u{e8} arrivato nulla"), "{frase}");
    }

    /// **Un contenuto che Telegram non saprebbe ritrovare non si dice «non
    /// restituito»** (COLLAUDO-FIX-01, CU01-013, DEC-508).
    ///
    /// Se gli identificativi non sono numeri, a Telegram non si chiede nulla:
    /// dire che «non ha restituito alcun messaggio» sarebbe scrivere una
    /// risposta che non c'è stata, e una fotografia la conserverebbe.
    #[test]
    fn un_contenuto_senza_identificativi_non_dice_che_telegram_non_ha_risposto() {
        let (database, content_id) = archivio_con_contenuto_della_fonte("@canale_di_prova");
        let mut connettore = ContornoFinto::default();

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO),
        ) else {
            panic!("la lettura deve riuscire");
        };

        assert!(
            connettore.chiesto.is_none(),
            "a Telegram non si chiede nulla"
        );
        assert_ne!(
            contesto.gap,
            Some(ContextGap::NothingReturned),
            "Telegram non è stato chiesto: non può non aver restituito nulla (CU01-013)"
        );
        assert_eq!(contesto.gap, Some(ContextGap::NotAddressable));
        assert!(!contesto.telegram_answered());
        let frase = contesto.as_sentence();
        assert!(!frase.contains("non ha restituito"), "{frase}");
    }

    /// **La frase dice sempre che ciò che si vede non è una prova.**
    ///
    /// È l'unica cosa che distingue questa schermata da un archivio, e chi la
    /// guarda a lungo smette di ricordarsene.
    #[test]
    fn la_frase_dice_sempre_che_cio_che_si_vede_non_e_una_prova() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![messaggio(499, "prima", ORA_ZERO - 60_000)],
            chiesto: None,
        };

        let con_contorno = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO),
        );
        let senza = read(&database, None, content_id, 5, 5, istante(ORA_ZERO));

        for esito in [con_contorno, senza] {
            let Ok(contesto) = esito else {
                panic!("la lettura deve riuscire");
            };
            let frase = contesto.as_sentence();
            assert!(frase.contains("non \u{e8} una prova"), "{frase}");
            assert!(frase.contains("guardarlo non lo rende tale"), "{frase}");
        }
    }

    /// **La finestra richiesta non supera il massimo dichiarato.**
    ///
    /// Una richiesta più larga non otterrebbe di più: otterrebbe meno, senza
    /// dirlo.
    #[test]
    fn la_finestra_richiesta_non_supera_il_massimo() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto::default();

        let Ok(_) = read(
            &database,
            Some(&mut connettore),
            content_id,
            10_000,
            10_000,
            istante(ORA_ZERO),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let Some((_, _, before, after)) = connettore.chiesto else {
            panic!("la richiesta doveva partire");
        };
        assert_eq!(before, MAX_WINDOW);
        assert_eq!(after, MAX_WINDOW);
    }

    /// La richiesta parte con la chat e il messaggio giusti.
    #[test]
    fn la_richiesta_parte_con_la_chat_e_il_messaggio_giusti() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto::default();

        let Ok(_) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            7,
            istante(ORA_ZERO),
        ) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(connettore.chiesto, Some((-1001, 500, 5, 7)));
    }

    /// **Le relazioni arrivano alla vista come una frase, non come una
    /// struttura.**
    ///
    /// # Perché la struttura si ferma qui
    ///
    /// Perché una schermata che riceve la struttura, prima o poi, la ricompone
    /// a modo suo — e due schermate direbbero la stessa relazione con parole
    /// diverse. È DEC-252: chi disegna riceve una frase già scritta.
    #[test]
    fn le_relazioni_arrivano_come_una_frase_gia_scritta() {
        let (database, content_id) = archivio_con_contenuto();
        let Ok(risposta_a) = MessageId::try_new(499) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let mut connettore = ContornoFinto {
            risposta: vec![
                messaggio_con(
                    500,
                    "l'ancora",
                    ORA_ZERO,
                    MessageRelations {
                        reply_to: Some(lisi_telegram::ReplyTo::in_the_same_conversation(
                            risposta_a,
                        )),
                        forwarded: None,
                        thread: None,
                        edited_at: Some(istante(ORA_ZERO + 60_000)),
                    },
                ),
                messaggio(499, "prima", ORA_ZERO - 60_000),
            ],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let Some(ancora) = contesto
            .surrounding
            .iter()
            .find(|messaggio| messaggio.is_anchor)
        else {
            panic!("l'ancora deve comparire fra i vicini");
        };
        let Some(frase) = ancora.relations.as_deref() else {
            panic!("le relazioni devono comporre una frase");
        };
        assert!(frase.contains("In risposta al messaggio 499"), "{frase}");
        assert!(
            frase.contains("Modificato dopo la pubblicazione"),
            "{frase}"
        );

        // E chi non ha relazioni non riceve una riga vuota.
        let Some(altro) = contesto
            .surrounding
            .iter()
            .find(|messaggio| !messaggio.is_anchor)
        else {
            panic!("il vicino deve esserci");
        };
        assert_eq!(altro.relations, None);
    }

    /// **Un messaggio di canale non risulta scritto da nessuno.**
    ///
    /// Uno spazio bianco al posto dell'autore si legge come «scritto da
    /// nessuno». Il caso ordinario è un altro, e va detto (ADR-0053).
    #[test]
    fn un_messaggio_di_canale_dice_perche_non_ha_un_autore() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![messaggio(500, "l'ancora", ORA_ZERO)],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        assert!(
            contesto.surrounding[0]
                .who
                .contains("il mittente \u{e8} il canale stesso"),
            "{}",
            contesto.surrounding[0].who
        );
    }

    /// **Una persona si legge con lo username e con l'identificativo, e la
    /// frase dice quale dei due regge.**
    #[test]
    fn una_persona_si_legge_con_cio_che_regge_nel_tempo() {
        let (database, content_id) = archivio_con_contenuto();
        let mut scritto_da_una_persona = messaggio(500, "l'ancora", ORA_ZERO);
        scritto_da_una_persona.message.author_identifier = Some(String::from("777000"));
        scritto_da_una_persona.message.author_username = Some(String::from("redazione"));

        let mut connettore = ContornoFinto {
            risposta: vec![scritto_da_una_persona],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let chi = contesto.surrounding[0].who.as_str();
        assert!(chi.contains("@redazione"), "{chi}");
        assert!(chi.contains("777000"), "{chi}");
        assert!(
            chi.contains("Lo username pu\u{f2} cambiare; l'identificativo no"),
            "chi legge deve sapere quale dei due regge \u{2014} {chi}"
        );
    }

    /// **Se l'ancora non torna, lo si dice come osservazione e non come
    /// cancellazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che un archivio con valore probatorio scriva «cancellato» dove ha visto
    /// «assente». Un messaggio che non torna può essere stato rimosso, può non
    /// essere più visibile a questo account, o può essere rimasto fuori dalla
    /// finestra consegnata: da qui non si distingue.
    #[test]
    fn un_ancora_che_non_torna_e_un_osservazione_non_una_cancellazione() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            // La finestra e' centrata su 500, e 500 non torna.
            risposta: vec![
                messaggio(499, "prima", ORA_ZERO - 60_000),
                messaggio(501, "dopo", ORA_ZERO + 60_000),
            ],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(
            contesto.anchor_presence,
            Some(AnchorPresence::NotReturned),
            "la finestra era centrata sull'ancora, e l'ancora non e' tornata"
        );

        let frase = contesto.as_sentence();
        assert!(
            frase.contains("non ha restituito questo messaggio"),
            "{frase}"
        );
        assert!(
            frase.contains("Non significa che sia stato cancellato"),
            "l'osservazione non e' una conclusione \u{2014} {frase}"
        );

        // E la prova resta quella che e'.
        assert_eq!(contesto.anchor.body, "il testo acquisito, che non cambia");
    }

    /// **Se l'ancora torna, lo si dice.**
    #[test]
    fn un_ancora_che_torna_risulta_presente() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![
                messaggio(499, "prima", ORA_ZERO - 60_000),
                messaggio(500, "l'ancora", ORA_ZERO),
            ],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(contesto.anchor_presence, Some(AnchorPresence::Returned));
    }

    /// **Senza contorno non si dice nulla sulla presenza dell'ancora.**
    ///
    /// Non avendo guardato, non si è osservato: «non misurato» non è «assente»
    /// (ADR-0053).
    #[test]
    fn senza_contorno_non_si_afferma_nulla_sulla_presenza() {
        let (database, content_id) = archivio_con_contenuto();

        let Ok(contesto) = read(&database, None, content_id, 5, 5, istante(ORA_ZERO)) else {
            panic!("la lettura deve riuscire anche senza connettore");
        };

        assert_eq!(
            contesto.anchor_presence, None,
            "senza aver guardato non si e' osservato nulla"
        );
        let frase = contesto.as_sentence();
        assert!(
            !frase.contains("non ha restituito questo messaggio"),
            "non aver guardato non e' aver visto un'assenza \u{2014} {frase}"
        );
    }

    /// **La frase del contesto non attribuisce un'intenzione a nessuno.**
    ///
    /// # Perché una guardia sul linguaggio, qui
    ///
    /// Perché questa è una vista su messaggi di persone, e le parole con cui la
    /// si descrive finiscono in un fascicolo. Un inoltro è un fatto; «ha
    /// diffuso» è un giudizio.
    #[test]
    fn le_frasi_di_questo_modulo_non_attribuiscono_intenzioni() {
        let codice = codice_senza_commenti();
        for parola in [
            "propagand",
            "diffus",
            "colpevol",
            "responsabil",
            "sospett",
            "pericolos",
            "malevol",
            "criminal",
            "estremis",
        ] {
            assert!(
                !codice.to_lowercase().contains(parola),
                "il modulo del contesto scrive «{parola}»: un inoltro e' un fatto, e \
                 descriverlo non e' giudicarlo"
            );
        }
    }

    /// **Se l'ancora torna con lo stesso testo, il confronto lo dice.**
    ///
    /// «Non è stato confrontato» e «è stato confrontato e coincide» sono due
    /// esiti diversi (ADR-0053).
    #[test]
    fn un_ancora_che_torna_identica_risulta_coincidente() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![messaggio(
                500,
                "il testo acquisito, che non cambia",
                ORA_ZERO,
            )],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let Some(confronto) = contesto.comparison else {
            panic!("con l'ancora tornata il confronto deve esserci");
        };
        assert_eq!(confronto.divergence(), Divergence::None);
        assert!(contesto.as_sentence().contains("coincidono"));
    }

    /// **Il confronto non scambia la prova con lo stato corrente.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Lo scambio dei due testi. Il compilatore lo rende impossibile da
    /// scrivere; questa prova verifica che **qui**, l'unico punto in cui i due
    /// tipi vengono costruiti, l'orientamento sia quello giusto.
    ///
    /// Se fossero scambiati, un messaggio a cui è stato **aggiunto** del testo
    /// risulterebbe **accorciato** — una frase che si legge benissimo e dice il
    /// contrario, in un archivio che finisce in un fascicolo.
    #[test]
    fn il_confronto_non_scambia_la_prova_con_lo_stato_corrente() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            // Telegram mostra ADESSO il testo acquisito piu' una coda.
            risposta: vec![messaggio(
                500,
                "il testo acquisito, che non cambia \u{2014} e una coda aggiunta dopo",
                ORA_ZERO,
            )],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let Some(confronto) = contesto.comparison else {
            panic!("il confronto deve esserci");
        };
        assert_eq!(
            confronto.change(),
            VersionChange::Appended,
            "e' stato AGGIUNTO del testo: se i due tipi fossero scambiati qui, \
             risulterebbe accorciato"
        );
    }

    /// **Una modifica dichiarata da Telegram si distingue da una differenza
    /// soltanto osservata.**
    #[test]
    fn una_modifica_dichiarata_arriva_fino_al_confronto() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![messaggio_con(
                500,
                "un testo del tutto diverso",
                ORA_ZERO,
                MessageRelations {
                    reply_to: None,
                    forwarded: None,
                    thread: None,
                    edited_at: Some(istante(ORA_ZERO + 60_000)),
                },
            )],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let Some(confronto) = contesto.comparison else {
            panic!("il confronto deve esserci");
        };
        assert!(
            matches!(confronto.divergence(), Divergence::Declared { .. }),
            "l'istante dichiarato da Telegram deve arrivare fino al confronto: {:?}",
            confronto.divergence()
        );
        assert!(
            contesto
                .as_sentence()
                .contains("Telegram dichiara una modifica il"),
            "{}",
            contesto.as_sentence()
        );
    }

    /// **Una differenza senza modifica dichiarata non accusa nessuno.**
    #[test]
    fn una_differenza_senza_modifica_dichiarata_non_accusa_nessuno() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![messaggio(500, "un testo del tutto diverso", ORA_ZERO)],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        let Some(confronto) = contesto.comparison else {
            panic!("il confronto deve esserci");
        };
        assert_eq!(confronto.divergence(), Divergence::Undeclared);

        let frase = contesto.as_sentence();
        assert!(frase.contains("non dichiara alcuna modifica"), "{frase}");
        assert!(
            frase.contains("Non significa che qualcuno abbia alterato qualcosa"),
            "{frase}"
        );
        assert!(
            frase.contains("Resta prova il testo dell'archivio"),
            "{frase}"
        );
    }

    /// **Se l'ancora non torna, il confronto non si fa e non si finge.**
    ///
    /// Non c'è nulla con cui confrontare. `None` dice «non è stato fatto», che
    /// non è «coincidono».
    #[test]
    fn senza_l_ancora_nel_contorno_il_confronto_non_si_fa() {
        let (database, content_id) = archivio_con_contenuto();
        let mut connettore = ContornoFinto {
            risposta: vec![
                messaggio(499, "prima", ORA_ZERO - 60_000),
                messaggio(501, "dopo", ORA_ZERO + 60_000),
            ],
            ..ContornoFinto::default()
        };

        let Ok(contesto) = read(
            &database,
            Some(&mut connettore),
            content_id,
            5,
            5,
            istante(ORA_ZERO + 120_000),
        ) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(contesto.comparison, None);
        let frase = contesto.as_sentence();
        assert!(
            !frase.contains("coincidono"),
            "non aver confrontato non e' aver trovato due testi uguali \u{2014} {frase}"
        );
    }

    /// **Senza connettore non si confronta nulla.**
    #[test]
    fn senza_connettore_il_confronto_non_esiste() {
        let (database, content_id) = archivio_con_contenuto();

        let Ok(contesto) = read(&database, None, content_id, 5, 5, istante(ORA_ZERO)) else {
            panic!("la lettura deve riuscire anche senza connettore");
        };

        assert_eq!(contesto.comparison, None);
        assert!(!contesto.as_sentence().contains("coincidono"));
    }

    /// **Il servizio non costruisce una seconda nozione di differenza.**
    ///
    /// # Perché una guardia testuale, qui
    ///
    /// Perché la seconda nozione non nasce come una funzione nuova: nasce come
    /// un `==` fra due corpi dentro una funzione che sembra fare altro. La
    /// relazione esatta esiste da CTX-01 (ADR-0051) e la usa
    /// `ContextComparison::between`: qui non se ne scrive un'altra.
    #[test]
    fn il_servizio_non_confronta_i_testi_di_testa_sua() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("ContextComparison::between("),
            "il confronto deve passare per il modello di CTX-05"
        );
        for artigianale in [
            "anchor.body ==",
            "anchor.body !=",
            "body == osservata",
            "text == anchor",
            ".text != anchor",
            "VersionChange::between(",
        ] {
            assert!(
                !codice.contains(artigianale),
                "il servizio confronta i testi con «{artigianale}»: sarebbe una seconda nozione \
                 accanto a quella di ADR-0051"
            );
        }
    }
}

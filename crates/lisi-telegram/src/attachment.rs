//! Gli allegati di un messaggio (ATTACH-01, ADR-0177).
//!
//! # Che cosa c'è
//!
//! - La **descrizione** di un allegato, letta all'acquisizione senza scaricare
//!   niente: il genere, e ciò che il mittente dichiara (nome, dimensione,
//!   tipo).
//! - La **lettura dei byte**, su richiesta (parte 2): un tratto sigillato,
//!   [`AttachmentReader`], che soltanto i connettori del prodotto
//!   implementano, e i due tetti.
//!
//! # Ciò che il mittente dichiara non è un fatto sul file
//!
//! Il nome e il tipo li sceglie chi pubblica. Un nome può contenere caratteri
//! di controllo, o i caratteri che invertono la direzione della scrittura e
//! fanno leggere un nome che finisce in `.pdf` dove c'è un `.exe`. Si tolgono, e si
//! dice che il nome è dichiarato. Il nome **non diventa mai il nome di un
//! file** (ADR-0177, decisione 7).

use crate::error::TelegramResult;

/// Il tetto di un allegato: 25 MiB. Oltre, non si scarica (ADR-0177,
/// decisione 5). Una costante del programma, non un'impostazione.
pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

/// Il tetto di tutti gli allegati conservati nell'archivio: 1 GiB.
pub const MAX_KEPT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

/// La risposta alla lettura dei byte di un allegato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentReply {
    /// I byte, non aperti.
    Fetched {
        /// I byte, così come Telegram li ha dati.
        bytes: Vec<u8>,
        /// Ciò che resta da sapere: la copia di TDLib che non si è fatta
        /// cancellare, per esempio. `None` quando non resta niente.
        leftover: Option<String>,
    },
    /// Telegram dice, prima del trasferimento, che l'allegato supera il tetto
    /// chiesto: non si è scaricato niente.
    TooLarge {
        /// La dimensione che Telegram dà.
        size: u64,
    },
    /// La lettura non ha dato i byte, e il perché: il messaggio non ha più un
    /// allegato, la dimensione non è nota, il file non si legge.
    NotRead(String),
    /// Telegram ha rifiutato: codice e messaggio così come sono.
    Refused {
        /// Il codice.
        code: i64,
        /// Il messaggio.
        message: String,
    },
}

/// La lettura dei byte di un allegato. **Sigillata** come
/// [`crate::lookup::OfficialLookup`]: la implementano soltanto i connettori
/// del prodotto.
pub trait AttachmentReader: crate::lookup::sealed::Sealed {
    /// Legge l'allegato del messaggio `message_id` della chat `chat_id`, se
    /// non supera `max_bytes`. Una lettura, mai ripetuta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore quando la lettura non è arrivata a una risposta:
    /// account non pronto, tempo scaduto, connettore arrestato. Un rifiuto
    /// **di Telegram** è una [`AttachmentReply::Refused`].
    fn fetch_attachment(
        &mut self,
        chat_id: i64,
        message_id: i64,
        max_bytes: u64,
    ) -> TelegramResult<AttachmentReply>;
}

/// Il tetto dei caratteri di un nome dichiarato.
pub const MAX_DECLARED_NAME_CHARS: usize = 255;

/// Il tetto dei caratteri di un tipo dichiarato.
pub const MAX_DECLARED_MIME_CHARS: usize = 100;

/// Il genere di un allegato, come Telegram lo dichiara.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachmentKind {
    /// Un documento: un file qualsiasi.
    Document,
    /// Una foto.
    Photo,
    /// Un video.
    Video,
    /// Un brano audio.
    Audio,
    /// Una nota vocale.
    VoiceNote,
    /// Un videomessaggio, il video tondo.
    VideoNote,
    /// Un'animazione.
    Animation,
    /// Un adesivo.
    Sticker,
}

impl AttachmentKind {
    /// Tutti i generi, nell'ordine in cui si elencano.
    pub const ALL: [Self; 8] = [
        Self::Document,
        Self::Photo,
        Self::Video,
        Self::Audio,
        Self::VoiceNote,
        Self::VideoNote,
        Self::Animation,
        Self::Sticker,
    ];

    /// La chiave dell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "documento",
            Self::Photo => "foto",
            Self::Video => "video",
            Self::Audio => "audio",
            Self::VoiceNote => "nota_vocale",
            Self::VideoNote => "videomessaggio",
            Self::Animation => "animazione",
            Self::Sticker => "adesivo",
        }
    }

    /// Il genere di una chiave dell'archivio.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|genere| genere.as_str() == key)
    }

    /// Il nome che si legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Document => "documento",
            Self::Photo => "foto",
            Self::Video => "video",
            Self::Audio => "audio",
            Self::VoiceNote => "nota vocale",
            Self::VideoNote => "videomessaggio",
            Self::Animation => "animazione",
            Self::Sticker => "adesivo",
        }
    }
}

/// La descrizione di un allegato: il genere e ciò che il mittente dichiara.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentDescriptor {
    /// Il genere.
    pub kind: AttachmentKind,
    /// Il nome dichiarato, ripulito: vedere [`clean_declared_name`].
    pub declared_name: Option<String>,
    /// La dimensione dichiarata, in byte. Assente quando Telegram non la dà.
    pub declared_size: Option<u64>,
    /// Il tipo dichiarato, ripulito: vedere [`clean_declared_mime`].
    pub declared_mime: Option<String>,
}

impl AttachmentDescriptor {
    /// Una descrizione con il solo genere.
    #[must_use]
    pub const fn of_kind(kind: AttachmentKind) -> Self {
        Self {
            kind,
            declared_name: None,
            declared_size: None,
            declared_mime: None,
        }
    }
}

/// Se il carattere cambia la direzione della scrittura, o è invisibile e
/// separa senza vedersi.
const fn is_deceptive_format_character(carattere: char) -> bool {
    matches!(
        carattere,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Un nome dichiarato ripulito: senza caratteri di controllo né caratteri che
/// cambiano la direzione della scrittura, spazi ai margini tolti, vuoto come
/// assente, troppo lungo troncato al tetto.
#[must_use]
pub fn clean_declared_name(name: &str) -> Option<String> {
    let senza: String = name
        .chars()
        .filter(|carattere| !carattere.is_control() && !is_deceptive_format_character(*carattere))
        .collect();
    let pulito = senza.trim();
    if pulito.is_empty() {
        return None;
    }
    Some(pulito.chars().take(MAX_DECLARED_NAME_CHARS).collect())
}

/// Un tipo dichiarato ripulito: in minuscolo, con i soli caratteri che un tipo
/// può avere. Un tipo con altri caratteri, vuoto o troppo lungo, è assente:
/// non si corregge un tipo, si scarta.
#[must_use]
pub fn clean_declared_mime(mime: &str) -> Option<String> {
    let minuscolo = mime.trim().to_ascii_lowercase();
    let ammesso =
        |carattere: char| carattere.is_ascii_alphanumeric() || "!#$&^_.+-/".contains(carattere);
    if minuscolo.is_empty()
        || minuscolo.len() > MAX_DECLARED_MIME_CHARS
        || !minuscolo.chars().all(ammesso)
        || minuscolo.matches('/').count() != 1
    {
        return None;
    }
    Some(minuscolo)
}

/// Una dimensione dichiarata: zero o negativa è «non dichiarata».
#[must_use]
pub fn declared_size(bytes: i64) -> Option<u64> {
    u64::try_from(bytes).ok().filter(|byte| *byte > 0)
}

#[cfg(test)]
mod tests {
    use super::{
        AttachmentKind, MAX_DECLARED_NAME_CHARS, clean_declared_mime, clean_declared_name,
        declared_size,
    };

    /// **Un nome che inverte la scrittura non inganna**: i caratteri di
    /// direzione e quelli di controllo si tolgono, e ciò che resta è ciò che
    /// c'è davvero.
    #[test]
    fn un_nome_che_inverte_la_scrittura_non_inganna() {
        assert_eq!(
            clean_declared_name("fattura\u{202E}fdp.exe").as_deref(),
            Some("fatturafdp.exe")
        );
        assert_eq!(
            clean_declared_name("  rapporto\u{0000}\u{200B}.docx\n ").as_deref(),
            Some("rapporto.docx")
        );
        assert_eq!(clean_declared_name(" \u{2066}\u{2069} "), None);
        let lungo = "a".repeat(MAX_DECLARED_NAME_CHARS + 10);
        assert_eq!(
            clean_declared_name(&lungo).map(|nome| nome.chars().count()),
            Some(MAX_DECLARED_NAME_CHARS)
        );
    }

    /// **Un tipo strano si scarta, non si corregge.**
    #[test]
    fn un_tipo_strano_si_scarta() {
        assert_eq!(
            clean_declared_mime(" Application/PDF ").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(clean_declared_mime("text/html; charset=utf-8"), None);
        assert_eq!(clean_declared_mime("pdf"), None);
        assert_eq!(clean_declared_mime("a/b/c"), None);
        assert_eq!(clean_declared_mime(""), None);
        assert_eq!(clean_declared_mime(&format!("a/{}", "b".repeat(200))), None);
    }

    /// **Una dimensione nulla non è dichiarata.**
    #[test]
    fn una_dimensione_nulla_non_e_dichiarata() {
        assert_eq!(declared_size(0), None);
        assert_eq!(declared_size(-5), None);
        assert_eq!(declared_size(2_048), Some(2_048));
    }

    /// **Ogni genere ha la sua chiave, e la chiave torna al genere.**
    #[test]
    fn ogni_genere_ha_la_sua_chiave() {
        for genere in AttachmentKind::ALL {
            assert_eq!(AttachmentKind::from_key(genere.as_str()), Some(genere));
        }
        let mut chiavi = AttachmentKind::ALL.map(AttachmentKind::as_str).to_vec();
        chiavi.sort_unstable();
        chiavi.dedup();
        assert_eq!(chiavi.len(), AttachmentKind::ALL.len());
        assert_eq!(AttachmentKind::from_key("eseguibile"), None);
    }
}

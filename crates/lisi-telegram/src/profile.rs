//! Foto, biografia e stato di un account di Telegram (PERSON-MEDIA-01,
//! ADR-0174).
//!
//! # Che cosa fa
//!
//! Chiede a Telegram, con le richieste ufficiali, ciò che rende visibile
//! all'account d'ufficio di **un** account già osservato, per il suo
//! identificativo numerico: la biografia, lo stato («in linea», «visto di
//! recente», …) e l'immagine piccola del profilo.
//!
//! # Che cosa non fa
//!
//! - Non cerca persone: parte da un identificativo, non da un nome.
//! - Non ripete: al più una lettura per genere, in sequenza, per gesto.
//! - Non guarda la foto: ne porta i byte e basta. Nessuna funzione di questa
//!   crate la decodifica, la confronta o ne estrae tratti (ADR-0174,
//!   decisione 5).

use crate::error::TelegramResult;

/// Il tetto dei byte di una foto: l'immagine piccola del profilo pesa pochi
/// kilobyte, e una risposta molto più grande non è quella che si è chiesta.
pub const MAX_PHOTO_BYTES: usize = 512 * 1024;

/// Il tetto dei caratteri di una biografia: Telegram ne ammette poche
/// centinaia, e una più lunga non è una biografia da credere.
pub const MAX_BIO_CHARS: usize = 1_000;

/// Lo stato di un account, **all'istante** della lettura, come Telegram lo
/// mostra all'account d'ufficio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileStatus {
    /// In linea.
    Online,
    /// Non in linea, con l'ultimo accesso che Telegram rende visibile.
    Offline {
        /// L'ultimo accesso, in millisecondi dall'epoca.
        was_online_millis: i64,
    },
    /// Visto di recente: le impostazioni di quella persona non dicono di più.
    Recently,
    /// Visto nell'ultima settimana.
    LastWeek,
    /// Visto nell'ultimo mese.
    LastMonth,
    /// Telegram non dice niente: non è «non attivo».
    NotShown,
}

impl ProfileStatus {
    /// La chiave dell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "in_linea",
            Self::Offline { .. } => "non_in_linea",
            Self::Recently => "di_recente",
            Self::LastWeek => "ultima_settimana",
            Self::LastMonth => "ultimo_mese",
            Self::NotShown => "non_mostrato",
        }
    }
}

/// Ciò che Telegram ha restituito per un account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileMedia {
    /// L'identificativo dell'account letto.
    pub user_id: i64,
    /// La biografia, se l'account ne ha una visibile.
    pub bio: Option<String>,
    /// Lo stato all'istante della lettura.
    pub status: ProfileStatus,
    /// I byte dell'immagine piccola del profilo, se ce n'è una visibile e si è
    /// potuta leggere. Non decodificati.
    pub photo: Option<Vec<u8>>,
    /// Perché la foto manca quando l'account ne ha una ma non si è letta
    /// (troppo grande, tempo scaduto, …): un'assenza spiegata non è «non ha
    /// foto».
    pub photo_not_read: Option<String>,
}

/// La risposta di Telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileMediaReply {
    /// Telegram ha restituito il profilo.
    Found(ProfileMedia),
    /// Telegram ha rifiutato: codice e messaggio così come sono.
    Refused {
        /// Il codice.
        code: i64,
        /// Il messaggio.
        message: String,
    },
}

/// La lettura di foto, biografia e stato. **Sigillata** come
/// [`crate::lookup::OfficialLookup`]: la implementano soltanto i connettori
/// del prodotto.
pub trait ProfileMediaReader: crate::lookup::sealed::Sealed {
    /// Legge foto, biografia e stato di `user_id`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore quando la lettura non è arrivata a una risposta:
    /// account non pronto, tempo scaduto, connettore arrestato. Un rifiuto
    /// **di Telegram** è una [`ProfileMediaReply::Refused`].
    fn read_profile_media(&mut self, user_id: i64) -> TelegramResult<ProfileMediaReply>;
}

/// Una biografia ripulita: spazi ai margini tolti, vuota come assente, troppo
/// lunga troncata al tetto.
#[must_use]
pub fn clean_bio(bio: &str) -> Option<String> {
    let pulita = bio.trim();
    if pulita.is_empty() {
        return None;
    }
    Some(pulita.chars().take(MAX_BIO_CHARS).collect())
}

#[cfg(test)]
mod tests {
    use super::{MAX_BIO_CHARS, ProfileStatus, clean_bio};

    #[test]
    fn una_biografia_vuota_e_assente_e_una_lunghissima_si_tronca() {
        assert_eq!(clean_bio("   "), None);
        assert_eq!(clean_bio("  Giornalista  ").as_deref(), Some("Giornalista"));
        let lunga = "a".repeat(MAX_BIO_CHARS + 50);
        assert_eq!(
            clean_bio(&lunga).map(|bio| bio.chars().count()),
            Some(MAX_BIO_CHARS)
        );
    }

    #[test]
    fn ogni_stato_ha_la_sua_chiave() {
        let chiavi = [
            ProfileStatus::Online,
            ProfileStatus::Offline {
                was_online_millis: 1,
            },
            ProfileStatus::Recently,
            ProfileStatus::LastWeek,
            ProfileStatus::LastMonth,
            ProfileStatus::NotShown,
        ]
        .map(ProfileStatus::as_str);
        let mut distinte = chiavi.to_vec();
        distinte.sort_unstable();
        distinte.dedup();
        assert_eq!(distinte.len(), chiavi.len());
    }
}

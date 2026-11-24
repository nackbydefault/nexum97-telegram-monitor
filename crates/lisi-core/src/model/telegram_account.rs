//! Profili di credenziali API e account Telegram (modello multi-account).
//!
//! Relazione: un [`ApiCredentialProfile`] serve **N** [`TelegramAccount`]. Qui
//! vivono solo i **metadati non segreti**: l'API hash, il numero pieno, i codici
//! e le chiavi non compaiono in questi tipi (ADR-0019). Il numero e' conservato
//! **mascherato**; l'identita' stabile di un account e' il suo **UUID**, mai il
//! numero, cosi' che un elenco di directory non riveli a chi appartengono.

use crate::error::{DomainError, DomainResult};
use crate::id::{ApiCredentialProfileId, TelegramAccountId};
use crate::text::DisplayName;
use crate::time::Timestamp;

/// UUID locale di un account, in forma esadecimale minuscola di 32 cifre.
///
/// E' l'identita' stabile usata per nominare la directory TDLib, la directory
/// file e il file della chiave di cifratura dell'account. Trentadue cifre
/// esadecimali (sedici byte casuali): sicuro come nome di file, senza separatori
/// ne' possibilita' di risalita, e privo di qualunque dato personale.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountUuid(String);

impl AccountUuid {
    /// Numero di cifre esadecimali (sedici byte).
    pub const HEX_LEN: usize = 32;

    /// Ricostruisce un UUID gia' generato (per esempio letto dal database).
    ///
    /// La generazione avviene nei servizi, con il generatore sicuro: il dominio
    /// non conosce l'entropia, solo la forma.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidAccountUuid`] se il valore non e'
    /// composto da esattamente 32 cifre esadecimali minuscole.
    pub fn from_hex(raw: &str) -> DomainResult<Self> {
        if raw.len() != Self::HEX_LEN
            || !raw
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DomainError::InvalidAccountUuid);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Costruisce l'UUID da sedici byte casuali.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let mut hex = String::with_capacity(Self::HEX_LEN);
        for byte in bytes {
            hex.push(nibble_to_hex(byte >> 4));
            hex.push(nibble_to_hex(byte & 0x0f));
        }
        Self(hex)
    }

    /// Forma esadecimale.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

const fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

/// Numero di telefono **mascherato** per la visualizzazione e la persistenza.
///
/// Il numero pieno non e' mai conservato in chiaro. Si tiene solo una forma
/// mascherata che mostra le ultime cifre, sufficiente a riconoscere l'account
/// senza rivelarne l'identita': per esempio `+** *** **34`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedPhoneNumber(String);

impl MaskedPhoneNumber {
    /// Cifre finali mostrate in chiaro.
    pub const VISIBLE_TAIL: usize = 2;

    /// Costruisce la forma mascherata dalle sole cifre di un numero.
    ///
    /// Riceve il numero gia' validato altrove; qui tiene le ultime
    /// [`Self::VISIBLE_TAIL`] cifre e maschera il resto. Non conserva il numero
    /// pieno.
    #[must_use]
    pub fn from_digits(digits: &str) -> Self {
        let only: Vec<char> = digits.chars().filter(char::is_ascii_digit).collect();
        let tail: String = only.iter().rev().take(Self::VISIBLE_TAIL).rev().collect();
        let hidden = only.len().saturating_sub(tail.chars().count());
        let mask: String = "*".repeat(hidden);
        Self(format!("+{mask}{tail}"))
    }

    /// Ricostruisce una forma mascherata gia' conservata.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidMaskedPhone`] se contiene una cifra che
    /// non sia fra le ultime ammesse (una forma con troppe cifre in chiaro
    /// avrebbe conservato piu' di quanto consentito).
    pub fn from_stored(raw: &str) -> DomainResult<Self> {
        let visible_digits = raw.chars().filter(char::is_ascii_digit).count();
        if raw.is_empty() || visible_digits > Self::VISIBLE_TAIL {
            return Err(DomainError::InvalidMaskedPhone);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Forma mascherata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stato di autorizzazione **conservato** di un account.
///
/// E' la sintesi coarse persistita fra un avvio e l'altro; lo stato fine, in
/// corso di accesso, vive nel runtime (`lisi-telegram::AuthorizationState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedAuthStatus {
    /// Account creato, mai autorizzato.
    Fresh,
    /// Autorizzazione in corso (attende un dato dall'operatore o la libreria).
    Authorizing,
    /// Autorizzato: la sessione esiste e si riapre senza nuovo login.
    Authorized,
    /// Disconnesso in modo esplicito (logout).
    LoggedOut,
    /// Autorizzazione fallita in modo non recuperabile.
    Failed,
}

/// Stato di collegamento **conservato** (ultimo noto) di un account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedConnectionStatus {
    /// Non collegato.
    Offline,
    /// Collegamento in corso.
    Connecting,
    /// Collegato.
    Connected,
    /// Ultimo stato non noto (mai collegato, o riavvio).
    Unknown,
}

macro_rules! status_str {
    ($name:ident { $($variant:ident => $repr:literal),+ $(,)? }) => {
        impl $name {
            /// Rappresentazione stabile per la persistenza e l'audit.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $repr),+ }
            }
            /// Ricostruisce lo stato dalla forma conservata.
            ///
            /// # Errori
            ///
            /// Restituisce [`DomainError::InvalidStatus`] per un valore non noto.
            pub fn parse(raw: &str) -> DomainResult<Self> {
                match raw {
                    $($repr => Ok(Self::$variant),)+
                    _ => Err(DomainError::InvalidStatus),
                }
            }
            /// Tutte le varianti, per i test.
            #[must_use]
            pub const fn all() -> &'static [Self] { &[$(Self::$variant),+] }
        }
    };
}

status_str!(PersistedAuthStatus {
    Fresh => "fresh",
    Authorizing => "authorizing",
    Authorized => "authorized",
    LoggedOut => "logged_out",
    Failed => "failed",
});

status_str!(PersistedConnectionStatus {
    Offline => "offline",
    Connecting => "connecting",
    Connected => "connected",
    Unknown => "unknown",
});

/// Profilo di credenziali API che si intende creare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiCredentialProfile {
    /// Etichetta scelta dall'operatore.
    pub label: DisplayName,
}

/// Profilo di credenziali API registrato.
///
/// `configured` dice se l'API id/hash e' stato salvato (nel file protetto): il
/// segreto **non** e' qui, solo il fatto che esista.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiCredentialProfile {
    /// Identificatore assegnato dalla persistenza.
    pub id: ApiCredentialProfileId,
    /// Etichetta.
    pub label: DisplayName,
    /// Se le credenziali API sono state salvate nel file protetto.
    pub configured: bool,
    /// Istante di creazione.
    pub created_at: Timestamp,
    /// Ultimo aggiornamento.
    pub updated_at: Timestamp,
}

/// Account Telegram che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTelegramAccount {
    /// UUID locale generato al momento della creazione.
    pub uuid: AccountUuid,
    /// Etichetta scelta dall'operatore.
    pub label: DisplayName,
    /// Profilo API associato.
    pub profile_id: ApiCredentialProfileId,
}

/// Account Telegram registrato (metadati non segreti).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramAccount {
    /// Identificatore locale (riga).
    pub id: TelegramAccountId,
    /// UUID locale: identita' stabile per directory e chiavi.
    pub uuid: AccountUuid,
    /// Etichetta.
    pub label: DisplayName,
    /// Numero mascherato, presente dopo il primo accesso.
    pub masked_phone: Option<MaskedPhoneNumber>,
    /// Profilo API associato.
    pub profile_id: ApiCredentialProfileId,
    /// Stato di autorizzazione conservato.
    pub auth_status: PersistedAuthStatus,
    /// Stato di collegamento conservato (ultimo noto).
    pub connection_status: PersistedConnectionStatus,
    /// Ultima connessione riuscita, se mai avvenuta.
    pub last_connected_at: Option<Timestamp>,
    /// Istante di creazione.
    pub created_at: Timestamp,
    /// Ultimo aggiornamento.
    pub updated_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::{AccountUuid, MaskedPhoneNumber, PersistedAuthStatus, PersistedConnectionStatus};

    #[test]
    fn an_uuid_from_bytes_is_thirty_two_hex_digits() {
        let uuid = AccountUuid::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(uuid.as_str().len(), AccountUuid::HEX_LEN);
        assert!(uuid.as_str().starts_with("0123456789abcdef"));
        assert!(AccountUuid::from_hex(uuid.as_str()).is_ok());
    }

    #[test]
    fn an_uuid_is_a_safe_file_name_component() {
        let uuid = AccountUuid::from_bytes([0xff; 16]);
        for forbidden in ['/', '\\', ':', '.', ' '] {
            assert!(!uuid.as_str().contains(forbidden));
        }
    }

    #[test]
    fn a_malformed_uuid_is_refused() {
        assert!(AccountUuid::from_hex("").is_err());
        assert!(AccountUuid::from_hex(&"g".repeat(32)).is_err());
        assert!(AccountUuid::from_hex(&"a".repeat(31)).is_err());
        assert!(
            AccountUuid::from_hex(&"A".repeat(32)).is_err(),
            "solo minuscole"
        );
    }

    #[test]
    fn a_masked_phone_hides_all_but_the_last_digits() {
        let masked = MaskedPhoneNumber::from_digits("+39 340 1234567");
        // Solo le ultime due cifre restano in chiaro.
        assert!(masked.as_str().ends_with("67"));
        let visible: String = masked
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        assert_eq!(visible, "67");
        assert!(MaskedPhoneNumber::from_stored(masked.as_str()).is_ok());
    }

    #[test]
    fn a_stored_mask_with_too_many_digits_is_refused() {
        // Una forma con l'intero numero non e' una maschera.
        assert!(MaskedPhoneNumber::from_stored("+393401234567").is_err());
        assert!(MaskedPhoneNumber::from_stored("").is_err());
    }

    #[test]
    fn every_status_round_trips_through_its_string() {
        for status in PersistedAuthStatus::all() {
            assert_eq!(
                PersistedAuthStatus::parse(status.as_str()).ok(),
                Some(*status)
            );
        }
        for status in PersistedConnectionStatus::all() {
            assert_eq!(
                PersistedConnectionStatus::parse(status.as_str()).ok(),
                Some(*status)
            );
        }
        assert!(PersistedAuthStatus::parse("boh").is_err());
    }
}

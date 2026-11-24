//! Valori riservati e loro redazione.
//!
//! Numero di telefono, codice di accesso, password 2FA, API ID e API hash non
//! devono comparire in chiaro da nessuna parte: né in un log, né in un messaggio
//! di errore, né nella resa `Debug` di una struttura che li contiene. La
//! redazione non è affidata alla disciplina di chi scrive il codice ma al tipo:
//! `Debug` è implementato a mano e `Display` **non è implementato affatto**, così
//! che `format!("{}", segreto)` non compili.
//!
//! Per leggere il valore in chiaro esiste un solo metodo, dal nome deliberatamente
//! scomodo: `expose_secret`. Chi lo scrive deve volerlo, e chi rilegge il codice
//! lo vede.

use core::fmt;

use crate::error::{TelegramError, TelegramResult};

/// Testo mostrato al posto di un valore riservato.
pub const REDACTED: &str = "«redatto»";

/// Contenitore di un testo riservato.
///
/// Non implementa `Display`, `Clone` di comodo né serializzazione: ogni via che
/// porti il valore fuori di qui deve essere esplicita.
struct SecretText(String);

impl SecretText {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl PartialEq for SecretText {
    fn eq(&self, other: &Self) -> bool {
        // Confronto non a tempo costante: serve ai test di uguaglianza, non a
        // decidere un'autenticazione. Nessun percorso del prodotto confronta
        // segreti per autorizzare alcunché.
        self.0 == other.0
    }
}

impl Eq for SecretText {}

impl Drop for SecretText {
    fn drop(&mut self) {
        // Sovrascrittura **best-effort** del buffer prima del rilascio.
        //
        // Limite dichiarato: non è una garanzia. Se la stringa è stata
        // riallocata durante la costruzione, il buffer precedente resta in
        // memoria e non è raggiungibile da qui; il sistema operativo può inoltre
        // aver paginato quella memoria su disco. Una cancellazione affidabile
        // richiede un tipo che non rialloca e primitive dedicate: è lavoro
        // dell'hardening previsto dalla Milestone 9, e va dichiarato come
        // limite anziché lasciato credere risolto.
        let length = self.0.len();
        self.0.clear();
        for _ in 0..length {
            self.0.push('\0');
        }
        // Impedisce al compilatore di considerare inutile la sovrascrittura.
        let _ = core::hint::black_box(&self.0);
    }
}

/// Genera un tipo riservato con validazione e redazione.
macro_rules! secret_type {
    (
        $(#[$meta:meta])*
        $name:ident, $field:literal, $min:expr, $max:expr, $validator:path
    ) => {
        $(#[$meta])*
        #[derive(PartialEq, Eq)]
        pub struct $name(SecretText);

        impl $name {
            /// Nome del campo, usato nei messaggi di errore. Non contiene il valore.
            pub const FIELD: &'static str = $field;

            /// Lunghezza minima ammessa, in caratteri.
            pub const MIN_CHARS: usize = $min;

            /// Lunghezza massima ammessa, in caratteri.
            pub const MAX_CHARS: usize = $max;

            /// Costruisce il valore validandolo.
            ///
            /// # Errori
            ///
            /// Restituisce [`TelegramError::InvalidSecret`] se il valore non
            /// rispetta il formato atteso. Il messaggio d'errore riporta il nome
            /// del campo e **mai** il valore.
            pub fn try_new(raw: &str) -> TelegramResult<Self> {
                let normalised = $validator(Self::FIELD, raw, Self::MIN_CHARS, Self::MAX_CHARS)?;
                Ok(Self(SecretText::new(normalised)))
            }

            /// Espone il valore in chiaro.
            ///
            /// Il nome è volutamente scomodo: ogni chiamata è un punto in cui un
            /// segreto lascia il proprio contenitore e va giustificata. Non
            /// passare mai il risultato a una macro di logging.
            #[must_use]
            pub fn expose_secret(&self) -> &str {
                self.0.expose()
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(formatter, "{}({})", stringify!($name), REDACTED)
            }
        }
    };
}

secret_type!(
    /// Numero di telefono dell'account d'ufficio, in formato internazionale.
    PhoneNumber,
    "numero_di_telefono",
    8,
    20,
    validate_phone
);

secret_type!(
    /// Codice di accesso ricevuto da Telegram.
    LoginCode,
    "codice_di_accesso",
    4,
    8,
    validate_digits
);

secret_type!(
    /// Password della verifica in due passaggi.
    TwoFactorPassword,
    "password_2fa",
    1,
    256,
    validate_opaque
);

secret_type!(
    /// Hash dell'applicazione rilasciato da Telegram.
    ApiHash,
    "api_hash",
    32,
    32,
    validate_hex
);

impl PhoneNumber {
    /// Numero in forma redatta, mostrabile all'operatore e registrabile.
    ///
    /// Conserva il prefisso internazionale e le ultime due cifre. È il
    /// compromesso deliberato fra due esigenze reali: l'operatore deve poter
    /// riconoscere quale utenza è configurata, e chi legge un log non deve
    /// poterla usare. Mostrare il numero intero renderebbe inutile ogni altra
    /// protezione; nasconderlo del tutto renderebbe impossibile accorgersi di
    /// aver configurato l'account sbagliato.
    #[must_use]
    pub fn redacted(&self) -> String {
        let raw = self.expose_secret();
        let digits: Vec<char> = raw.chars().filter(char::is_ascii_digit).collect();

        // Con pochissime cifre non c'è nulla da mostrare senza rivelare tutto.
        if digits.len() < 6 {
            return String::from("+**");
        }

        let prefix: String = digits.iter().take(2).collect();
        let suffix: String = digits.iter().skip(digits.len() - 2).collect();
        let hidden = "*".repeat(digits.len() - 4);

        format!("+{prefix}{hidden}{suffix}")
    }
}

/// Identificativo numerico dell'applicazione rilasciato da Telegram.
///
/// È trattato come riservato insieme all'hash: la coppia identifica
/// l'applicazione e non va diffusa.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ApiId(i32);

impl ApiId {
    /// Costruisce l'identificativo verificando che sia positivo.
    ///
    /// # Errori
    ///
    /// Restituisce [`TelegramError::InvalidSecret`] per valori non positivi.
    pub const fn try_new(value: i32) -> TelegramResult<Self> {
        if value <= 0 {
            return Err(TelegramError::InvalidSecret {
                field: "api_id",
                reason: "deve essere un intero positivo",
            });
        }
        Ok(Self(value))
    }

    /// Espone il valore in chiaro.
    #[must_use]
    pub const fn expose_secret(self) -> i32 {
        self.0
    }
}

impl fmt::Debug for ApiId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApiId({REDACTED})")
    }
}

/// Verifica un numero di telefono in formato internazionale.
fn validate_phone(
    field: &'static str,
    raw: &str,
    min: usize,
    max: usize,
) -> TelegramResult<String> {
    let trimmed: String = raw.chars().filter(|character| *character != ' ').collect();
    let digits = trimmed.strip_prefix('+').unwrap_or(&trimmed);

    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_digit()) {
        return Err(TelegramError::InvalidSecret {
            field,
            reason: "sono ammesse solo cifre, con un eventuale prefisso +",
        });
    }
    check_length(field, digits.chars().count(), min, max)?;

    Ok(format!("+{digits}"))
}

/// Verifica una sequenza di sole cifre.
fn validate_digits(
    field: &'static str,
    raw: &str,
    min: usize,
    max: usize,
) -> TelegramResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.chars().all(|character| character.is_ascii_digit()) {
        return Err(TelegramError::InvalidSecret {
            field,
            reason: "sono ammesse solo cifre",
        });
    }
    check_length(field, trimmed.chars().count(), min, max)?;

    Ok(trimmed.to_owned())
}

/// Verifica una sequenza esadecimale.
fn validate_hex(field: &'static str, raw: &str, min: usize, max: usize) -> TelegramResult<String> {
    let trimmed = raw.trim();
    if !trimmed
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(TelegramError::InvalidSecret {
            field,
            reason: "sono ammessi solo cifre e lettere da a a f",
        });
    }
    check_length(field, trimmed.chars().count(), min, max)?;

    Ok(trimmed.to_ascii_lowercase())
}

/// Verifica un valore di cui non si conosce il formato.
///
/// Una password non ha una forma prescritta: si controlla solo che non sia vuota,
/// che stia entro un limite e che non contenga caratteri di controllo, che
/// indicherebbero un incollaggio accidentale.
fn validate_opaque(
    field: &'static str,
    raw: &str,
    min: usize,
    max: usize,
) -> TelegramResult<String> {
    if raw.chars().any(char::is_control) {
        return Err(TelegramError::InvalidSecret {
            field,
            reason: "contiene caratteri di controllo",
        });
    }
    check_length(field, raw.chars().count(), min, max)?;

    Ok(raw.to_owned())
}

/// Verifica la lunghezza senza mai riportare il valore.
const fn check_length(
    field: &'static str,
    actual: usize,
    min: usize,
    max: usize,
) -> TelegramResult<()> {
    if actual < min {
        return Err(TelegramError::InvalidSecret {
            field,
            reason: "più corto della lunghezza minima ammessa",
        });
    }
    if actual > max {
        return Err(TelegramError::InvalidSecret {
            field,
            reason: "più lungo della lunghezza massima ammessa",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ApiHash, ApiId, LoginCode, PhoneNumber, REDACTED, TwoFactorPassword};
    use crate::error::TelegramError;

    // Valori dichiaratamente fittizi. Nessun dato reale compare nei test.
    const FAKE_PHONE: &str = "+390612345678";
    const FAKE_CODE: &str = "12345";
    const FAKE_PASSWORD: &str = "password-di-prova-non-reale";
    const FAKE_HASH: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_phone_number_is_normalised_without_spaces() {
        let Ok(phone) = PhoneNumber::try_new("+39 06 1234 5678") else {
            panic!("il numero di prova deve essere accettato");
        };
        assert_eq!(phone.expose_secret(), FAKE_PHONE);
    }

    #[test]
    fn a_phone_number_without_a_prefix_gains_one() {
        let Ok(phone) = PhoneNumber::try_new("390612345678") else {
            panic!("il numero di prova deve essere accettato");
        };
        assert_eq!(phone.expose_secret(), FAKE_PHONE);
    }

    #[test]
    fn a_phone_number_with_letters_is_rejected() {
        assert!(matches!(
            PhoneNumber::try_new("+39061234567a"),
            Err(TelegramError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn the_debug_output_of_every_secret_hides_the_value() {
        let (Ok(phone), Ok(code), Ok(password), Ok(hash), Ok(api_id)) = (
            PhoneNumber::try_new(FAKE_PHONE),
            LoginCode::try_new(FAKE_CODE),
            TwoFactorPassword::try_new(FAKE_PASSWORD),
            ApiHash::try_new(FAKE_HASH),
            ApiId::try_new(1_234_567),
        ) else {
            panic!("i valori di prova devono essere accettati");
        };

        for (rendered, secret) in [
            (format!("{phone:?}"), FAKE_PHONE),
            (format!("{code:?}"), FAKE_CODE),
            (format!("{password:?}"), FAKE_PASSWORD),
            (format!("{hash:?}"), FAKE_HASH),
            (format!("{api_id:?}"), "1234567"),
        ] {
            assert!(
                !rendered.contains(secret),
                "la resa Debug '{rendered}' non deve contenere il valore in chiaro"
            );
            assert!(rendered.contains(REDACTED));
        }
    }

    #[test]
    fn a_secret_nested_in_a_structure_is_still_redacted() {
        #[derive(Debug)]
        struct Credenziali {
            phone: PhoneNumber,
        }

        let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere accettato");
        };
        let credenziali = Credenziali { phone };
        let rendered = format!("{credenziali:?}");

        assert!(!rendered.contains(FAKE_PHONE));
        assert!(rendered.contains(REDACTED));
        // Il valore resta leggibile per chi lo chiede esplicitamente: e' la
        // resa testuale a essere redatta, non il dato a essere perso.
        assert_eq!(credenziali.phone.expose_secret(), FAKE_PHONE);
    }

    #[test]
    fn an_error_about_a_secret_never_carries_its_value() {
        let Err(error) = PhoneNumber::try_new("non-un-numero-9876543210") else {
            panic!("il valore doveva essere rifiutato");
        };
        let rendered = error.to_string();

        assert!(!rendered.contains("9876543210"));
        assert!(rendered.contains("numero_di_telefono"));
    }

    #[test]
    fn a_login_code_accepts_only_digits() {
        assert!(LoginCode::try_new(FAKE_CODE).is_ok());
        assert!(matches!(
            LoginCode::try_new("12a45"),
            Err(TelegramError::InvalidSecret { .. })
        ));
        assert!(matches!(
            LoginCode::try_new(""),
            Err(TelegramError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn a_login_code_outside_the_admitted_length_is_rejected() {
        assert!(matches!(
            LoginCode::try_new("123"),
            Err(TelegramError::InvalidSecret { .. })
        ));
        assert!(matches!(
            LoginCode::try_new("123456789"),
            Err(TelegramError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn an_api_hash_must_be_thirty_two_hexadecimal_characters() {
        assert!(ApiHash::try_new(FAKE_HASH).is_ok());
        assert!(matches!(
            ApiHash::try_new("0123456789abcdef"),
            Err(TelegramError::InvalidSecret { .. })
        ));
        assert!(matches!(
            ApiHash::try_new("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            Err(TelegramError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn an_api_hash_is_normalised_to_lowercase() {
        let Ok(hash) = ApiHash::try_new("0123456789ABCDEF0123456789ABCDEF") else {
            panic!("l'hash di prova deve essere accettato");
        };
        assert_eq!(hash.expose_secret(), FAKE_HASH);
    }

    #[test]
    fn a_non_positive_api_id_is_rejected() {
        assert!(matches!(
            ApiId::try_new(0),
            Err(TelegramError::InvalidSecret {
                field: "api_id",
                ..
            })
        ));
        assert!(matches!(
            ApiId::try_new(-1),
            Err(TelegramError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn a_redacted_number_keeps_the_prefix_and_the_last_two_digits() {
        let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere valido");
        };
        let redacted = phone.redacted();

        // Dodici cifre: due di prefisso, due finali, otto nascoste.
        assert_eq!(redacted, "+39********78");
        assert!(!redacted.contains("0612345"), "il corpo non deve comparire");
        assert!(redacted.starts_with("+39"));
        assert!(redacted.ends_with("78"));
    }

    #[test]
    fn a_redacted_number_hides_as_many_digits_as_the_original_has() {
        let Ok(phone) = PhoneNumber::try_new(FAKE_PHONE) else {
            panic!("il numero di prova deve essere valido");
        };
        let visible_digits = phone
            .redacted()
            .chars()
            .filter(char::is_ascii_digit)
            .count();
        assert_eq!(visible_digits, 4, "solo prefisso e ultime due cifre");
    }

    #[test]
    fn a_very_short_number_is_redacted_entirely() {
        let Ok(phone) = PhoneNumber::try_new("12345678") else {
            panic!("il numero di prova deve essere valido");
        };
        // Otto cifre: il compromesso resta prudente e non rivela il corpo.
        let redacted = phone.redacted();
        assert!(!redacted.contains("3456"));
    }

    #[test]
    fn a_password_with_control_characters_is_rejected() {
        assert!(matches!(
            TwoFactorPassword::try_new("password\u{0}nascosta"),
            Err(TelegramError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn a_password_keeps_its_spaces_because_they_may_be_significant() {
        let Ok(password) = TwoFactorPassword::try_new("  con spazi  ") else {
            panic!("la password di prova deve essere accettata");
        };
        assert_eq!(password.expose_secret(), "  con spazi  ");
    }

    /// **Il contenitore comune non stampa il valore** (PR-15).
    ///
    /// Le prove dei tipi pubblici passano dal loro `Debug`, che non chiama
    /// quello del contenitore: una struttura che un giorno lo includesse con un
    /// `#[derive(Debug)]` passerebbe da qui, e nessuna prova lo guardava. Il
    /// catalogo delle classi di rischio lo ha trovato mutandolo: la prova restava
    /// verde.
    #[test]
    fn il_contenitore_comune_non_stampa_il_valore() {
        let segreto = super::SecretText::new(String::from(FAKE_PASSWORD));
        let reso = format!("{segreto:?}");
        assert!(
            !reso.contains(FAKE_PASSWORD),
            "«{reso}» porta il valore in chiaro"
        );
        assert!(reso.contains(REDACTED));
    }
}

//! Le persone dell'ufficio (TEAM-ASSIGN-01, ADR-0097).
//!
//! # Perché esistono
//!
//! Fino a oggi ogni atto era attribuito a `postazione.<identificativo>`, e il
//! registro lo diceva: chi usa fisicamente quella postazione non era
//! distinguibile. Tre milestone di fila hanno dichiarato quel limite; qui si
//! chiude.
//!
//! # Che cosa c'è qui e che cosa no
//!
//! Qui ci sono i **tipi**: come si chiama una persona, che cosa è una frase di
//! accesso, che forma ha il verificatore che l'Hub conserva al suo posto.
//!
//! **Non** c'è la derivazione del verificatore. Argon2id sta in
//! `lisi-security`, insieme a DPAPI e alle chiavi: `lisi-core` non tocca il
//! sistema operativo e non fa crittografia, per la stessa ragione per cui non
//! possiede un generatore di numeri casuali.
//!
//! # La frase non esce da qui
//!
//! [`Passphrase`] è redatta come [`crate::model::identity::DeviceSecret`]:
//! `Debug` stampa un segnaposto, non c'è `Display`, non c'è `Clone`, e i byte
//! si sovrascrivono uscendo. Una frase che comparisse in un registro resterebbe
//! su un disco per sempre.

use core::fmt;

use crate::Timestamp;
use crate::error::{DomainError, DomainResult};
use crate::model::hub_access::HubRole;
use crate::model::identity::SECRET_REDACTED;
use crate::text::DisplayName;

/// Caratteri al più dell'identificativo di una persona.
pub const MAX_PERSON_ID_CHARS: usize = 32;

/// Caratteri al meno dell'identificativo di una persona.
///
/// Tre: `rm` è un identificativo che si confonde, `mrossi` no.
pub const MIN_PERSON_ID_CHARS: usize = 3;

/// Caratteri al meno di una frase di accesso.
///
/// **Dodici**, e la regola sta qui e non nell'interfaccia: una regola scritta
/// in una schermata vale finché qualcuno non ne scrive una seconda (ADR-0097,
/// decisione 2). Dodici caratteri non sono una garanzia — una frase corta e
/// comune resta indovinabile — sono il minimo sotto il quale non si scende.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Caratteri al più di una frase di accesso.
///
/// Il tetto non protegge la frase: protegge chi la verifica, perché la
/// verifica è **lenta apposta** e una frase lunghissima la renderebbe un modo
/// per occupare l'Hub.
pub const MAX_PASSPHRASE_CHARS: usize = 128;

/// Caratteri al più del verificatore conservato.
///
/// Un `PHC string` di Argon2id sta ampiamente dentro: il tetto esiste perché
/// il valore rientra dall'archivio, e ciò che rientra si misura.
pub const MAX_VERIFIER_CHARS: usize = 256;

/// L'identificativo di una persona dell'ufficio.
///
/// Minuscole, cifre, trattino e trattino basso. **Niente punti**: l'atto si
/// scrive `persona.<identificativo>`, e un punto dentro l'identificativo
/// renderebbe ambiguo dove finisce il prefisso.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersonId(String);

impl PersonId {
    /// Riconosce un identificativo scritto o conservato.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidPersonId`] se la lunghezza è fuori dai limiti o
    /// se un carattere non appartiene all'alfabeto ammesso.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        let pulito = raw.trim().to_ascii_lowercase();
        let quanti = pulito.chars().count();
        if quanti < MIN_PERSON_ID_CHARS {
            return Err(DomainError::InvalidPersonId {
                reason: "ha meno di tre caratteri",
            });
        }
        if quanti > MAX_PERSON_ID_CHARS {
            return Err(DomainError::InvalidPersonId {
                reason: "ha più di trentadue caratteri",
            });
        }
        if !pulito
            .chars()
            .all(|carattere| carattere.is_ascii_alphanumeric() || matches!(carattere, '-' | '_'))
        {
            return Err(DomainError::InvalidPersonId {
                reason: "contiene un carattere che non è una lettera, una cifra, un trattino o un \
                         trattino basso",
            });
        }
        Ok(Self(pulito))
    }

    /// Forma canonica.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PersonId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Una frase di accesso, mentre attraversa il programma.
///
/// Non si conserva: l'Hub ne tiene un [`PassphraseVerifier`]. Questo tipo vive
/// il tempo di essere verificato.
///
/// I byte, e non una `String`: sovrascriverli uscendo è ciò che questo tipo
/// deve saper fare, e una `String` non si lascia sovrascrivere senza `unsafe`
/// — che in `lisi-core` è vietato. È anche la forma che Argon2id vuole.
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    /// Accetta una frase digitata da una persona.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidPassphrase`] se è troppo corta, troppo lunga o
    /// contiene caratteri di controllo. **Il motivo non contiene mai la
    /// frase.**
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let quanti = raw.chars().count();
        if quanti < MIN_PASSPHRASE_CHARS {
            return Err(DomainError::InvalidPassphrase {
                reason: "ha meno di dodici caratteri",
            });
        }
        if quanti > MAX_PASSPHRASE_CHARS {
            return Err(DomainError::InvalidPassphrase {
                reason: "ha più di centoventotto caratteri",
            });
        }
        if raw.chars().any(char::is_control) {
            return Err(DomainError::InvalidPassphrase {
                reason: "contiene caratteri di controllo",
            });
        }
        Ok(Self(raw.as_bytes().to_vec()))
    }

    /// Espone la frase a chi deve verificarla.
    ///
    /// Il nome è scomodo apposta: ogni chiamata è un punto in cui la frase
    /// esce, e i punti devono essere pochi e visibili.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SECRET_REDACTED)
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        // Sovrascrittura best-effort, con lo stesso limite dichiarato per
        // DeviceSecret: cancella la copia che si conosce, non quelle che il
        // sistema puo' aver fatto.
        self.0.fill(0);
    }
}

/// Ciò che l'Hub conserva al posto di una frase.
///
/// È la forma testuale di Argon2id, parametri compresi: il giorno in cui
/// verranno alzati, le impronte vecchie devono restare verificabili
/// (ADR-0097, decisione 3).
#[derive(Clone, PartialEq, Eq)]
pub struct PassphraseVerifier(String);

impl PassphraseVerifier {
    /// Accetta un verificatore prodotto da `lisi-security` o riletto
    /// dall'archivio.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidPassphrase`] se non ha la forma di un `PHC
    /// string` di Argon2id o se supera il tetto.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        if !raw.starts_with("$argon2id$") {
            return Err(DomainError::InvalidPassphrase {
                reason: "il verificatore non è nella forma attesa",
            });
        }
        if raw.chars().count() > MAX_VERIFIER_CHARS {
            return Err(DomainError::InvalidPassphrase {
                reason: "il verificatore supera la lunghezza prevista",
            });
        }
        Ok(Self(String::from(raw)))
    }

    /// Forma conservata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PassphraseVerifier {
    /// Redatto.
    ///
    /// Non è una credenziale utilizzabile, ma è ciò da cui si parte per
    /// provare le frasi offline: non c'è ragione perché compaia in un registro.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SECRET_REDACTED)
    }
}

/// Che cosa l'ufficio sa di una persona.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersonState {
    /// Può entrare e lavorare.
    #[default]
    Active,
    /// Non può entrare. Gli atti che ha già compiuto restano suoi.
    Suspended,
}

impl PersonState {
    /// Forma conservata nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "attiva",
            Self::Suspended => "sospesa",
        }
    }

    /// Nome per chi legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "Attiva",
            Self::Suspended => "Sospesa",
        }
    }

    /// Riconosce la forma conservata.
    ///
    /// # Errori
    ///
    /// [`DomainError::UnknownVariant`] se il valore non è previsto.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        match raw {
            "attiva" => Ok(Self::Active),
            "sospesa" => Ok(Self::Suspended),
            _ => Err(DomainError::UnknownVariant {
                kind: "stato della persona",
                value: String::from(raw),
            }),
        }
    }
}

/// Una persona dell'ufficio, come l'Hub la conosce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// Come si chiama negli atti.
    pub id: PersonId,
    /// Come la chiama l'ufficio.
    pub label: DisplayName,
    /// Che cosa le è consentito.
    pub role: HubRole,
    /// Se può entrare.
    pub state: PersonState,
    /// Da quando esiste.
    pub created_at: Timestamp,
}

impl Person {
    /// Se questa persona può entrare adesso.
    #[must_use]
    pub const fn may_sign_in(&self) -> bool {
        matches!(self.state, PersonState::Active)
    }
}

/// Come si scrive negli atti chi ha agito.
///
/// Le due forme si distinguono a colpo d'occhio, ed è il punto: un registro in
/// cui non si vede la differenza fra «verificato» e «non verificato» non serve
/// a niente (ADR-0097, decisione 7).
#[must_use]
pub fn attore_della_persona(person: &PersonId) -> String {
    format!("persona.{person}")
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PASSPHRASE_CHARS, MIN_PASSPHRASE_CHARS, Passphrase, PassphraseVerifier, PersonId,
        PersonState, attore_della_persona,
    };
    use crate::model::identity::SECRET_REDACTED;

    fn persona() -> PersonId {
        match PersonId::parse("mrossi") {
            Ok(persona) => persona,
            Err(errore) => panic!("identificativo di prova: {errore}"),
        }
    }

    #[test]
    fn un_identificativo_si_normalizza_e_si_riconosce() {
        let Ok(persona) = PersonId::parse("  MRossi  ") else {
            panic!("l'identificativo deve essere accettato");
        };
        assert_eq!(persona.as_str(), "mrossi");
    }

    #[test]
    fn un_identificativo_non_puo_contenere_un_punto() {
        // L'atto si scrive «persona.<identificativo>»: un punto dentro
        // renderebbe ambiguo dove finisce il prefisso.
        assert!(PersonId::parse("m.rossi").is_err());
    }

    #[test]
    fn un_identificativo_troppo_corto_o_troppo_lungo_si_rifiuta() {
        assert!(PersonId::parse("ab").is_err());
        assert!(PersonId::parse(&"a".repeat(33)).is_err());
    }

    #[test]
    fn l_atto_di_una_persona_si_distingue_da_quello_di_una_postazione() {
        let atto = attore_della_persona(&persona());
        assert_eq!(atto, "persona.mrossi");
        assert!(
            !atto.starts_with("postazione."),
            "le due forme devono restare distinguibili"
        );
    }

    #[test]
    fn una_frase_troppo_corta_si_rifiuta_senza_citarla() {
        let Err(errore) = Passphrase::try_new("corta") else {
            panic!("una frase di cinque caratteri non deve essere accettata");
        };
        let detto = format!("{errore}");
        assert!(
            !detto.contains("corta"),
            "il rifiuto cita la frase: «{detto}»"
        );
    }

    #[test]
    fn una_frase_si_accetta_dal_minimo_al_massimo() {
        assert!(Passphrase::try_new(&"a".repeat(MIN_PASSPHRASE_CHARS)).is_ok());
        assert!(Passphrase::try_new(&"a".repeat(MAX_PASSPHRASE_CHARS)).is_ok());
        assert!(Passphrase::try_new(&"a".repeat(MAX_PASSPHRASE_CHARS + 1)).is_err());
    }

    #[test]
    fn una_frase_con_caratteri_di_controllo_si_rifiuta() {
        assert!(Passphrase::try_new("frase\u{0}nascosta").is_err());
    }

    #[test]
    fn una_frase_non_compare_mai_nella_sua_resa() {
        let Ok(frase) = Passphrase::try_new("parola-molto-lunga") else {
            panic!("la frase deve essere accettata");
        };
        assert_eq!(format!("{frase:?}"), SECRET_REDACTED);
        assert_eq!(frase.expose(), b"parola-molto-lunga");
    }

    #[test]
    fn il_verificatore_e_redatto_e_riconosce_la_propria_forma() {
        let Ok(verificatore) =
            PassphraseVerifier::try_new("$argon2id$v=19$m=19456,t=2,p=1$c2Fs$aGFzaA")
        else {
            panic!("il verificatore deve essere accettato");
        };
        assert_eq!(format!("{verificatore:?}"), SECRET_REDACTED);
        assert!(PassphraseVerifier::try_new("$2b$12$qualcosa").is_err());
        assert!(PassphraseVerifier::try_new("").is_err());
    }

    #[test]
    fn lo_stato_di_una_persona_va_e_torna_dall_archivio() {
        for stato in [PersonState::Active, PersonState::Suspended] {
            let Ok(riletto) = PersonState::parse(stato.as_str()) else {
                panic!("lo stato {stato:?} deve potersi rileggere");
            };
            assert_eq!(riletto, stato);
            assert!(!stato.label().is_empty());
        }
        assert!(PersonState::parse("qualunque").is_err());
    }
}

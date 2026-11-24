//! La modalità client: che cosa la postazione sa dell'Hub, e che cosa non
//! inventa (TEAM-CLIENT-01, ADR-0091).
//!
//! # L'Hub si configura, non si scopre
//!
//! Non esiste una scoperta di rete, e non esiste un nome da risolvere:
//! l'indirizzo è un **IP letterale con la sua porta** ([`HubAddress`]). Un Hub
//! trovato da solo è un Hub che qualcun altro può far trovare, e un nome
//! metterebbe il DNS d'ufficio — che nessuno autentica — dentro la decisione su
//! *con chi* la postazione parla.
//!
//! La validazione avviene **quando si scrive** la configurazione, non quando la
//! si usa: una configurazione inutilizzabile va rifiutata da chi la scrive,
//! mentre c'è ancora qualcuno che può correggerla.
//!
//! # L'attesa si stringe una volta sola
//!
//! [`HubExpectation`] ha due forme (ADR-0082): i 120 bit ricopiati dal
//! foglietto e i 256 bit appuntati dopo la prima connessione verificata. Il
//! passaggio dal primo al secondo è l'**unico** restringimento automatico:
//! un'impronta diversa da quella appuntata non la sostituisce
//! ([`PinVerdict::Refused`]), perché un riappuntamento silenzioso sarebbe un
//! TOFU ritardato.

use core::fmt;
use core::str::FromStr;
use core::time::Duration;
use std::net::SocketAddr;

use crate::error::{DomainError, DomainResult};
use crate::model::hub_identity::{HubExpectation, HubFingerprint};

/// Caratteri al più per l'indirizzo scritto.
///
/// Un `[…]:65535` IPv6 intero sta in quarantacinque caratteri: il tetto rifiuta
/// un testo lungo **prima** di analizzarlo, perché il testo può arrivare da un
/// file che qualcuno ha riscritto.
pub const HUB_ADDRESS_MAX_CHARS: usize = 64;

/// L'indirizzo dell'Hub: un IP letterale, con la sua porta.
///
/// Non esiste una porta predefinita: sceglierne una qui significherebbe fissare
/// un dato pubblico del protocollo senza averlo deciso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubAddress(SocketAddr);

impl HubAddress {
    /// Accetta un indirizzo utilizzabile per raggiungere un Hub.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidHubAddress`] per l'indirizzo non specificato, il
    /// multicast, il broadcast IPv4 e la porta zero. Il motivo è una costante:
    /// l'indirizzo può venire da un file riscritto, e un messaggio composto con
    /// il dato ricevuto è un messaggio che il dato ricevuto può riscrivere.
    pub fn try_new(address: SocketAddr) -> DomainResult<Self> {
        if address.port() == 0 {
            return Err(DomainError::InvalidHubAddress {
                reason: "la porta zero non è una porta a cui collegarsi",
            });
        }
        if address.ip().is_unspecified() {
            return Err(DomainError::InvalidHubAddress {
                reason: "l'Hub si raggiunge a un indirizzo preciso, non a «qualunque indirizzo»",
            });
        }
        if address.ip().is_multicast() {
            return Err(DomainError::InvalidHubAddress {
                reason: "questo indirizzo raggiunge molti computer insieme, non un Hub",
            });
        }
        if matches!(address.ip(), std::net::IpAddr::V4(quattro) if quattro.is_broadcast()) {
            return Err(DomainError::InvalidHubAddress {
                reason: "questo indirizzo raggiunge tutta la rete, non un Hub",
            });
        }
        Ok(Self(address))
    }

    /// Riconosce la forma scritta: `192.0.2.10:8443`, oppure `[2001:db8::1]:8443`.
    ///
    /// **Nessun nome**: ciò che non è un IP letterale viene rifiutato, e con
    /// esso ogni risoluzione di nomi.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidHubAddress`] se il testo è vuoto, più lungo di
    /// [`HUB_ADDRESS_MAX_CHARS`], non è un indirizzo letterale con porta, o non
    /// supera [`Self::try_new`].
    pub fn parse(raw: &str) -> DomainResult<Self> {
        let pulito = raw.trim();
        if pulito.is_empty() {
            return Err(DomainError::InvalidHubAddress {
                reason: "l'indirizzo dell'Hub non può essere vuoto",
            });
        }
        if pulito.chars().count() > HUB_ADDRESS_MAX_CHARS {
            return Err(DomainError::InvalidHubAddress {
                reason: "l'indirizzo dell'Hub è più lungo di qualunque indirizzo con porta",
            });
        }
        let indirizzo =
            SocketAddr::from_str(pulito).map_err(|_| DomainError::InvalidHubAddress {
                reason: "l'indirizzo dell'Hub si scrive in cifre con la sua porta, mai con un nome",
            })?;
        Self::try_new(indirizzo)
    }

    /// L'indirizzo, per chi apre la connessione.
    #[must_use]
    pub const fn as_socket_addr(&self) -> SocketAddr {
        self.0
    }
}

impl fmt::Display for HubAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Che cosa la postazione sa dell'Hub: dove sta, e quale chiave attende.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubConnection {
    /// Dove sta l'Hub.
    pub address: HubAddress,
    /// Quale chiave la postazione attende (ADR-0082).
    pub expectation: HubExpectation,
}

impl HubConnection {
    /// La configurazione appena scritta dal foglietto: prefisso di 120 bit.
    #[must_use]
    pub const fn new(address: HubAddress, expectation: HubExpectation) -> Self {
        Self {
            address,
            expectation,
        }
    }

    /// Se l'attesa è già l'impronta intera.
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        matches!(self.expectation, HubExpectation::Pinned(_))
    }
}

/// Che cosa una postazione è, rispetto all'**acquisizione** da Telegram
/// (TEAM-AUTHORITY-01, ADR-0092).
///
/// L'acquisizione la fa **una sola autorità**: l'Hub, una volta per tutti
/// (freeze §7.10). Una postazione che segue un Hub non acquisisce, e non deve
/// nemmeno poterci provare: N client non devono produrre N carichi su Telegram,
/// né N sessioni TDLib per lo stesso account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StationRole {
    /// Acquisisce da sé: una postazione Standalone, oppure l'Hub stesso.
    OwnAuthority,
    /// Segue un Hub: **non acquisisce**.
    HubClient,
}

impl StationRole {
    /// Che cosa la postazione è, dato che abbia o no un Hub configurato.
    #[must_use]
    pub const fn of_station(has_hub: bool) -> Self {
        if has_hub {
            Self::HubClient
        } else {
            Self::OwnAuthority
        }
    }

    /// Se questa postazione può acquisire da Telegram.
    #[must_use]
    pub const fn may_acquire(self) -> bool {
        matches!(self, Self::OwnAuthority)
    }

    /// La frase per l'operatore quando l'acquisizione non le spetta.
    ///
    /// Dice **dove** il lavoro viene fatto, non soltanto che qui non si può: un
    /// rifiuto senza il resto manda a cercare il modo di aggirarlo.
    #[must_use]
    pub const fn acquisition_message(self) -> &'static str {
        match self {
            Self::OwnAuthority => {
                "Questa postazione acquisisce da Telegram con le proprie credenziali."
            }
            Self::HubClient => {
                "Questa postazione segue un Hub: l'acquisizione da Telegram la esegue l'Hub, \
                 una volta sola per tutto l'ufficio. Qui non si apre alcuna sessione Telegram. \
                 Per acquisire da questa postazione occorre toglierle la configurazione \
                 dell'Hub, che è un atto di chi amministra."
            }
        }
    }
}

/// Che cosa fare dell'impronta che l'Hub ha appena presentato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinVerdict {
    /// Si appunta: era il prefisso del foglietto, ed è la prima connessione
    /// verificata.
    Pin(HubFingerprint),
    /// È la stessa già appuntata: non cambia nulla.
    Unchanged,
    /// **Non è quella appuntata.** La sessione si ferma e serve una persona.
    Refused,
}

/// Che cosa fare dell'impronta presentata, data l'attesa conservata.
///
/// Un prefisso che **non** corrisponde è anch'esso un rifiuto: il trasporto non
/// dovrebbe arrivare qui con una chiave sbagliata, e se ci arriva la risposta è
/// la stessa.
#[must_use]
pub fn pin_verdict(expectation: HubExpectation, presented: HubFingerprint) -> PinVerdict {
    match expectation {
        HubExpectation::Enrollment(prefisso) => {
            if prefisso.matches(&presented) {
                PinVerdict::Pin(presented)
            } else {
                PinVerdict::Refused
            }
        }
        HubExpectation::Pinned(appuntata) => {
            if appuntata == presented {
                PinVerdict::Unchanged
            } else {
                PinVerdict::Refused
            }
        }
    }
}

/// I tetti di **una sessione** con l'Hub.
///
/// Valori scelti da noi, **non misurati** (HVQ-08). Servono a che una sessione
/// finisca: un Hub che risponde sempre «c'è ancora» non deve poter tenere la
/// postazione in un ciclo che nessuno interrompe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// Pagine chieste al più in una sessione.
    pub max_pages: u32,
    /// Eventi applicati al più in una sessione.
    pub max_events: usize,
    /// Durata massima della sessione, dal primo byte.
    pub max_duration: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_pages: 64,
            max_events: 10_000,
            max_duration: Duration::from_secs(120),
        }
    }
}

impl SessionLimits {
    /// Se i tetti sono utilizzabili: nessuno nullo.
    ///
    /// Un tetto nullo non è «nessun limite», è una sessione che non comincia:
    /// in entrambe le letture è un difetto di configurazione, e si rifiuta.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.max_pages > 0 && self.max_events > 0 && !self.max_duration.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{HubAddress, HubConnection, PinVerdict, SessionLimits, StationRole, pin_verdict};
    use crate::model::hub_identity::{HUB_FINGERPRINT_BYTES, HubExpectation, HubFingerprint};

    fn impronta(seme: u8) -> HubFingerprint {
        HubFingerprint::from_bytes([seme; HUB_FINGERPRINT_BYTES])
    }

    #[test]
    fn a_literal_address_with_a_port_is_accepted() {
        let Ok(indirizzo) = HubAddress::parse("192.0.2.10:8443") else {
            panic!("un indirizzo letterale con porta deve essere accettato");
        };
        assert_eq!(indirizzo.to_string(), "192.0.2.10:8443");
        assert!(HubAddress::parse("[2001:db8::1]:8443").is_ok());
        assert!(HubAddress::parse("127.0.0.1:1").is_ok());
    }

    #[test]
    fn a_name_is_never_an_address() {
        for testo in [
            "hub.ufficio.local:8443",
            "localhost:8443",
            "192.0.2.10",
            "",
            "   ",
        ] {
            assert!(
                HubAddress::parse(testo).is_err(),
                "«{testo}» non è un indirizzo letterale con porta"
            );
        }
    }

    #[test]
    fn an_address_that_reaches_many_or_none_is_refused() {
        let casi = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 8443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 8443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 0),
        ];
        for caso in casi {
            assert!(
                HubAddress::try_new(caso).is_err(),
                "«{caso}» non raggiunge un Hub e basta"
            );
        }
    }

    #[test]
    fn a_long_text_is_refused_before_being_parsed() {
        let lungo = format!("{}:8443", "9".repeat(super::HUB_ADDRESS_MAX_CHARS));
        assert!(HubAddress::parse(&lungo).is_err());
    }

    #[test]
    fn the_first_verified_connection_pins_the_whole_fingerprint() {
        let intera = impronta(7);
        let attesa = HubExpectation::Enrollment(intera.prefix());
        assert_eq!(pin_verdict(attesa, intera), PinVerdict::Pin(intera));
    }

    #[test]
    fn a_pinned_fingerprint_is_never_replaced_in_silence() {
        let attesa = HubExpectation::Pinned(impronta(7));
        assert_eq!(pin_verdict(attesa, impronta(7)), PinVerdict::Unchanged);
        assert_eq!(pin_verdict(attesa, impronta(8)), PinVerdict::Refused);
    }

    #[test]
    fn a_prefix_that_does_not_match_is_refused_too() {
        let attesa = HubExpectation::Enrollment(impronta(7).prefix());
        assert_eq!(pin_verdict(attesa, impronta(8)), PinVerdict::Refused);
    }

    #[test]
    fn a_connection_knows_whether_it_is_already_pinned() {
        let Ok(indirizzo) = HubAddress::parse("192.0.2.10:8443") else {
            panic!("indirizzo");
        };
        let dal_foglietto =
            HubConnection::new(indirizzo, HubExpectation::Enrollment(impronta(1).prefix()));
        assert!(!dal_foglietto.is_pinned());
        let appuntata = HubConnection::new(indirizzo, HubExpectation::Pinned(impronta(1)));
        assert!(appuntata.is_pinned());
    }

    #[test]
    fn only_a_station_with_no_hub_acquires_from_telegram() {
        assert_eq!(StationRole::of_station(false), StationRole::OwnAuthority);
        assert_eq!(StationRole::of_station(true), StationRole::HubClient);
        assert!(StationRole::OwnAuthority.may_acquire());
        assert!(
            !StationRole::HubClient.may_acquire(),
            "l'acquisizione la fa l'Hub, una volta sola per tutto l'ufficio"
        );
    }

    #[test]
    fn the_refusal_says_where_the_work_is_done() {
        let frase = StationRole::HubClient.acquisition_message();
        assert!(frase.contains("l'Hub"), "«{frase}»");
        assert!(
            frase.contains("chi amministra"),
            "il rifiuto deve dire di chi è l'atto che lo toglierebbe: «{frase}»"
        );
    }

    #[test]
    fn session_limits_without_a_ceiling_are_refused() {
        assert!(SessionLimits::default().is_usable());
        assert!(
            !SessionLimits {
                max_pages: 0,
                ..SessionLimits::default()
            }
            .is_usable()
        );
        assert!(
            !SessionLimits {
                max_events: 0,
                ..SessionLimits::default()
            }
            .is_usable()
        );
        assert!(
            !SessionLimits {
                max_duration: Duration::ZERO,
                ..SessionLimits::default()
            }
            .is_usable()
        );
    }
}

//! Le reti dell'ufficio: dove l'Hub può stare e da dove lo si raggiunge
//! (HUB-SITES-01, ADR-0198).
//!
//! # Mai Internet
//!
//! Un Hub serve le postazioni di una sede, e attraverso la VPN dell'ufficio
//! quelle delle altre sedi; non serve Internet. Senza dichiarazione valgono
//! gli intervalli che Internet non instrada per norma ([`DEFAULT_RANGES`]).
//! Un ufficio che usa al proprio interno indirizzi pubblici li dichiara: è
//! un'azione riservata, e un intervallo più largo di `/8` in IPv4 o di `/16` in
//! IPv6 non è la rete di un ufficio ([`OfficeNetwork::parse`]).
//!
//! # Gli indirizzi IPv4 dentro IPv6
//!
//! Una connessione IPv4 che arriva su un socket IPv6 si presenta come
//! `::ffff:a.b.c.d`. Il confronto usa la forma canonica: lo stesso computer non
//! deve essere dell'ufficio in una forma e fuori nell'altra.

use core::fmt;
use core::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{DomainError, DomainResult};

/// Il prefisso più largo ammesso in IPv4: un `/8` è già una rete enorme.
pub const IPV4_WIDEST_PREFIX: u8 = 8;

/// Il prefisso più largo ammesso in IPv6.
pub const IPV6_WIDEST_PREFIX: u8 = 16;

/// Quante reti si dichiarano al più.
pub const MAX_DECLARED_NETWORKS: usize = 32;

/// Un intervallo di indirizzi: l'indirizzo della rete e la lunghezza del
/// prefisso. I bit dell'ospite sono sempre a zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OfficeNetwork {
    network: IpAddr,
    prefix: u8,
}

/// Gli intervalli che Internet non instrada, per norma.
///
/// Gli indirizzi privati IPv4 (RFC 1918), lo spazio condiviso usato dalle VPN e
/// dagli operatori (RFC 6598), gli indirizzi locali unici IPv6 (RFC 4193) e il
/// proprio computer.
pub const DEFAULT_RANGES: [(&str, &str); 7] = [
    ("10.0.0.0/8", "indirizzi privati"),
    ("172.16.0.0/12", "indirizzi privati"),
    ("192.168.0.0/16", "indirizzi privati"),
    ("100.64.0.0/10", "indirizzi dei collegamenti fra le sedi"),
    ("127.0.0.0/8", "questo computer"),
    ("fc00::/7", "indirizzi privati"),
    ("::1/128", "questo computer"),
];

impl OfficeNetwork {
    /// Costruisce un intervallo, azzerando i bit dell'ospite.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidOfficeNetwork`] se il prefisso è oltre la
    /// lunghezza dell'indirizzo o più largo di quanto ammesso.
    pub fn try_new(address: IpAddr, prefix: u8) -> DomainResult<Self> {
        let address = canonical(address);
        let (bits, piu_largo) = match address {
            IpAddr::V4(_) => (32, IPV4_WIDEST_PREFIX),
            IpAddr::V6(_) => (128, IPV6_WIDEST_PREFIX),
        };
        if prefix > bits {
            return Err(DomainError::InvalidOfficeNetwork {
                reason: "il prefisso è più lungo dell'indirizzo",
            });
        }
        if prefix < piu_largo {
            return Err(DomainError::InvalidOfficeNetwork {
                reason: "un intervallo così largo non è la rete di un ufficio: è un pezzo di \
                         Internet",
            });
        }
        Ok(Self {
            network: mask(address, prefix),
            prefix,
        })
    }

    /// Riconosce la forma scritta: `10.20.0.0/16`, `fd00:1::/48`.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidOfficeNetwork`] se il testo non ha la forma
    /// indirizzo/prefisso o non supera [`Self::try_new`].
    pub fn parse(raw: &str) -> DomainResult<Self> {
        let pulito = raw.trim();
        let Some((indirizzo, prefisso)) = pulito.split_once('/') else {
            return Err(DomainError::InvalidOfficeNetwork {
                reason: "una rete si scrive come indirizzo e prefisso, per esempio 10.20.0.0/16",
            });
        };
        let indirizzo =
            IpAddr::from_str(indirizzo.trim()).map_err(|_| DomainError::InvalidOfficeNetwork {
                reason: "l'indirizzo della rete si scrive in cifre, mai con un nome",
            })?;
        let prefisso =
            u8::from_str(prefisso.trim()).map_err(|_| DomainError::InvalidOfficeNetwork {
                reason: "il prefisso è un numero intero",
            })?;
        Self::try_new(indirizzo, prefisso)
    }

    /// Se l'indirizzo sta dentro l'intervallo.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = canonical(address);
        match (self.network, address) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(address, self.prefix) == self.network
            }
            _ => false,
        }
    }

    /// Se l'intervallo sta tutto dentro quelli che Internet non instrada.
    #[must_use]
    pub fn is_not_routed_on_internet(&self) -> bool {
        default_networks()
            .iter()
            .any(|base| base.prefix <= self.prefix && base.contains(self.network))
    }
}

impl fmt::Display for OfficeNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

/// La forma canonica: un IPv4 dentro IPv6 torna IPv4.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(sei) => sei.to_ipv4_mapped().map_or(IpAddr::V6(sei), IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// Azzera i bit oltre il prefisso.
fn mask(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(quattro) => {
            let maschera = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(quattro) & maschera))
        }
        IpAddr::V6(sei) => {
            let maschera = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(sei) & maschera))
        }
    }
}

/// Gli intervalli predefiniti, come valori.
///
/// Non passano dal tetto di larghezza di [`OfficeNetwork::try_new`]: lo fissa
/// la norma, non chi dichiara, e `fc00::/7` è più largo di un `/16`. Scartarlo
/// in silenzio farebbe sembrare di fuori un indirizzo locale IPv6.
#[must_use]
pub fn default_networks() -> Vec<OfficeNetwork> {
    DEFAULT_RANGES
        .iter()
        .filter_map(|(testo, _)| {
            let (indirizzo, prefisso) = testo.split_once('/')?;
            let indirizzo = canonical(IpAddr::from_str(indirizzo).ok()?);
            let prefisso = u8::from_str(prefisso).ok()?;
            Some(OfficeNetwork {
                network: mask(indirizzo, prefisso),
                prefix: prefisso,
            })
        })
        .collect()
}

/// Le reti dell'ufficio di questa postazione: le predefinite più quelle
/// dichiarate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfficeNetworks {
    declared: Vec<OfficeNetwork>,
}

impl OfficeNetworks {
    /// Con le reti dichiarate, senza doppioni e in ordine.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidOfficeNetwork`] se sono più di
    /// [`MAX_DECLARED_NETWORKS`].
    pub fn try_new(mut declared: Vec<OfficeNetwork>) -> DomainResult<Self> {
        declared.sort();
        declared.dedup();
        if declared.len() > MAX_DECLARED_NETWORKS {
            return Err(DomainError::InvalidOfficeNetwork {
                reason: "si dichiarano al più trentadue reti",
            });
        }
        Ok(Self { declared })
    }

    /// Riconosce un elenco scritto, separato da virgole, spazi o righe. Un
    /// testo vuoto è l'elenco vuoto: valgono le sole predefinite.
    ///
    /// # Errori
    ///
    /// Il primo intervallo non valido, oppure troppi intervalli.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        let reti = raw
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .filter(|pezzo| !pezzo.trim().is_empty())
            .map(OfficeNetwork::parse)
            .collect::<DomainResult<Vec<_>>>()?;
        Self::try_new(reti)
    }

    /// Le reti dichiarate, senza le predefinite.
    #[must_use]
    pub fn declared(&self) -> &[OfficeNetwork] {
        &self.declared
    }

    /// Le reti dichiarate che Internet instrada: la schermata le dice.
    #[must_use]
    pub fn declared_routed_on_internet(&self) -> Vec<OfficeNetwork> {
        self.declared
            .iter()
            .copied()
            .filter(|rete| !rete.is_not_routed_on_internet())
            .collect()
    }

    /// Se l'indirizzo è dell'ufficio: dentro una rete predefinita o dichiarata.
    #[must_use]
    pub fn admits(&self, address: IpAddr) -> bool {
        default_networks()
            .iter()
            .chain(self.declared.iter())
            .any(|rete| rete.contains(address))
    }

    /// La forma scritta delle reti dichiarate, per conservarle.
    #[must_use]
    pub fn to_text(&self) -> String {
        self.declared
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::{OfficeNetwork, OfficeNetworks};
    use std::net::IpAddr;

    fn ip(testo: &str) -> IpAddr {
        let Ok(indirizzo) = testo.parse() else {
            panic!("indirizzo di prova non valido: {testo}");
        };
        indirizzo
    }

    #[test]
    fn senza_dichiarazione_valgono_gli_intervalli_che_internet_non_instrada() {
        let reti = OfficeNetworks::default();
        for dentro in [
            "10.1.2.3",
            "172.20.0.5",
            "192.168.1.10",
            "100.64.3.4",
            "127.0.0.1",
        ] {
            assert!(reti.admits(ip(dentro)), "{dentro}");
        }
        for dentro in ["fd12:3456::1", "::1", "::ffff:192.168.1.10"] {
            assert!(reti.admits(ip(dentro)), "{dentro}");
        }
        for fuori in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2001:4860::8888",
            "169.254.1.1",
        ] {
            assert!(!reti.admits(ip(fuori)), "{fuori}");
        }
    }

    #[test]
    fn ogni_intervallo_predefinito_si_legge() {
        assert_eq!(super::default_networks().len(), super::DEFAULT_RANGES.len());
    }

    #[test]
    fn una_rete_dichiarata_si_aggiunge_e_si_riconosce_pubblica() {
        let Ok(reti) = OfficeNetworks::parse("193.204.0.0/16, 10.20.0.0/16") else {
            panic!("reti valide rifiutate");
        };
        assert!(reti.admits(ip("193.204.5.6")));
        assert!(!reti.admits(ip("193.205.5.6")));
        let pubbliche = reti.declared_routed_on_internet();
        assert_eq!(pubbliche.len(), 1);
        assert_eq!(
            pubbliche.first().map(ToString::to_string).as_deref(),
            Some("193.204.0.0/16")
        );
        assert_eq!(reti.to_text(), "10.20.0.0/16, 193.204.0.0/16");
    }

    #[test]
    fn un_intervallo_troppo_largo_non_e_la_rete_di_un_ufficio() {
        assert!(OfficeNetwork::parse("0.0.0.0/0").is_err());
        assert!(OfficeNetwork::parse("64.0.0.0/2").is_err());
        assert!(OfficeNetwork::parse("2000::/3").is_err());
        assert!(OfficeNetwork::parse("10.0.0.0/8").is_ok());
        assert!(OfficeNetwork::parse("fd00::/16").is_ok());
    }

    #[test]
    fn la_forma_scritta_si_controlla() {
        for sbagliata in [
            "10.0.0.0",
            "ufficio.example/16",
            "10.0.0.0/x",
            "10.0.0.0/33",
        ] {
            assert!(OfficeNetwork::parse(sbagliata).is_err(), "{sbagliata}");
        }
        // I bit dell'ospite si azzerano.
        let Ok(rete) = OfficeNetwork::parse("10.20.30.40/16") else {
            panic!("rete valida rifiutata");
        };
        assert_eq!(rete.to_string(), "10.20.0.0/16");
        assert!(OfficeNetworks::parse("").is_ok_and(|reti| reti.declared().is_empty()));
    }
}

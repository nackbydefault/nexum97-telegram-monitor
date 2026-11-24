//! L'identità dell'Hub, come la conosce una postazione.
//!
//! # Che cosa è
//!
//! L'Hub è riconosciuto dalla sua **chiave pubblica**, e la postazione la
//! conosce per **impronta**: `SHA-256` della struttura `SubjectPublicKeyInfo`
//! codificata in DER (ADR-0082, decisione 2). Con le chiavi pubbliche nude di
//! ADR-0083 quella struttura è **proprio ciò che viaggia** nell'handshake: non
//! c'è un certificato da cui estrarla.
//!
//! # Due forme, due momenti
//!
//! - **All'arruolamento** la postazione ha soltanto ciò che una persona ha
//!   ricopiato dal foglietto: i primi **120 bit** dell'impronta, in **24 cifre
//!   di Crockford** a gruppi di quattro, con la stessa implementazione del
//!   codice di arruolamento ([`crate::model::readable_code`]). È
//!   [`HubFingerprintPrefix`].
//! - **Dopo la prima connessione verificata** conserva l'impronta **intera** e
//!   da lì confronta tutti i 256 bit. È [`HubFingerprint`].
//!
//! [`HubExpectation`] dice quale delle due la postazione ha in mano, e il
//! confronto è uno solo.
//!
//! # Che cosa questo modulo non fa
//!
//! Non parla in rete, non analizza chiavi e non verifica firme: calcola e
//! confronta impronte. **L'impronta da sola non autentica nessuno** — dimostra
//! soltanto che l'altro capo conosce una chiave pubblica, che è un dato
//! pubblico. La firma dell'handshake la verifica il trasporto (ADR-0083,
//! decisione 4).

use core::fmt;

use sha2::{Digest, Sha256};

use crate::error::{DomainError, DomainResult};
use crate::model::readable_code;

/// Byte di un'impronta intera.
pub const HUB_FINGERPRINT_BYTES: usize = 32;

/// Byte della forma portata fuori banda: 120 bit.
///
/// Centoventi bit entrano in ventiquattro cifre **senza avanzi**: non esistono
/// stringhe «quasi valide» da ricordarsi di rifiutare. Fabbricare una chiave
/// che coincida sui primi 120 bit è una seconda preimmagine da circa 2^120
/// operazioni (ADR-0082).
pub const HUB_FINGERPRINT_PREFIX_BYTES: usize = 15;

/// Cifre della forma leggibile, separatori esclusi.
pub const HUB_FINGERPRINT_PREFIX_DIGITS: usize = 24;

/// Cifre per gruppo nella forma leggibile: la stessa del codice di arruolamento.
const CIFRE_PER_GRUPPO: usize = 4;

/// L'impronta intera della chiave pubblica dell'Hub.
///
/// Non è un segreto: è l'impronta di un dato pubblico, e si mostra a chi
/// amministra. `Debug` la rende in esadecimale.
#[derive(Clone, Copy)]
pub struct HubFingerprint([u8; HUB_FINGERPRINT_BYTES]);

impl HubFingerprint {
    /// Calcola l'impronta di una `SubjectPublicKeyInfo` codificata in DER.
    ///
    /// Non verifica che i byte siano una chiave valida: l'impronta di dati
    /// qualsiasi è un'impronta che non coinciderà con quella attesa, e il
    /// confronto li rifiuta senza doverli analizzare.
    #[must_use]
    pub fn of_public_key_info(spki_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(spki_der);
        let mut bytes = [0_u8; HUB_FINGERPRINT_BYTES];
        bytes.copy_from_slice(&hasher.finalize());
        Self(bytes)
    }

    /// Ricostruisce un'impronta conservata.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HUB_FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Riconosce la forma esadecimale intera, quella mostrata a chi amministra.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidHubFingerprint`] se il testo non è di 64 cifre
    /// esadecimali. Il motivo è una costante: il testo può venire dalla rete.
    pub fn from_hex(raw: &str) -> DomainResult<Self> {
        let raw = raw.trim().as_bytes();
        if raw.len() != HUB_FINGERPRINT_BYTES * 2 {
            return Err(DomainError::InvalidHubFingerprint {
                reason: "non ha sessantaquattro caratteri",
            });
        }
        let mut bytes = [0_u8; HUB_FINGERPRINT_BYTES];
        for (indice, coppia) in raw.chunks_exact(2).enumerate() {
            let (Some(alto), Some(basso)) =
                (valore_esadecimale(coppia[0]), valore_esadecimale(coppia[1]))
            else {
                return Err(DomainError::InvalidHubFingerprint {
                    reason: "contiene un carattere non ammesso: sono ammesse solo cifre e lettere da a a f",
                });
            };
            bytes[indice] = (alto << 4) | basso;
        }
        Ok(Self(bytes))
    }

    /// I 256 bit dell'impronta.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HUB_FINGERPRINT_BYTES] {
        &self.0
    }

    /// La forma esadecimale intera, in minuscolo.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut testo = String::with_capacity(HUB_FINGERPRINT_BYTES * 2);
        for valore in self.0 {
            testo.push(cifra_esadecimale(valore >> 4));
            testo.push(cifra_esadecimale(valore & 0x0F));
        }
        testo
    }

    /// La forma da portare fuori banda: i primi 120 bit.
    #[must_use]
    pub fn prefix(&self) -> HubFingerprintPrefix {
        let mut bytes = [0_u8; HUB_FINGERPRINT_PREFIX_BYTES];
        bytes.copy_from_slice(&self.0[..HUB_FINGERPRINT_PREFIX_BYTES]);
        HubFingerprintPrefix(bytes)
    }
}

impl PartialEq for HubFingerprint {
    /// Confronto scritto per non uscire in anticipo sulla prima differenza.
    ///
    /// L'impronta non è un segreto, ma questo confronto **decide se l'altro capo
    /// è l'Hub**, e ADR-0083 chiede che non racconti a chi misura quante cifre
    /// ha indovinato. **Limite dichiarato:** il linguaggio non garantisce che
    /// resti tale dopo l'ottimizzazione — lo stesso limite di `DeviceSecret`.
    fn eq(&self, other: &Self) -> bool {
        uguali_senza_uscire_prima(&self.0, &other.0)
    }
}

impl Eq for HubFingerprint {}

impl fmt::Debug for HubFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HubFingerprint({})", self.to_hex())
    }
}

/// I primi 120 bit dell'impronta, nella forma che una persona ricopia.
#[derive(Clone, Copy)]
pub struct HubFingerprintPrefix([u8; HUB_FINGERPRINT_PREFIX_BYTES]);

impl HubFingerprintPrefix {
    /// Riconosce la forma ricopiata dal foglietto.
    ///
    /// Accetta minuscole, separatori mancanti e le confusioni di lettura
    /// previste dall'alfabeto, come il codice di arruolamento.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidHubFingerprint`] se le cifre non sono ventiquattro
    /// o se una di esse non appartiene all'alfabeto.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        let canonico =
            readable_code::canonicalize(raw, HUB_FINGERPRINT_PREFIX_DIGITS, CIFRE_PER_GRUPPO)
                .map_err(|forma| DomainError::InvalidHubFingerprint {
                    reason: match forma {
                        readable_code::FormaScorretta::CarattereEstraneo => {
                            "contiene un carattere che non appartiene all'alfabeto"
                        }
                        readable_code::FormaScorretta::Lunghezza => "non ha ventiquattro cifre",
                    },
                })?;
        readable_code::decode::<HUB_FINGERPRINT_PREFIX_BYTES>(&canonico)
            .map(Self)
            .ok_or(DomainError::InvalidHubFingerprint {
                reason: "non è scritto nella forma prevista",
            })
    }

    /// La forma leggibile: ventiquattro cifre in sei gruppi da quattro.
    #[must_use]
    pub fn to_readable(&self) -> String {
        readable_code::encode(&self.0, HUB_FINGERPRINT_PREFIX_DIGITS, CIFRE_PER_GRUPPO)
    }

    /// Se un'impronta intera comincia con questi 120 bit.
    #[must_use]
    pub fn matches(&self, fingerprint: &HubFingerprint) -> bool {
        uguali_senza_uscire_prima(&self.0, &fingerprint.0[..HUB_FINGERPRINT_PREFIX_BYTES])
    }
}

impl fmt::Debug for HubFingerprintPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HubFingerprintPrefix({})", self.to_readable())
    }
}

/// Che cosa la postazione sa dell'Hub a cui si collega.
///
/// **Non esiste una variante «qualunque Hub»**: nessun TOFU, nessuna radice del
/// sistema (ADR-0082). Una postazione che non ha né il foglietto né
/// un'impronta conservata non ha un Hub a cui collegarsi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubExpectation {
    /// All'arruolamento: i 120 bit ricopiati dal foglietto.
    Enrollment(HubFingerprintPrefix),
    /// Dopo la prima connessione verificata: tutti i 256 bit.
    Pinned(HubFingerprint),
}

impl HubExpectation {
    /// Se la chiave presentata è quella attesa.
    #[must_use]
    pub fn accepts(&self, presented: &HubFingerprint) -> bool {
        match self {
            Self::Enrollment(prefix) => prefix.matches(presented),
            Self::Pinned(fingerprint) => fingerprint == presented,
        }
    }
}

impl PartialEq for HubFingerprintPrefix {
    fn eq(&self, other: &Self) -> bool {
        uguali_senza_uscire_prima(&self.0, &other.0)
    }
}

impl Eq for HubFingerprintPrefix {}

/// Confronta due sequenze della stessa lunghezza senza fermarsi alla prima
/// differenza. Lunghezze diverse sono sempre diverse.
fn uguali_senza_uscire_prima(primo: &[u8], secondo: &[u8]) -> bool {
    if primo.len() != secondo.len() {
        return false;
    }
    let mut differenze = 0_u8;
    for (mio, suo) in primo.iter().zip(secondo.iter()) {
        differenze |= mio ^ suo;
    }
    differenze == 0
}

fn cifra_esadecimale(valore: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(valore & 0x0F)])
}

fn valore_esadecimale(carattere: u8) -> Option<u8> {
    match carattere {
        b'0'..=b'9' => Some(carattere - b'0'),
        b'a'..=b'f' => Some(carattere - b'a' + 10),
        b'A'..=b'F' => Some(carattere - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{HUB_FINGERPRINT_BYTES, HubExpectation, HubFingerprint, HubFingerprintPrefix};

    fn impronta(riempimento: u8) -> HubFingerprint {
        HubFingerprint::from_bytes([riempimento; HUB_FINGERPRINT_BYTES])
    }

    #[test]
    fn the_fingerprint_is_sha256_of_the_public_key_info() {
        // Vettore noto: SHA-256 della stringa vuota. Se la funzione usasse un
        // altro algoritmo, o togliesse o aggiungesse byte, cambierebbe.
        assert_eq!(
            HubFingerprint::of_public_key_info(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_readable_form_round_trips_and_has_twenty_four_digits() {
        let originale = HubFingerprint::of_public_key_info(b"chiave dell'Hub");
        let leggibile = originale.prefix().to_readable();
        assert_eq!(
            leggibile.len(),
            24 + 5,
            "sei gruppi da quattro, cinque trattini"
        );

        let ricopiata = leggibile.to_lowercase().replace('-', "").replace('0', "o");
        let Ok(riletta) = HubFingerprintPrefix::parse(&ricopiata) else {
            panic!("una forma ricopiata con le confusioni previste deve essere riconosciuta");
        };
        assert!(riletta.matches(&originale));
        assert_eq!(riletta, originale.prefix());
    }

    #[test]
    fn a_prefix_does_not_match_a_different_key() {
        let vera = HubFingerprint::of_public_key_info(b"chiave vera");
        let estranea = HubFingerprint::of_public_key_info(b"chiave estranea");
        assert!(!vera.prefix().matches(&estranea));
    }

    #[test]
    fn a_prefix_ignores_only_the_bits_it_does_not_carry() {
        // Stessi primi 120 bit, coda diversa: all'arruolamento coincide, e
        // proprio per questo dopo si confrontano tutti i 256 bit.
        let mut coda_diversa = [7_u8; HUB_FINGERPRINT_BYTES];
        coda_diversa[31] = 8;
        let a = impronta(7);
        let b = HubFingerprint::from_bytes(coda_diversa);

        assert!(HubExpectation::Enrollment(a.prefix()).accepts(&b));
        assert!(!HubExpectation::Pinned(a).accepts(&b));

        // Un solo bit dentro i 120 basta a rifiutare.
        let mut testa_diversa = [7_u8; HUB_FINGERPRINT_BYTES];
        testa_diversa[14] ^= 1;
        assert!(
            !HubExpectation::Enrollment(a.prefix())
                .accepts(&HubFingerprint::from_bytes(testa_diversa))
        );
    }

    #[test]
    fn malformed_readable_forms_are_rejected_with_a_constant_reason() {
        for sbagliata in [
            "",
            "ABCD",
            "ABCD-ABCD-ABCD-ABCD-ABCD-ABC",
            "ABCD-ABCD-ABCD-ABCD-ABCD-ABCDE",
            "ABCD-ABCD-ABCD-ABCD-ABCD-ABC!",
        ] {
            let Err(errore) = HubFingerprintPrefix::parse(sbagliata) else {
                panic!("«{sbagliata}» non deve essere riconosciuta");
            };
            assert!(
                !errore.to_string().contains(sbagliata) || sbagliata.is_empty(),
                "il motivo non deve ripetere il testo ricevuto"
            );
        }
    }

    #[test]
    fn the_hex_form_round_trips_and_rejects_malformed_text() {
        let originale = HubFingerprint::of_public_key_info(b"x");
        let Ok(riletta) = HubFingerprint::from_hex(&originale.to_hex().to_uppercase()) else {
            panic!("la forma esadecimale deve rileggersi");
        };
        assert_eq!(riletta, originale);

        assert!(HubFingerprint::from_hex("abc").is_err());
        assert!(HubFingerprint::from_hex(&"g".repeat(64)).is_err());
        // Multi-byte: la lunghezza in byte non deve bastare a passare.
        assert!(HubFingerprint::from_hex(&"é".repeat(32)).is_err());
    }
}

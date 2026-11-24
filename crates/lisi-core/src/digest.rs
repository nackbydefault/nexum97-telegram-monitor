//! Impronte SHA-256.
//!
//! Usate per riconoscere contenuti identici fra sessioni diverse e, dalle
//! milestone dei report, per il manifest di integrità.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::error::{DomainError, DomainResult};

/// Impronta SHA-256 in forma esadecimale minuscola.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Numero di caratteri esadecimali di un SHA-256.
    pub const HEX_LEN: usize = 64;

    /// Calcola l'impronta del testo indicato.
    #[must_use]
    pub fn of_text(text: &str) -> Self {
        Self::of_bytes(text.as_bytes())
    }

    /// Calcola l'impronta dei byte indicati.
    ///
    /// Il manifest di integrità impronta **i byte scritti sul file**, non il
    /// testo da cui sono stati ottenuti: sono la stessa cosa finché la
    /// codifica non cambia, e impegnarsi sui byte è ciò che rende la verifica
    /// ripetibile da chi riceve il documento e non ha il testo originale.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self::from_hasher(hasher)
    }

    /// Calcola l'impronta leggendo a blocchi, senza tenere in memoria l'intero
    /// flusso.
    ///
    /// Serve a improntare un file di dimensione non nota — per esempio un
    /// rapporto esportato durante la sua verifica — senza caricarlo per intero:
    /// un file enorme, lasciato nella cartella da un altro processo, non deve
    /// poter gonfiare la memoria di chi lo verifica.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore di lettura del flusso.
    pub fn of_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(Self::from_hasher(hasher))
    }

    /// Converte lo stato dell'hasher nella forma esadecimale minuscola.
    ///
    /// `write!` su `String` non può fallire, ma i requisiti vietano `unwrap`: la
    /// formattazione esadecimale è fatta a mano.
    fn from_hasher(hasher: Sha256) -> Self {
        let bytes = hasher.finalize();
        let mut hex = String::with_capacity(Self::HEX_LEN);
        for byte in bytes {
            hex.push(nibble_to_hex(byte >> 4));
            hex.push(nibble_to_hex(byte & 0x0f));
        }
        Self(hex)
    }

    /// Ricostruisce un'impronta già calcolata, per esempio letta dal database.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidDigest`] se il valore non è composto da
    /// esattamente 64 caratteri esadecimali.
    pub fn from_hex(raw: &str) -> DomainResult<Self> {
        let trimmed = raw.trim();
        if trimmed.len() != Self::HEX_LEN || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidDigest);
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    /// Rappresentazione esadecimale.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Impronta di un flusso scritto a pezzi, senza tenerlo in memoria.
///
/// Serve dove i byte si **producono** invece di leggersi: la verifica di una
/// copia cifrata decifra a blocchi e impronta ciò che esce, senza scrivere il
/// chiaro da nessuna parte (ENCRYPT-01, ADR-0175).
#[derive(Debug, Clone, Default)]
pub struct Sha256Writer {
    hasher: Sha256,
}

impl Sha256Writer {
    /// Un'impronta vuota.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// L'impronta di tutto ciò che è stato scritto.
    #[must_use]
    pub fn finish(self) -> Sha256Digest {
        Sha256Digest::from_hasher(self.hasher)
    }
}

impl std::io::Write for Sha256Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256Digest;
    use crate::error::DomainError;

    #[test]
    fn the_digest_of_the_empty_string_is_the_known_value() {
        assert_eq!(
            Sha256Digest::of_text("").as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_digest_of_abc_is_the_known_value() {
        assert_eq!(
            Sha256Digest::of_text("abc").as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_digest_of_bytes_and_of_the_same_text_coincide() {
        // Il manifest impronta i byte scritti; il testo e' la stessa cosa
        // finche' la codifica e' UTF-8, e questo test lo tiene vero.
        assert_eq!(
            Sha256Digest::of_bytes("città".as_bytes()),
            Sha256Digest::of_text("città")
        );
    }

    #[test]
    fn equal_texts_produce_equal_digests() {
        assert_eq!(
            Sha256Digest::of_text("messaggio identico"),
            Sha256Digest::of_text("messaggio identico")
        );
    }

    #[test]
    fn hashing_a_reader_matches_hashing_the_same_bytes() {
        // Il flusso a blocchi deve dare la stessa impronta del buffer intero,
        // anche quando i byte attraversano piu' letture del buffer interno.
        let payload = "città ripetuta ".repeat(10_000);
        let bytes = payload.as_bytes();
        let Ok(streamed) = Sha256Digest::of_reader(bytes) else {
            panic!("un lettore in memoria non deve fallire");
        };
        assert_eq!(streamed, Sha256Digest::of_bytes(bytes));
    }

    #[test]
    fn hashing_an_empty_reader_is_the_empty_digest() {
        let empty: &[u8] = &[];
        let Ok(digest) = Sha256Digest::of_reader(empty) else {
            panic!("un lettore vuoto non deve fallire");
        };
        assert_eq!(
            digest.as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn different_texts_produce_different_digests() {
        assert_ne!(
            Sha256Digest::of_text("messaggio a"),
            Sha256Digest::of_text("messaggio b")
        );
    }

    #[test]
    fn a_digest_is_reparsed_from_its_hexadecimal_form() {
        let original = Sha256Digest::of_text("contenuto");
        let Ok(restored) = Sha256Digest::from_hex(original.as_str()) else {
            panic!("l'impronta appena calcolata deve essere rileggibile");
        };
        assert_eq!(original, restored);
    }

    #[test]
    fn uppercase_hexadecimal_is_normalised_to_lowercase() {
        let upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let Ok(digest) = Sha256Digest::from_hex(upper) else {
            panic!("l'esadecimale maiuscolo deve essere accettato");
        };
        assert_eq!(digest.as_str(), upper.to_ascii_lowercase());
    }

    #[test]
    fn a_malformed_digest_is_rejected() {
        for malformed in ["", "abc", &"z".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert_eq!(
                Sha256Digest::from_hex(malformed),
                Err(DomainError::InvalidDigest),
                "'{malformed}' doveva essere rifiutato"
            );
        }
    }

    /// Scritta a pezzi, l'impronta è quella dei byte interi.
    #[test]
    fn the_writer_digest_is_the_digest_of_the_whole_stream() {
        use std::io::Write;

        let testo = "abc".repeat(50_000);
        let mut scrittore = super::Sha256Writer::new();
        for pezzo in testo.as_bytes().chunks(7_001) {
            let Ok(()) = scrittore.write_all(pezzo) else {
                panic!("la scrittura in memoria non può fallire");
            };
        }
        assert_eq!(scrittore.finish(), Sha256Digest::of_text(&testo));
    }
}

//! La copia cifrata: una chiave per copia, aperta da una frase (ENCRYPT-01,
//! ADR-0175).
//!
//! # Che cosa fa questo modulo, e che cosa no
//!
//! Cifra e decifra **un flusso di byte**: non sa che cosa sia un archivio, non
//! sceglie dove scrivere e non registra nulla. Il servizio che fa la copia
//! (`lisi-services`) decide la fotografia, la destinazione e l'audit.
//!
//! # Nessuna crittografia scritta qui
//!
//! AES-256-GCM viene da `aes-gcm` di RustCrypto, la famiglia di `argon2` che
//! il prodotto usa già; la frase diventa chiave con Argon2id; i byte casuali
//! dal generatore di sistema ([`crate::random_bytes`]). Qui c'è soltanto il
//! modo di **comporli**: la costruzione STREAM (Hoang, Reyhanitabar, Rogaway,
//! Vizár, 2015), la stessa di `age` e di Tink. `ring` resta del solo
//! trasporto (ADR-0083, decisione 8).
//!
//! # Il formato
//!
//! L'intestazione (vedere ADR-0175) porta firma, versione, parametri e sale di
//! Argon2id, la chiave della copia avvolta dalla frase, la stessa chiave
//! protetta da DPAPI dell'utente (facoltativa), il prefisso dei nonce e la
//! dimensione dei blocchi. Seguono i blocchi, ciascuno con la propria marca.
//! L'intestazione intera è il dato autenticato di ogni blocco: chi la ritocca
//! rende illeggibile la copia, non la cambia.
//!
//! # Un limite che il chiamante deve rispettare
//!
//! [`open`] scrive un blocco soltanto dopo averlo verificato, ma i blocchi
//! verificati **prima** di uno alterato sono già stati scritti quando arriva
//! il rifiuto. Chi apre deve scrivere in un posto provvisorio e scartarlo se
//! l'esito è un errore: un archivio a metà non è un archivio.

use std::fmt;
use std::io::{self, Read, Write};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::SecurityError;

/// Firma in testa al file: dice che cosa è prima di qualunque altra cosa.
pub const MAGIC: &[u8; 8] = b"NX97CPC1";

/// Versione del formato.
pub const FORMAT_VERSION: u8 = 1;

/// Caratteri minimi della frase che apre una copia.
pub const MIN_PHRASE_CHARS: usize = 16;

/// Memoria di Argon2id per la frase di una copia, in kibibyte (64 MiB).
///
/// Più del triplo di quella delle frasi d'accesso
/// ([`crate::passphrase::ARGON2_MEMORY_KIB`]): chi attacca una copia rubata ha
/// il file in mano e tutto il tempo che vuole.
pub const COPY_ARGON2_MEMORY_KIB: u32 = 65_536;

/// Passaggi di Argon2id per la frase di una copia.
pub const COPY_ARGON2_ITERATIONS: u32 = 3;

/// Corsie di Argon2id per la frase di una copia.
pub const COPY_ARGON2_PARALLELISM: u32 = 1;

/// Byte di testo in chiaro di un blocco.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// Byte della marca di autenticazione di AES-GCM.
const TAG_BYTES: usize = 16;

/// Byte della chiave della copia.
const KEY_BYTES: usize = 32;

/// Byte del nonce di AES-GCM.
const NONCE_LEN: usize = 12;

/// Byte del sale di Argon2id.
const SALT_BYTES: usize = 16;

/// Byte del prefisso casuale dei nonce dei blocchi.
const NONCE_PREFIX_BYTES: usize = 7;

/// Busta DPAPI più grande che si accetta in lettura.
const MAX_USER_ENVELOPE_BYTES: usize = 4096;

/// Tetti dei parametri letti da una copia: oltre, la copia si rifiuta prima di
/// impegnare la memoria che chiede.
const MAX_ARGON2_MEMORY_KIB: u32 = 1_048_576;
const MAX_ARGON2_ITERATIONS: u32 = 16;
const MAX_ARGON2_PARALLELISM: u32 = 8;

/// Perché una copia non si è cifrata o non si è aperta.
///
/// Nessuna variante porta la frase, la chiave o un byte del contenuto.
#[derive(Debug, thiserror::Error)]
pub enum SealedCopyError {
    /// La frase è più corta del minimo.
    #[error("la frase deve avere almeno {min} caratteri")]
    PhraseTooShort {
        /// Caratteri minimi.
        min: usize,
    },
    /// Il file non comincia con la firma di una copia cifrata.
    #[error("il file non è una copia cifrata di NEXUM/97")]
    NotASealedCopy,
    /// La copia è di una versione del formato che questo programma non legge.
    #[error("copia cifrata nella versione {0}, che questo programma non legge")]
    UnsupportedVersion(u8),
    /// L'intestazione non è leggibile o chiede valori fuori dai tetti.
    #[error("intestazione della copia cifrata non valida: {0}")]
    InvalidHeader(&'static str),
    /// La chiave della copia non si è aperta: frase sbagliata, oppure copia
    /// alterata. AES-GCM non distingue i due casi, e il messaggio non finge.
    #[error("la chiave della copia non si apre: frase sbagliata, oppure copia alterata")]
    KeyNotOpened,
    /// La copia non porta la chiave protetta per l'utente.
    #[error("la copia non si apre senza frase: è stata fatta senza la chiave dell'utente")]
    NoUserKey,
    /// La chiave protetta per l'utente non si apre con questo profilo Windows.
    #[error("la chiave dell'utente non si apre con questo profilo Windows")]
    UserKeyRefused,
    /// Un blocco non si verifica: la copia è alterata o danneggiata da lì.
    #[error("la copia è alterata o danneggiata dal blocco {index}")]
    ChunkRefused {
        /// Numero del blocco, da zero.
        index: u32,
    },
    /// La copia è troppo grande per il formato.
    #[error("la copia supera il numero di blocchi che il formato ammette")]
    TooLarge,
    /// Un guasto della protezione locale (generatore, DPAPI).
    #[error(transparent)]
    Security(#[from] SecurityError),
    /// Un guasto di lettura o scrittura.
    #[error("errore di lettura o scrittura della copia: {0}")]
    Io(#[from] io::Error),
    /// La libreria crittografica ha rifiutato un'operazione che non dovrebbe
    /// rifiutare.
    #[error("operazione crittografica non riuscita: {0}")]
    Crypto(&'static str),
}

/// Chi apre la copia.
pub enum Opener<'a> {
    /// La frase scelta quando la copia è stata fatta.
    Phrase(&'a str),
    /// L'utente Windows che l'ha fatta, sulla stessa postazione (DPAPI).
    User,
}

impl fmt::Debug for Opener<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // La frase non si stampa, nemmeno in un registro di prova.
        match self {
            Self::Phrase(_) => f.write_str("Opener::Phrase(«nascosta»)"),
            Self::User => f.write_str("Opener::User"),
        }
    }
}

/// Che cosa è passato per [`seal`] o [`open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Byte in chiaro.
    pub plaintext_bytes: u64,
    /// Blocchi.
    pub chunks: u32,
}

/// L'intestazione letta o composta.
struct Header {
    bytes: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; SALT_BYTES],
    wrap_nonce: [u8; NONCE_LEN],
    wrapped_key: [u8; KEY_BYTES + TAG_BYTES],
    /// Fin dove arriva il dato autenticato della chiave avvolta.
    wrap_aad_len: usize,
    user_envelope: Vec<u8>,
    nonce_prefix: [u8; NONCE_PREFIX_BYTES],
}

/// Cifra `input` in `output` con una chiave nuova, aperta da `phrase` e, se
/// `with_user_key`, anche dall'utente Windows corrente.
///
/// # Errori
///
/// [`SealedCopyError::PhraseTooShort`] prima di qualunque altra cosa; poi i
/// guasti del generatore, di DPAPI, della libreria o della scrittura.
pub fn seal<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    phrase: &str,
    with_user_key: bool,
) -> Result<Summary, SealedCopyError> {
    if phrase.chars().count() < MIN_PHRASE_CHARS {
        return Err(SealedCopyError::PhraseTooShort {
            min: MIN_PHRASE_CHARS,
        });
    }

    let mut chiave = Zeroizing::new([0_u8; KEY_BYTES]);
    crate::random_bytes(chiave.as_mut_slice())?;
    let mut salt = [0_u8; SALT_BYTES];
    crate::random_bytes(&mut salt)?;
    let mut wrap_nonce = [0_u8; NONCE_LEN];
    crate::random_bytes(&mut wrap_nonce)?;
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_BYTES];
    crate::random_bytes(&mut nonce_prefix)?;

    // LA PARTE FISSA, che è il dato autenticato della chiave avvolta.
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(MAGIC);
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(&COPY_ARGON2_MEMORY_KIB.to_be_bytes());
    bytes.extend_from_slice(&COPY_ARGON2_ITERATIONS.to_be_bytes());
    bytes.extend_from_slice(&COPY_ARGON2_PARALLELISM.to_be_bytes());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&wrap_nonce);
    let wrap_aad_len = bytes.len();

    let kek = derive_kek(
        phrase,
        &salt,
        COPY_ARGON2_MEMORY_KIB,
        COPY_ARGON2_ITERATIONS,
        COPY_ARGON2_PARALLELISM,
    )?;
    let mut avvolta = chiave.to_vec();
    aead_key(&kek)?
        .encrypt_in_place(
            &Nonce::<Aes256Gcm>::from(wrap_nonce),
            &bytes[..wrap_aad_len],
            &mut avvolta,
        )
        .map_err(|_| SealedCopyError::Crypto("la chiave della copia non si è cifrata"))?;
    bytes.extend_from_slice(&avvolta);

    let busta = if with_user_key {
        crate::dpapi::protect(chiave.as_slice())?
    } else {
        Vec::new()
    };
    let lunghezza = u32::try_from(busta.len())
        .map_err(|_| SealedCopyError::Crypto("chiave dell'utente troppo grande"))?;
    bytes.extend_from_slice(&lunghezza.to_be_bytes());
    bytes.extend_from_slice(&busta);
    bytes.extend_from_slice(&nonce_prefix);
    let chunk = u32::try_from(CHUNK_BYTES).map_err(|_| SealedCopyError::Crypto("blocco"))?;
    bytes.extend_from_slice(&chunk.to_be_bytes());

    output.write_all(&bytes)?;

    let key = aead_key(&chiave)?;
    let mut summary = Summary {
        plaintext_bytes: 0,
        chunks: 0,
    };
    let mut corrente = Zeroizing::new(Vec::with_capacity(CHUNK_BYTES + TAG_BYTES));
    let mut letti = read_up_to(&mut input, &mut corrente, CHUNK_BYTES)?;
    loop {
        // GUARDARE AVANTI DI UN BYTE dice se questo è l'ultimo blocco: un
        // file lungo esattamente un multiplo del blocco finisce con un blocco
        // pieno segnato come ultimo, non con un blocco vuoto in più.
        let mut avanti = [0_u8; 1];
        let ultimo = letti < CHUNK_BYTES || read_one(&mut input, &mut avanti)? == 0;
        summary.plaintext_bytes += letti as u64;
        key.encrypt_in_place(
            &chunk_nonce(&nonce_prefix, summary.chunks, ultimo),
            &bytes,
            &mut *corrente,
        )
        .map_err(|_| SealedCopyError::Crypto("un blocco non si è cifrato"))?;
        output.write_all(&corrente)?;
        summary.chunks = summary
            .chunks
            .checked_add(1)
            .ok_or(SealedCopyError::TooLarge)?;
        if ultimo {
            break;
        }
        corrente.clear();
        corrente.push(avanti[0]);
        letti = 1 + read_up_to(&mut input, &mut corrente, CHUNK_BYTES - 1)?;
    }
    output.flush()?;
    Ok(summary)
}

/// Decifra `input` in `output`, aprendo la chiave con `opener`.
///
/// Ogni blocco si scrive soltanto dopo essere stato verificato; vedere il
/// limite in testa al modulo per i blocchi già scritti prima di un rifiuto.
///
/// # Errori
///
/// [`SealedCopyError::NotASealedCopy`], [`SealedCopyError::UnsupportedVersion`]
/// o [`SealedCopyError::InvalidHeader`] per un file che non si lascia leggere;
/// [`SealedCopyError::KeyNotOpened`], [`SealedCopyError::NoUserKey`] o
/// [`SealedCopyError::UserKeyRefused`] per una chiave che non si apre;
/// [`SealedCopyError::ChunkRefused`] per un blocco alterato, scambiato o
/// mancante.
pub fn open<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    opener: &Opener<'_>,
) -> Result<Summary, SealedCopyError> {
    let header = read_header(&mut input)?;
    let chiave = open_key(&header, opener)?;
    let key = aead_key(&chiave)?;

    let mut summary = Summary {
        plaintext_bytes: 0,
        chunks: 0,
    };
    let pieno = CHUNK_BYTES + TAG_BYTES;
    let mut corrente = Zeroizing::new(Vec::with_capacity(pieno));
    let mut letti = read_up_to(&mut input, &mut corrente, pieno)?;
    loop {
        let mut avanti = [0_u8; 1];
        let ultimo = letti < pieno || read_one(&mut input, &mut avanti)? == 0;
        let indice = summary.chunks;
        key.decrypt_in_place(
            &chunk_nonce(&header.nonce_prefix, indice, ultimo),
            &header.bytes,
            &mut *corrente,
        )
        .map_err(|_| SealedCopyError::ChunkRefused { index: indice })?;
        let chiaro = corrente.as_slice();
        output.write_all(chiaro)?;
        summary.plaintext_bytes += chiaro.len() as u64;
        summary.chunks = indice.checked_add(1).ok_or(SealedCopyError::TooLarge)?;
        if ultimo {
            break;
        }
        corrente.clear();
        corrente.push(avanti[0]);
        letti = 1 + read_up_to(&mut input, &mut corrente, pieno - 1)?;
    }
    output.flush()?;
    Ok(summary)
}

/// Apre la chiave della copia.
fn open_key(
    header: &Header,
    opener: &Opener<'_>,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, SealedCopyError> {
    let mut chiave = Zeroizing::new([0_u8; KEY_BYTES]);
    match opener {
        Opener::Phrase(frase) => {
            let kek = derive_kek(
                frase,
                &header.salt,
                header.memory_kib,
                header.iterations,
                header.parallelism,
            )?;
            let mut avvolta = Zeroizing::new(header.wrapped_key.to_vec());
            aead_key(&kek)?
                .decrypt_in_place(
                    &Nonce::<Aes256Gcm>::from(header.wrap_nonce),
                    &header.bytes[..header.wrap_aad_len],
                    &mut *avvolta,
                )
                .map_err(|_| SealedCopyError::KeyNotOpened)?;
            if avvolta.len() != KEY_BYTES {
                return Err(SealedCopyError::KeyNotOpened);
            }
            chiave.copy_from_slice(&avvolta);
        }
        Opener::User => {
            if header.user_envelope.is_empty() {
                return Err(SealedCopyError::NoUserKey);
            }
            let aperta = Zeroizing::new(
                crate::dpapi::unprotect(&header.user_envelope)
                    .map_err(|_| SealedCopyError::UserKeyRefused)?,
            );
            if aperta.len() != KEY_BYTES {
                return Err(SealedCopyError::UserKeyRefused);
            }
            chiave.copy_from_slice(&aperta);
        }
    }
    Ok(chiave)
}

/// Legge l'intestazione, controllandone ogni campo prima di usarlo.
fn read_header<R: Read>(input: &mut R) -> Result<Header, SealedCopyError> {
    let mut bytes = Vec::with_capacity(256);
    let mut firma = [0_u8; 8];
    read_field(input, &mut firma, &mut bytes).map_err(|_| SealedCopyError::NotASealedCopy)?;
    if &firma != MAGIC {
        return Err(SealedCopyError::NotASealedCopy);
    }
    let mut versione = [0_u8; 1];
    read_field(input, &mut versione, &mut bytes)?;
    if versione[0] != FORMAT_VERSION {
        return Err(SealedCopyError::UnsupportedVersion(versione[0]));
    }
    let memory_kib = read_u32(input, &mut bytes)?;
    let iterations = read_u32(input, &mut bytes)?;
    let parallelism = read_u32(input, &mut bytes)?;
    if !(1..=MAX_ARGON2_MEMORY_KIB).contains(&memory_kib)
        || !(1..=MAX_ARGON2_ITERATIONS).contains(&iterations)
        || !(1..=MAX_ARGON2_PARALLELISM).contains(&parallelism)
    {
        return Err(SealedCopyError::InvalidHeader(
            "parametri della frase fuori dai tetti",
        ));
    }
    let mut salt = [0_u8; SALT_BYTES];
    read_field(input, &mut salt, &mut bytes)?;
    let mut wrap_nonce = [0_u8; NONCE_LEN];
    read_field(input, &mut wrap_nonce, &mut bytes)?;
    let wrap_aad_len = bytes.len();
    let mut wrapped_key = [0_u8; KEY_BYTES + TAG_BYTES];
    read_field(input, &mut wrapped_key, &mut bytes)?;
    let lunghezza = usize::try_from(read_u32(input, &mut bytes)?)
        .map_err(|_| SealedCopyError::InvalidHeader("chiave dell'utente"))?;
    if lunghezza > MAX_USER_ENVELOPE_BYTES {
        return Err(SealedCopyError::InvalidHeader(
            "chiave dell'utente troppo grande",
        ));
    }
    let mut user_envelope = vec![0_u8; lunghezza];
    read_field(input, &mut user_envelope, &mut bytes)?;
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_BYTES];
    read_field(input, &mut nonce_prefix, &mut bytes)?;
    let chunk = read_u32(input, &mut bytes)?;
    if usize::try_from(chunk).ok() != Some(CHUNK_BYTES) {
        return Err(SealedCopyError::InvalidHeader(
            "dimensione dei blocchi diversa da quella del formato",
        ));
    }
    Ok(Header {
        bytes,
        memory_kib,
        iterations,
        parallelism,
        salt,
        wrap_nonce,
        wrapped_key,
        wrap_aad_len,
        user_envelope,
        nonce_prefix,
    })
}

/// Legge un campo dell'intestazione e lo aggiunge ai byte autenticati.
fn read_field<R: Read>(
    input: &mut R,
    campo: &mut [u8],
    bytes: &mut Vec<u8>,
) -> Result<(), SealedCopyError> {
    input.read_exact(campo).map_err(|errore| {
        if errore.kind() == io::ErrorKind::UnexpectedEof {
            SealedCopyError::InvalidHeader("intestazione incompleta")
        } else {
            SealedCopyError::Io(errore)
        }
    })?;
    bytes.extend_from_slice(campo);
    Ok(())
}

fn read_u32<R: Read>(input: &mut R, bytes: &mut Vec<u8>) -> Result<u32, SealedCopyError> {
    let mut campo = [0_u8; 4];
    read_field(input, &mut campo, bytes)?;
    Ok(u32::from_be_bytes(campo))
}

/// Ricava dalla frase la chiave che avvolge quella della copia.
fn derive_kek(
    frase: &str,
    salt: &[u8; SALT_BYTES],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, SealedCopyError> {
    let parametri = Params::new(memory_kib, iterations, parallelism, Some(KEY_BYTES))
        .map_err(|_| SealedCopyError::InvalidHeader("parametri della frase non validi"))?;
    let mut kek = Zeroizing::new([0_u8; KEY_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parametri)
        .hash_password_into(frase.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|_| SealedCopyError::Crypto("la frase non ha dato una chiave"))?;
    Ok(kek)
}

fn aead_key(chiave: &[u8; KEY_BYTES]) -> Result<Aes256Gcm, SealedCopyError> {
    Aes256Gcm::new_from_slice(chiave).map_err(|_| SealedCopyError::Crypto("la chiave non è valida"))
}

/// Il nonce di un blocco: prefisso casuale, numero del blocco, segno di fine.
fn chunk_nonce(prefisso: &[u8; NONCE_PREFIX_BYTES], indice: u32, ultimo: bool) -> Nonce<Aes256Gcm> {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefisso);
    nonce[NONCE_PREFIX_BYTES..NONCE_LEN - 1].copy_from_slice(&indice.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(ultimo);
    Nonce::<Aes256Gcm>::from(nonce)
}

/// Aggiunge a `buffer` fino a `quanti` byte, fermandosi soltanto alla fine
/// del flusso. Restituisce quanti ne ha aggiunti.
fn read_up_to<R: Read>(
    input: &mut R,
    buffer: &mut Vec<u8>,
    quanti: usize,
) -> Result<usize, SealedCopyError> {
    let mut aggiunti = 0;
    let mut pezzo = Zeroizing::new(vec![0_u8; quanti]);
    while aggiunti < quanti {
        match input.read(&mut pezzo[aggiunti..]) {
            Ok(0) => break,
            Ok(n) => aggiunti += n,
            Err(errore) if errore.kind() == io::ErrorKind::Interrupted => {}
            Err(errore) => return Err(SealedCopyError::Io(errore)),
        }
    }
    buffer.extend_from_slice(&pezzo[..aggiunti]);
    Ok(aggiunti)
}

/// Legge un byte, o niente alla fine del flusso.
fn read_one<R: Read>(input: &mut R, uno: &mut [u8; 1]) -> Result<usize, SealedCopyError> {
    loop {
        match input.read(uno) {
            Ok(n) => return Ok(n),
            Err(errore) if errore.kind() == io::ErrorKind::Interrupted => {}
            Err(errore) => return Err(SealedCopyError::Io(errore)),
        }
    }
}

#[cfg(test)]
mod tests {
    // DPAPI e il generatore di sistema esistono soltanto su Windows.
    #[cfg(windows)]
    mod su_windows {

        use super::super::{
            CHUNK_BYTES, MAGIC, MIN_PHRASE_CHARS, Opener, SealedCopyError, TAG_BYTES, open, seal,
        };

        const FRASE: &str = "una frase di prova lunga abbastanza";

        fn contenuto(n: usize) -> Vec<u8> {
            (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
        }

        fn sigilla(chiaro: &[u8], con_utente: bool) -> Vec<u8> {
            let mut cifrato = Vec::new();
            let Ok(_) = seal(chiaro, &mut cifrato, FRASE, con_utente) else {
                panic!("la copia deve potersi cifrare");
            };
            cifrato
        }

        fn apri(cifrato: &[u8], chi: &Opener<'_>) -> Result<Vec<u8>, SealedCopyError> {
            let mut chiaro = Vec::new();
            open(cifrato, &mut chiaro, chi).map(|_| chiaro)
        }

        /// Dove comincia il primo blocco, letto dall'intestazione.
        fn inizio_dei_blocchi(cifrato: &[u8]) -> usize {
            let busta = 8 + 1 + 12 + 16 + 12 + 48;
            let lunghezza = u32::from_be_bytes([
                cifrato[busta],
                cifrato[busta + 1],
                cifrato[busta + 2],
                cifrato[busta + 3],
            ]);
            busta + 4 + usize::try_from(lunghezza).unwrap_or(0) + 7 + 4
        }

        #[test]
        fn una_copia_si_riapre_con_la_frase_e_con_l_utente() {
            // Le lunghezze che contano: vuota, corta, un blocco esatto, un blocco
            // e un byte, più blocchi.
            for n in [0, 1, CHUNK_BYTES, CHUNK_BYTES + 1, 3 * CHUNK_BYTES + 17] {
                let chiaro = contenuto(n);
                let cifrato = sigilla(&chiaro, true);
                assert_eq!(&cifrato[..8], MAGIC);
                assert_eq!(
                    apri(&cifrato, &Opener::Phrase(FRASE)).ok(),
                    Some(chiaro.clone())
                );
                assert_eq!(apri(&cifrato, &Opener::User).ok(), Some(chiaro), "{n} byte");
            }
        }

        #[test]
        fn il_contenuto_non_si_legge_nel_cifrato() {
            let chiaro = b"SQLite format 3\0".repeat(5000);
            let cifrato = sigilla(&chiaro, false);
            assert!(
                !cifrato.windows(15).any(|w| w == b"SQLite format 3"),
                "la firma dell'archivio in chiaro non deve comparire nella copia cifrata"
            );
        }

        #[test]
        fn una_frase_sbagliata_non_apre_la_copia() {
            let cifrato = sigilla(&contenuto(1000), true);
            assert!(matches!(
                apri(
                    &cifrato,
                    &Opener::Phrase("una frase di prova lunga abbastanzA")
                ),
                Err(SealedCopyError::KeyNotOpened)
            ));
        }

        #[test]
        fn una_frase_corta_non_cifra_niente() {
            let corta: String = "x".repeat(MIN_PHRASE_CHARS - 1);
            let mut cifrato = Vec::new();
            assert!(matches!(
                seal(&b"dati"[..], &mut cifrato, &corta, false),
                Err(SealedCopyError::PhraseTooShort { .. })
            ));
            assert!(
                cifrato.is_empty(),
                "un rifiuto non scrive nemmeno l'intestazione"
            );
        }

        #[test]
        fn senza_la_chiave_dell_utente_serve_la_frase() {
            let cifrato = sigilla(&contenuto(10), false);
            assert!(matches!(
                apri(&cifrato, &Opener::User),
                Err(SealedCopyError::NoUserKey)
            ));
        }

        #[test]
        fn un_byte_cambiato_in_un_blocco_si_rifiuta() {
            let chiaro = contenuto(2 * CHUNK_BYTES + 5);
            let mut cifrato = sigilla(&chiaro, false);
            let posto = inizio_dei_blocchi(&cifrato) + CHUNK_BYTES + TAG_BYTES + 3;
            cifrato[posto] ^= 0x01;
            assert!(matches!(
                apri(&cifrato, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::ChunkRefused { index: 1 })
            ));
        }

        #[test]
        fn un_intestazione_ritoccata_rende_illeggibile_la_copia() {
            let cifrato = sigilla(&contenuto(100), true);
            let inizio = inizio_dei_blocchi(&cifrato);
            // Il prefisso dei nonce: la chiave si apre, i blocchi no.
            let mut ritoccata = cifrato.clone();
            ritoccata[inizio - 5] ^= 0x01;
            assert!(matches!(
                apri(&ritoccata, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::ChunkRefused { index: 0 })
            ));
            // Il sale: la chiave non si apre.
            let mut ritoccata = cifrato.clone();
            ritoccata[8 + 1 + 12] ^= 0x01;
            assert!(matches!(
                apri(&ritoccata, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::KeyNotOpened)
            ));
            // La busta dell'utente fa parte del dato autenticato dei blocchi.
            let mut ritoccata = cifrato;
            ritoccata[8 + 1 + 12 + 16 + 12 + 48 + 4 + 2] ^= 0x01;
            assert!(apri(&ritoccata, &Opener::Phrase(FRASE)).is_err());
        }

        #[test]
        fn una_copia_troncata_si_rifiuta_anche_al_confine_di_un_blocco() {
            let chiaro = contenuto(2 * CHUNK_BYTES);
            let cifrato = sigilla(&chiaro, false);
            let inizio = inizio_dei_blocchi(&cifrato);
            // Tolto l'ultimo blocco intero: il penultimo non era segnato ultimo.
            let senza_ultimo = &cifrato[..inizio + CHUNK_BYTES + TAG_BYTES];
            assert!(matches!(
                apri(senza_ultimo, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::ChunkRefused { index: 0 })
            ));
            // Tolti pochi byte in fondo.
            let accorciata = &cifrato[..cifrato.len() - 3];
            assert!(matches!(
                apri(accorciata, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::ChunkRefused { index: 1 })
            ));
        }

        #[test]
        fn byte_in_piu_dopo_la_fine_si_rifiutano() {
            let mut cifrato = sigilla(&contenuto(100), false);
            cifrato.extend_from_slice(b"aggiunta");
            assert!(matches!(
                apri(&cifrato, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::ChunkRefused { index: 0 })
            ));
        }

        #[test]
        fn due_blocchi_scambiati_si_rifiutano() {
            let chiaro = contenuto(3 * CHUNK_BYTES);
            let mut cifrato = sigilla(&chiaro, false);
            let inizio = inizio_dei_blocchi(&cifrato);
            let pieno = CHUNK_BYTES + TAG_BYTES;
            let (primo, resto) = cifrato[inizio..].split_at_mut(pieno);
            primo.swap_with_slice(&mut resto[..pieno]);
            assert!(matches!(
                apri(&cifrato, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::ChunkRefused { index: 0 })
            ));
        }

        #[test]
        fn un_file_qualunque_non_e_una_copia_cifrata() {
            assert!(matches!(
                apri(b"SQLite format 3\0 e altro", &Opener::Phrase(FRASE)),
                Err(SealedCopyError::NotASealedCopy)
            ));
            let mut altra_versione = sigilla(&contenuto(1), false);
            altra_versione[8] = 2;
            assert!(matches!(
                apri(&altra_versione, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::UnsupportedVersion(2))
            ));
        }

        #[test]
        fn parametri_esagerati_si_rifiutano_prima_di_impegnare_memoria() {
            let mut cifrato = sigilla(&contenuto(1), false);
            cifrato[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(matches!(
                apri(&cifrato, &Opener::Phrase(FRASE)),
                Err(SealedCopyError::InvalidHeader(_))
            ));
        }

        #[test]
        fn due_copie_dello_stesso_contenuto_non_si_assomigliano() {
            let chiaro = contenuto(500);
            assert_ne!(
                sigilla(&chiaro, false),
                sigilla(&chiaro, false),
                "chiave, sale e nonce nuovi per ogni copia"
            );
        }

        #[test]
        fn la_frase_non_si_stampa() {
            let testo = format!("{:?}", Opener::Phrase(FRASE));
            assert!(!testo.contains(FRASE));
        }
    }
}

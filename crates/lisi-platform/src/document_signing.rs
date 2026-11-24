// SEDICESIMO modulo del crate autorizzato a contenere `unsafe`, dopo
// quelli elencati in `lib.rs`. Vedere ADR-0009 per la regola e ADR-0181 per la
// decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Firmare un file con il certificato dell'ufficio, chiedendolo a Windows.
//!
//! # Perché esiste accanto a `detached_signature`
//!
//! `detached_signature` legge una firma separata; questo modulo la scrive,
//! nella stessa forma: PKCS#7 (CMS, RFC 5652), il file come contenuto
//! separato, un firmatario, impronta SHA-256 (ADR-0181). Una firma scritta
//! qui si verifica là.
//!
//! # Perché si chiede a Windows
//!
//! Per la stessa ragione di `signature` e di `detached_signature` (ADR-0037):
//! la chiave sta nel fornitore di Windows, una chiave dell'utente o una smart
//! card, e non ne esce. Il programma riceve una maniglia, non la chiave.
//! Nessuna crittografia scritta qui.
//!
//! # Che cosa la firma porta
//!
//! Oltre agli attributi obbligatori, il **certificato del firmatario**
//! (`signingCertificateV2`, RFC 5035) e, quando chi chiama lo chiede,
//! l'**istante di firma** (`signingTime`): è il profilo di base CAdES. Nella
//! firma dentro un PDF l'istante non si mette, perché PAdES lo vuole nel
//! dizionario della firma.
//!
//! # Che cosa questo modulo NON decide
//!
//! **Quale certificato.** Riceve l'impronta SHA-256 di quello scelto
//! dall'amministratore; non sa che cosa sia un pacchetto o un dizionario.
//!
//! # Le invarianti dell'FFI
//!
//! 1. **Ogni maniglia ha un custode.** L'archivio, il certificato, la catena,
//!    la chiave e il messaggio sono posseduti da una struttura che li libera
//!    in `Drop`; un ritorno anticipato non ne perde nessuno. La chiave si
//!    chiede con `CRYPT_ACQUIRE_CACHE_FLAG`: Windows la tiene sul
//!    certificato e la libera con lui; si libera qui soltanto se Windows dice
//!    che tocca a chi l'ha chiesta.
//! 2. **I byte passati a Windows vivono più a lungo della chiamata.** Il
//!    contenuto è un `&[u8]` di chi chiama; gli attributi e le loro codifiche
//!    sono locali che vivono fino a dopo `CryptMsgUpdate`, l'ultima chiamata
//!    che li legge.
//! 3. **Le strutture di Windows puntano soltanto a memoria viva.** Gli
//!    identificatori di oggetto sono costanti terminate da zero; Windows li
//!    legge e non li scrive, anche dove il tipo dice `*mut`.
//! 4. **Nessun puntatore esce da questo modulo.** Escono copie: la firma, il
//!    certificato in DER, i nomi.
//! 5. **Nessuna rete.** La catena e la revoca si controllano con
//!    `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL`,
//!    `CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY` e senza aggiornamento
//!    automatico delle radici: ciò che la postazione non sa resta non saputo,
//!    e lo si dice (ADR-0181, decisione 5).
//! 6. **Nessuna chiave si apre per elencare.** L'elenco dei certificati
//!    guarda se una chiave c'è, senza aprirla: una smart card non chiede il
//!    PIN per farsi elencare.

use std::time::SystemTime;

/// Un certificato dell'archivio personale con una chiave privata: uno di
/// quelli fra cui l'amministratore sceglie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningCertificate {
    /// Il nome del titolare, come Windows lo mostra.
    pub subject: String,
    /// Il nome di chi l'ha emesso.
    pub issuer: String,
    /// Fino a quando vale, in secondi dal 1970 (UTC).
    pub not_after_unix: i64,
    /// L'impronta SHA-256 del certificato: è ciò che si sceglie e si scrive.
    pub sha256: [u8; 32],
}

/// Che cosa la postazione sa della revoca del certificato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationKnowledge {
    /// Controllata con le liste presenti sulla postazione: non è revocato.
    NotRevoked,
    /// La postazione non lo sa: nessuna lista, e la rete non si apre.
    Unknown,
}

/// Una firma separata appena fatta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    /// La firma, CMS in DER: il file `.p7s`.
    pub signature: Vec<u8>,
    /// Il certificato del firmatario, in DER.
    pub signer_certificate: Vec<u8>,
    /// Che cosa si sa della revoca.
    pub revocation: RevocationKnowledge,
}

/// Perché non si è firmato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningRefusal {
    /// Nell'archivio personale non c'è un certificato con quell'impronta.
    CertificateNotFound,
    /// Il certificato c'è, ma la sua chiave privata non è raggiungibile.
    NoPrivateKey,
    /// Il certificato, o uno della sua catena, non è valido adesso.
    NotValidNow,
    /// Il certificato dichiara usi che non comprendono la firma.
    NotForSigning,
    /// Il certificato risulta revocato.
    Revoked,
    /// Il certificato non risale a una radice di questa postazione.
    ChainNotTrusted {
        /// Il codice di Windows, per chi indaga.
        code: u32,
    },
    /// La firma non si è potuta fare.
    Failed {
        /// Perché.
        reason: String,
    },
}

impl SigningRefusal {
    /// La frase per una persona.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::CertificateNotFound => {
                String::from("Il certificato scelto non è fra quelli di questo utente di Windows.")
            }
            Self::NoPrivateKey => String::from(
                "Il certificato c'è, ma la sua chiave non si raggiunge. Se la chiave sta su \
                 un supporto, prima di firmare va inserito il supporto.",
            ),
            Self::NotValidNow => String::from("Il certificato è scaduto, o non vale ancora."),
            Self::NotForSigning => String::from("Il certificato non è fatto per firmare."),
            Self::Revoked => String::from("Il certificato è stato revocato: non si firma."),
            Self::ChainNotTrusted { code } => format!(
                "Questa postazione non riconosce l'autorità del certificato. Codice di \
                 Windows: {code:#010x}."
            ),
            Self::Failed { reason } => format!("La firma non si è potuta fare: {reason}."),
        }
    }
}

/// I certificati dell'archivio personale dell'utente che hanno una chiave
/// privata. Non apre nessuna chiave (invariante 6).
#[must_use]
pub fn signing_certificates() -> Vec<SigningCertificate> {
    windows_impl::elenca(&windows_impl::Origine::DellaPostazione)
}

/// Firma `content` con il certificato dell'archivio personale che ha
/// l'impronta SHA-256 indicata.
///
/// Con `signing_time` la firma porta quell'istante; senza, non ne porta
/// (la firma dentro un PDF). Non scrive file, non va in rete. Se la chiave
/// sta su una smart card, è Windows a chiedere il PIN, con la sua finestra.
///
/// # Errors
///
/// [`SigningRefusal`], con il motivo.
pub fn sign_detached(
    content: &[u8],
    certificate_sha256: &[u8; 32],
    signing_time: Option<SystemTime>,
) -> Result<DetachedSignature, SigningRefusal> {
    windows_impl::firma(
        content,
        certificate_sha256,
        signing_time,
        &windows_impl::Origine::DellaPostazione,
    )
}

/// Il valore dell'attributo `signingCertificateV2` (RFC 5035) per un
/// certificato di cui si conosce l'impronta SHA-256.
///
/// ```text
/// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
/// ESSCertIDv2 ::= SEQUENCE { certHash OCTET STRING }   -- SHA-256, il valore predefinito
/// ```
///
/// La struttura ha una lunghezza fissa: l'algoritmo predefinito si omette e
/// l'impronta è sempre di 32 byte. Non c'è niente da calcolare, soltanto da
/// mettere in fila.
fn signing_certificate_v2(impronta: &[u8; 32]) -> [u8; 40] {
    let mut valore = [0_u8; 40];
    valore[..8].copy_from_slice(&[0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20]);
    valore[8..].copy_from_slice(impronta);
    valore
}

/// Un istante come FILETIME di Windows: centinaia di nanosecondi dal 1601.
fn filetime(istante: SystemTime) -> Option<u64> {
    const DAL_1601_AL_1970: u64 = 116_444_736_000_000_000;
    let dal_1970 = istante.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    let centinaia = u64::try_from(dal_1970.as_nanos() / 100).ok()?;
    centinaia.checked_add(DAL_1601_AL_1970)
}

#[cfg(windows)]
pub(crate) mod windows_impl {
    use std::ffi::c_void;
    use std::time::SystemTime;

    use windows_sys::Win32::Foundation::{CERT_E_EXPIRED, CRYPT_E_REVOKED, FILETIME};
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_SHA256_ALGORITHM, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT,
        CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_BASE,
        CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS, CERT_CHAIN_POLICY_PARA,
        CERT_CHAIN_POLICY_STATUS, CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, CERT_CONTEXT,
        CERT_DIGITAL_SIGNATURE_KEY_USAGE, CERT_KEY_CONTEXT_PROP_ID, CERT_KEY_PROV_INFO_PROP_ID,
        CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NCRYPT_KEY_HANDLE_PROP_ID,
        CERT_NCRYPT_KEY_SPEC, CERT_NON_REPUDIATION_KEY_USAGE, CERT_STORE_OPEN_EXISTING_FLAG,
        CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_TRUST_IS_REVOKED, CERT_TRUST_REVOCATION_STATUS_UNKNOWN, CMSG_CONTENT_PARAM,
        CMSG_DETACHED_FLAG, CMSG_SIGNED, CMSG_SIGNED_ENCODE_INFO, CMSG_SIGNER_ENCODE_INFO,
        CMSG_SIGNER_ENCODE_INFO_0, CRYPT_ACQUIRE_CACHE_FLAG, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
        CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_ATTRIBUTE,
        CRYPT_INTEGER_BLOB, CertCloseStore, CertDuplicateCertificateContext,
        CertEnumCertificatesInStore, CertFreeCertificateChain, CertFreeCertificateContext,
        CertGetCertificateChain, CertGetCertificateContextProperty, CertGetIntendedKeyUsage,
        CertGetNameStringW, CertOpenStore, CertVerifyCertificateChainPolicy,
        CertVerifyTimeValidity, CryptAcquireCertificatePrivateKey, CryptEncodeObject,
        CryptHashCertificate2, CryptMsgClose, CryptMsgGetParam, CryptMsgOpenToEncode,
        CryptMsgUpdate, CryptReleaseContext, HCERTCHAINENGINE, HCERTSTORE, NCryptFreeObject,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING, szOID_NIST_sha256, szOID_RSA_signingTime,
    };

    use super::{
        DetachedSignature, RevocationKnowledge, SigningCertificate, SigningRefusal, filetime,
        signing_certificate_v2,
    };

    /// La codifica di messaggi e certificati.
    const CODIFICA: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    /// L'identificatore di `signingCertificateV2` (RFC 5035), terminato da
    /// zero (invariante 3).
    const OID_SIGNING_CERTIFICATE_V2: &[u8] = b"1.2.840.113549.1.9.16.2.47\0";

    /// Da dove vengono i certificati e contro quali radici si controllano.
    pub enum Origine {
        /// L'archivio personale dell'utente e le radici della postazione:
        /// l'unico caso fuori dalle prove.
        DellaPostazione,
        /// Un archivio e un motore di catene di prova (vedi `tests`).
        #[cfg(test)]
        DiProva {
            archivio: HCERTSTORE,
            motore: HCERTCHAINENGINE,
        },
    }

    /// Un archivio di certificati aperto.
    struct Archivio {
        maniglia: HCERTSTORE,
        /// Se lo si chiude qui: quello di prova lo chiude la prova.
        proprio: bool,
    }
    impl Drop for Archivio {
        fn drop(&mut self) {
            if self.proprio {
                // SAFETY: la maniglia viene da `CertOpenStore`, non è nulla e
                // si chiude una volta sola. I certificati ancora aperti lo
                // tengono vivo finché non sono liberati.
                let _ = unsafe { CertCloseStore(self.maniglia, 0) };
            }
        }
    }

    /// Un certificato preso dall'archivio.
    struct Certificato(*mut CERT_CONTEXT);
    impl Drop for Certificato {
        fn drop(&mut self) {
            // SAFETY: il contesto viene da `CertDuplicateCertificateContext`,
            // non è nullo e si libera una volta sola.
            let _ = unsafe { CertFreeCertificateContext(self.0) };
        }
    }

    /// La catena costruita da Windows.
    struct Catena(*mut CERT_CHAIN_CONTEXT);
    impl Drop for Catena {
        fn drop(&mut self) {
            // SAFETY: il contesto viene da `CertGetCertificateChain`, non è
            // nullo e si libera una volta sola.
            unsafe { CertFreeCertificateChain(self.0) };
        }
    }

    /// La maniglia della chiave privata, liberata soltanto se tocca a noi.
    struct Chiave {
        maniglia: usize,
        specie: u32,
        da_liberare: bool,
    }
    impl Drop for Chiave {
        fn drop(&mut self) {
            if !self.da_liberare {
                return;
            }
            // SAFETY: la maniglia viene da `CryptAcquireCertificatePrivateKey`,
            // che ha detto che tocca a chi l'ha chiesta liberarla; la specie
            // dice se è di CNG o del vecchio fornitore.
            unsafe {
                if self.specie == CERT_NCRYPT_KEY_SPEC {
                    let _ = NCryptFreeObject(self.maniglia);
                } else {
                    let _ = CryptReleaseContext(self.maniglia, 0);
                }
            }
        }
    }

    /// Il messaggio CMS in costruzione.
    struct Messaggio(*mut c_void);
    impl Drop for Messaggio {
        fn drop(&mut self) {
            // SAFETY: la maniglia viene da `CryptMsgOpenToEncode`, non è nulla
            // e si chiude una volta sola.
            let _ = unsafe { CryptMsgClose(self.0) };
        }
    }

    fn apri(origine: &Origine) -> Option<Archivio> {
        match origine {
            Origine::DellaPostazione => {
                let nome = windows_sys::core::w!("MY");
                // SAFETY: `nome` è una stringa costante terminata da zero; si
                // apre in sola lettura un archivio che esiste già.
                let maniglia = unsafe {
                    CertOpenStore(
                        CERT_STORE_PROV_SYSTEM_W,
                        0,
                        0,
                        CERT_SYSTEM_STORE_CURRENT_USER
                            | CERT_STORE_READONLY_FLAG
                            | CERT_STORE_OPEN_EXISTING_FLAG,
                        nome.cast::<c_void>(),
                    )
                };
                (!maniglia.is_null()).then_some(Archivio {
                    maniglia,
                    proprio: true,
                })
            }
            #[cfg(test)]
            Origine::DiProva { archivio, .. } => Some(Archivio {
                maniglia: *archivio,
                proprio: false,
            }),
        }
    }

    const fn motore(origine: &Origine) -> HCERTCHAINENGINE {
        match origine {
            Origine::DellaPostazione => std::ptr::null_mut(),
            #[cfg(test)]
            Origine::DiProva { motore, .. } => *motore,
        }
    }

    /// I byte del certificato, presi in prestito dal contesto.
    ///
    /// # Safety
    ///
    /// `contesto` è un contesto aperto, che vive più a lungo del risultato.
    unsafe fn der<'a>(contesto: *const CERT_CONTEXT) -> &'a [u8] {
        // SAFETY: per il contratto della funzione; `pbCertEncoded` punta a
        // `cbCertEncoded` byte validi finché il contesto vive.
        unsafe {
            let contesto = &*contesto;
            let lunghezza = usize::try_from(contesto.cbCertEncoded).unwrap_or(0);
            if contesto.pbCertEncoded.is_null() || lunghezza == 0 {
                return &[];
            }
            std::slice::from_raw_parts(contesto.pbCertEncoded, lunghezza)
        }
    }

    /// L'impronta SHA-256 di un certificato in DER, calcolata da Windows.
    pub fn impronta(der: &[u8]) -> Option<[u8; 32]> {
        let lunghezza = u32::try_from(der.len()).ok()?;
        let mut impronta = [0_u8; 32];
        let mut dimensione: u32 = 32;
        // SAFETY: `der` è viva per la chiamata e ne dichiariamo la lunghezza;
        // `impronta` ha i 32 byte dichiarati in `dimensione`.
        let ok = unsafe {
            CryptHashCertificate2(
                BCRYPT_SHA256_ALGORITHM,
                0,
                std::ptr::null(),
                der.as_ptr(),
                lunghezza,
                impronta.as_mut_ptr(),
                &raw mut dimensione,
            )
        };
        (ok != 0 && dimensione == 32).then_some(impronta)
    }

    /// Se il certificato ha una chiave privata, senza aprirla (invariante 6).
    fn ha_chiave(contesto: *const CERT_CONTEXT) -> bool {
        [
            CERT_KEY_PROV_INFO_PROP_ID,
            CERT_KEY_CONTEXT_PROP_ID,
            CERT_NCRYPT_KEY_HANDLE_PROP_ID,
        ]
        .into_iter()
        .any(|proprieta| {
            let mut dimensione: u32 = 0;
            // SAFETY: il contesto è aperto; con il puntatore ai dati nullo
            // Windows scrive soltanto la dimensione.
            unsafe {
                CertGetCertificateContextProperty(
                    contesto,
                    proprieta,
                    std::ptr::null_mut(),
                    &raw mut dimensione,
                ) != 0
            }
        })
    }

    /// Un nome del certificato, del titolare o dell'emittente.
    pub fn nome(contesto: *const CERT_CONTEXT, emittente: bool) -> String {
        let bandiere = if emittente { CERT_NAME_ISSUER_FLAG } else { 0 };
        let mut buffer = [0_u16; 256];
        let capienza = u32::try_from(buffer.len()).unwrap_or(0);
        // SAFETY: il contesto è aperto; `buffer` ha la capienza dichiarata, e
        // Windows termina il nome con uno zero dentro quella capienza.
        let scritti = unsafe {
            CertGetNameStringW(
                contesto,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                bandiere,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                capienza,
            )
        };
        let lunghezza = usize::try_from(scritti).unwrap_or(0).saturating_sub(1);
        String::from_utf16_lossy(&buffer[..lunghezza.min(buffer.len())])
    }

    /// La scadenza del certificato, in secondi dal 1970.
    pub fn scadenza(contesto: *const CERT_CONTEXT) -> i64 {
        // SAFETY: il contesto è aperto e `pCertInfo` punta alla sua parte
        // decodificata, viva quanto il contesto.
        let fine = unsafe {
            let info = &*(*contesto).pCertInfo;
            (u64::from(info.NotAfter.dwHighDateTime) << 32) | u64::from(info.NotAfter.dwLowDateTime)
        };
        let secondi = (fine / 10_000_000).saturating_sub(11_644_473_600);
        i64::try_from(secondi).unwrap_or(i64::MAX)
    }

    /// Scorre l'archivio; per ogni certificato chiama `ogni`, che dice se
    /// fermarsi tenendo una copia di quel certificato.
    fn scorri(
        archivio: &Archivio,
        mut ogni: impl FnMut(*const CERT_CONTEXT) -> bool,
    ) -> Option<Certificato> {
        let mut corrente: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            // SAFETY: l'archivio è aperto; `corrente` è nullo o il contesto
            // restituito dalla chiamata precedente, che Windows libera qui.
            corrente = unsafe { CertEnumCertificatesInStore(archivio.maniglia, corrente) };
            if corrente.is_null() {
                return None;
            }
            if ogni(corrente) {
                // SAFETY: `corrente` è aperto; la copia ha un custode suo, e
                // l'originale si libera qui, una volta sola, perché lo scorrere
                // si ferma.
                let copia = unsafe {
                    let copia = CertDuplicateCertificateContext(corrente);
                    let _ = CertFreeCertificateContext(corrente);
                    copia
                };
                return (!copia.is_null()).then_some(Certificato(copia));
            }
        }
    }

    pub fn elenca(origine: &Origine) -> Vec<SigningCertificate> {
        let Some(archivio) = apri(origine) else {
            return Vec::new();
        };
        let mut trovati = Vec::new();
        let _ = scorri(&archivio, |contesto| {
            if ha_chiave(contesto) {
                // SAFETY: il contesto è aperto per tutta la closure.
                if let Some(sha256) = impronta(unsafe { der(contesto) }) {
                    trovati.push(SigningCertificate {
                        subject: nome(contesto, false),
                        issuer: nome(contesto, true),
                        not_after_unix: scadenza(contesto),
                        sha256,
                    });
                }
            }
            false
        });
        trovati
    }

    fn fallita(reason: &str) -> SigningRefusal {
        SigningRefusal::Failed {
            reason: String::from(reason),
        }
    }

    /// La catena e la revoca, senza rete (invariante 5).
    fn controlla_catena(
        certificato: &Certificato,
        archivio: &Archivio,
        origine: &Origine,
    ) -> Result<RevocationKnowledge, SigningRefusal> {
        let parametri = CERT_CHAIN_PARA {
            cbSize: u32::try_from(size_of::<CERT_CHAIN_PARA>()).unwrap_or(0),
            ..Default::default()
        };
        let mut catena: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        // SAFETY: il certificato e l'archivio sono aperti; `parametri` e
        // `catena` sono locali e vivi per la chiamata. Un tempo nullo vuol
        // dire adesso.
        let ok = unsafe {
            CertGetCertificateChain(
                motore(origine),
                certificato.0,
                std::ptr::null(),
                archivio.maniglia,
                &raw const parametri,
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
                    | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
                    | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
                    | CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                std::ptr::null(),
                &raw mut catena,
            )
        };
        if ok == 0 || catena.is_null() {
            return Err(fallita(
                "Windows non ha costruito la catena del certificato",
            ));
        }
        let catena = Catena(catena);
        // SAFETY: la catena è aperta; si leggono due numeri e un contatore.
        let (errori, anelli) = unsafe {
            let contesto = &*catena.0;
            let anelli = if contesto.cChain == 0 || contesto.rgpChain.is_null() {
                0
            } else {
                (**contesto.rgpChain).cElement
            };
            (contesto.TrustStatus.dwErrorStatus, anelli)
        };
        if errori & CERT_TRUST_IS_REVOKED != 0 {
            return Err(SigningRefusal::Revoked);
        }

        let politica = CERT_CHAIN_POLICY_PARA {
            cbSize: u32::try_from(size_of::<CERT_CHAIN_POLICY_PARA>()).unwrap_or(0),
            dwFlags: CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS,
            ..Default::default()
        };
        let mut stato = CERT_CHAIN_POLICY_STATUS {
            cbSize: u32::try_from(size_of::<CERT_CHAIN_POLICY_STATUS>()).unwrap_or(0),
            ..Default::default()
        };
        // SAFETY: la catena è aperta; `politica` e `stato` sono locali e vivi
        // per la chiamata, con la dimensione dichiarata.
        let ok = unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_BASE,
                catena.0,
                &raw const politica,
                &raw mut stato,
            )
        };
        if ok == 0 {
            return Err(fallita("Windows non ha valutato la catena del certificato"));
        }
        match stato.dwError {
            0 => {}
            codice if codice == CERT_E_EXPIRED.cast_unsigned() => {
                return Err(SigningRefusal::NotValidNow);
            }
            codice if codice == CRYPT_E_REVOKED.cast_unsigned() => {
                return Err(SigningRefusal::Revoked);
            }
            code => return Err(SigningRefusal::ChainNotTrusted { code }),
        }
        // Un certificato che è la propria radice non ha nessuno che lo
        // revochi: «non revocato» lo si dice soltanto quando la revoca si è
        // davvero controllata.
        if anelli < 2 || errori & CERT_TRUST_REVOCATION_STATUS_UNKNOWN != 0 {
            Ok(RevocationKnowledge::Unknown)
        } else {
            Ok(RevocationKnowledge::NotRevoked)
        }
    }

    /// Codifica l'istante di firma, con il codificatore di Windows.
    fn codifica_istante(istante: SystemTime) -> Result<Vec<u8>, SigningRefusal> {
        let centinaia = filetime(istante).ok_or_else(|| fallita("l'orologio è prima del 1970"))?;
        let tempo = FILETIME {
            dwLowDateTime: u32::try_from(centinaia & 0xFFFF_FFFF).unwrap_or(0),
            dwHighDateTime: u32::try_from(centinaia >> 32).unwrap_or(0),
        };
        let mut dimensione: u32 = 0;
        // SAFETY: `tempo` è locale e vivo; con il buffer nullo Windows scrive
        // soltanto la dimensione.
        let ok = unsafe {
            CryptEncodeObject(
                CODIFICA,
                szOID_RSA_signingTime,
                (&raw const tempo).cast::<c_void>(),
                std::ptr::null_mut(),
                &raw mut dimensione,
            )
        };
        if ok == 0 {
            return Err(fallita("Windows non ha scritto l'istante"));
        }
        let mut codificato = vec![0_u8; usize::try_from(dimensione).unwrap_or(0)];
        // SAFETY: `codificato` ha i byte dichiarati in `dimensione`.
        let ok = unsafe {
            CryptEncodeObject(
                CODIFICA,
                szOID_RSA_signingTime,
                (&raw const tempo).cast::<c_void>(),
                codificato.as_mut_ptr(),
                &raw mut dimensione,
            )
        };
        if ok == 0 {
            return Err(fallita("Windows non ha scritto l'istante"));
        }
        codificato.truncate(usize::try_from(dimensione).unwrap_or(0));
        Ok(codificato)
    }

    pub fn firma(
        content: &[u8],
        certificate_sha256: &[u8; 32],
        signing_time: Option<SystemTime>,
        origine: &Origine,
    ) -> Result<DetachedSignature, SigningRefusal> {
        let lunghezza_contenuto =
            u32::try_from(content.len()).map_err(|_| fallita("il file è troppo grande"))?;
        let archivio =
            apri(origine).ok_or_else(|| fallita("l'archivio dei certificati non si apre"))?;

        // IL CERTIFICATO SCELTO.
        let certificato = scorri(&archivio, |contesto| {
            // SAFETY: il contesto è aperto per tutta la closure.
            impronta(unsafe { der(contesto) }).as_ref() == Some(certificate_sha256)
        })
        .ok_or(SigningRefusal::CertificateNotFound)?;
        // SAFETY: il certificato è aperto e lo resta fino alla fine.
        let der_firmatario = unsafe { der(certificato.0) }.to_vec();
        // SAFETY: il certificato è aperto; `pCertInfo` vive quanto lui.
        let info = unsafe { (*certificato.0).pCertInfo };

        // VALIDO ADESSO.
        // SAFETY: tempo nullo vuol dire adesso; `info` è viva.
        if unsafe { CertVerifyTimeValidity(std::ptr::null(), info) } != 0 {
            return Err(SigningRefusal::NotValidNow);
        }

        // FATTO PER FIRMARE, se lo dichiara.
        let mut usi = [0_u8; 2];
        // SAFETY: `info` è viva; `usi` ha i due byte dichiarati.
        let dichiarati = unsafe { CertGetIntendedKeyUsage(CODIFICA, info, usi.as_mut_ptr(), 2) };
        let per_firmare = u32::from(usi[0])
            & (CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_NON_REPUDIATION_KEY_USAGE)
            != 0;
        if dichiarati != 0 && !per_firmare {
            return Err(SigningRefusal::NotForSigning);
        }

        // LA CATENA E LA REVOCA, SENZA RETE.
        let revocation = controlla_catena(&certificato, &archivio, origine)?;

        // LA CHIAVE, CHE RESTA A WINDOWS.
        let mut maniglia: usize = 0;
        let mut specie: u32 = 0;
        let mut da_liberare: windows_sys::core::BOOL = 0;
        // SAFETY: il certificato è aperto; le tre uscite sono locali e vive.
        // Nessuna bandiera silenziosa: una smart card chiede il PIN. Con la
        // bandiera della cache Windows tiene la maniglia sul certificato, la
        // riusa se è già aperta e la libera con lui (invariante 1).
        let ok = unsafe {
            CryptAcquireCertificatePrivateKey(
                certificato.0,
                CRYPT_ACQUIRE_CACHE_FLAG
                    | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
                    | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
                std::ptr::null(),
                &raw mut maniglia,
                &raw mut specie,
                &raw mut da_liberare,
            )
        };
        if ok == 0 || maniglia == 0 {
            return Err(SigningRefusal::NoPrivateKey);
        }
        let chiave = Chiave {
            maniglia,
            specie,
            da_liberare: da_liberare != 0,
        };

        // GLI ATTRIBUTI FIRMATI (invariante 2: vivono fino alla fine).
        let impronta_firmatario = impronta(&der_firmatario)
            .ok_or_else(|| fallita("Windows non ha calcolato l'impronta"))?;
        let mut certificato_v2 = signing_certificate_v2(&impronta_firmatario);
        let mut istante = match signing_time {
            Some(quando) => Some(codifica_istante(quando)?),
            None => None,
        };
        let mut valore_certificato = CRYPT_INTEGER_BLOB {
            cbData: 40,
            pbData: certificato_v2.as_mut_ptr(),
        };
        let mut attributi = vec![CRYPT_ATTRIBUTE {
            pszObjId: OID_SIGNING_CERTIFICATE_V2.as_ptr().cast_mut(),
            cValue: 1,
            rgValue: &raw mut valore_certificato,
        }];
        let mut valore_istante =
            istante
                .as_mut()
                .map_or_else(CRYPT_INTEGER_BLOB::default, |codificato| {
                    CRYPT_INTEGER_BLOB {
                        cbData: u32::try_from(codificato.len()).unwrap_or(0),
                        pbData: codificato.as_mut_ptr(),
                    }
                });
        if istante.is_some() {
            attributi.push(CRYPT_ATTRIBUTE {
                pszObjId: szOID_RSA_signingTime.cast_mut(),
                cValue: 1,
                rgValue: &raw mut valore_istante,
            });
        }

        let mut firmatario = CMSG_SIGNER_ENCODE_INFO {
            cbSize: u32::try_from(size_of::<CMSG_SIGNER_ENCODE_INFO>()).unwrap_or(0),
            pCertInfo: info,
            Anonymous: CMSG_SIGNER_ENCODE_INFO_0 {
                hNCryptKey: chiave.maniglia,
            },
            dwKeySpec: chiave.specie,
            HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: szOID_NIST_sha256.cast_mut(),
                Parameters: CRYPT_INTEGER_BLOB::default(),
            },
            pvHashAuxInfo: std::ptr::null_mut(),
            cAuthAttr: u32::try_from(attributi.len()).unwrap_or(0),
            rgAuthAttr: attributi.as_mut_ptr(),
            cUnauthAttr: 0,
            rgUnauthAttr: std::ptr::null_mut(),
        };
        let mut certificato_dentro = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(der_firmatario.len()).unwrap_or(0),
            pbData: der_firmatario.as_ptr().cast_mut(),
        };
        let informazioni = CMSG_SIGNED_ENCODE_INFO {
            cbSize: u32::try_from(size_of::<CMSG_SIGNED_ENCODE_INFO>()).unwrap_or(0),
            cSigners: 1,
            rgSigners: &raw mut firmatario,
            cCertEncoded: 1,
            rgCertEncoded: &raw mut certificato_dentro,
            cCrlEncoded: 0,
            rgCrlEncoded: std::ptr::null_mut(),
        };

        // IL MESSAGGIO, CON IL CONTENUTO SEPARATO.
        // SAFETY: `informazioni` e tutto ciò a cui punta sono locali vivi fino
        // a dopo `CryptMsgUpdate` (invarianti 2 e 3); la chiave è aperta.
        let maniglia_messaggio = unsafe {
            CryptMsgOpenToEncode(
                CODIFICA,
                CMSG_DETACHED_FLAG,
                CMSG_SIGNED,
                (&raw const informazioni).cast::<c_void>(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if maniglia_messaggio.is_null() {
            return Err(fallita("Windows non ha preparato la firma"));
        }
        let messaggio = Messaggio(maniglia_messaggio);
        // SAFETY: `content` è viva per la chiamata e ne dichiariamo la
        // lunghezza esatta; è l'ultimo pezzo.
        let ok = unsafe { CryptMsgUpdate(messaggio.0, content.as_ptr(), lunghezza_contenuto, 1) };
        if ok == 0 {
            return Err(fallita("Windows non ha firmato"));
        }

        let mut dimensione: u32 = 0;
        // SAFETY: con il buffer nullo Windows scrive soltanto la dimensione.
        let ok = unsafe {
            CryptMsgGetParam(
                messaggio.0,
                CMSG_CONTENT_PARAM,
                0,
                std::ptr::null_mut(),
                &raw mut dimensione,
            )
        };
        if ok == 0 || dimensione == 0 {
            return Err(fallita("Windows non ha restituito la firma"));
        }
        let mut signature = vec![0_u8; usize::try_from(dimensione).unwrap_or(0)];
        // SAFETY: `signature` ha i byte dichiarati in `dimensione`.
        let ok = unsafe {
            CryptMsgGetParam(
                messaggio.0,
                CMSG_CONTENT_PARAM,
                0,
                signature.as_mut_ptr().cast::<c_void>(),
                &raw mut dimensione,
            )
        };
        if ok == 0 {
            return Err(fallita("Windows non ha restituito la firma"));
        }
        signature.truncate(usize::try_from(dimensione).unwrap_or(0));

        // L'ordine conta (invariante 1): il messaggio prima della chiave, la
        // chiave prima del certificato, il certificato prima dell'archivio.
        drop(messaggio);
        drop(chiave);
        drop(certificato);
        drop(archivio);

        Ok(DetachedSignature {
            signature,
            signer_certificate: der_firmatario,
            revocation,
        })
    }
}

#[cfg(not(windows))]
mod windows_impl {
    use std::time::SystemTime;

    use super::{DetachedSignature, SigningCertificate, SigningRefusal};

    /// Da dove vengono i certificati.
    pub enum Origine {
        /// L'archivio della postazione.
        DellaPostazione,
    }

    /// Fuori da Windows non ci sono certificati da elencare.
    pub fn elenca(_origine: &Origine) -> Vec<SigningCertificate> {
        Vec::new()
    }

    /// Fuori da Windows la firma non esiste, e lo si dice.
    pub fn firma(
        _content: &[u8],
        _certificate_sha256: &[u8; 32],
        _signing_time: Option<SystemTime>,
        _origine: &Origine,
    ) -> Result<DetachedSignature, SigningRefusal> {
        Err(SigningRefusal::Failed {
            reason: String::from("la firma esiste solo su Windows"),
        })
    }
}

#[cfg(windows)]
#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;
    use std::ffi::c_void;
    use std::time::{Duration, SystemTime};

    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_RSA_ALGORITHM, CERT_CHAIN_ENGINE_CONFIG, CERT_CONTEXT,
        CERT_CREATE_SELFSIGN_NO_KEY_INFO, CERT_DIGITAL_SIGNATURE_KEY_USAGE, CERT_EXTENSION,
        CERT_EXTENSIONS, CERT_KEY_CONTEXT, CERT_KEY_CONTEXT_0, CERT_KEY_CONTEXT_PROP_ID,
        CERT_KEY_ENCIPHERMENT_KEY_USAGE, CERT_NCRYPT_KEY_SPEC, CERT_STORE_ADD_ALWAYS,
        CERT_STORE_PROV_MEMORY, CERT_X500_NAME_STR, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_BIT_BLOB,
        CRYPT_INTEGER_BLOB, CertAddCertificateContextToStore, CertAddEncodedCertificateToStore,
        CertCloseStore, CertCreateCertificateChainEngine, CertCreateSelfSignCertificate,
        CertFreeCertificateChainEngine, CertFreeCertificateContext, CertOpenStore,
        CertSetCertificateContextProperty, CertStrToNameW, CryptEncodeObject, HCERTCHAINENGINE,
        HCERTSTORE, MS_KEY_STORAGE_PROVIDER, NCRYPT_LENGTH_PROPERTY, NCryptCreatePersistedKey,
        NCryptFinalizeKey, NCryptFreeObject, NCryptOpenStorageProvider, NCryptSetProperty,
        X509_ASN_ENCODING, X509_KEY_USAGE, szOID_KEY_USAGE, szOID_RSA_SHA256RSA,
    };

    use super::windows_impl::{Origine, elenca, firma, impronta};
    use super::{RevocationKnowledge, SigningRefusal, signing_certificate_v2};
    use crate::detached_signature::DetachedVerdict;
    use crate::detached_signature::windows_impl::{Radici, verify};

    const CONTENUTO: &[u8] = b"manifest di prova: tre file, tre impronte\n";

    /// Gli identificatori in DER, per riconoscere gli attributi nella firma.
    const DER_SIGNING_CERTIFICATE_V2: &[u8] = &[
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
    ];
    const DER_SIGNING_TIME: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
    ];

    /// Che uso dichiara il certificato di prova.
    #[derive(Clone, Copy)]
    pub(crate) enum Uso {
        Firma,
        SoloCifratura,
        NessunoDichiarato,
    }

    /// Un certificato autofirmato creato nella prova, con una chiave RSA
    /// **effimera**: CNG la tiene in memoria e non la scrive da nessuna
    /// parte, e nessun archivio di Windows viene toccato.
    pub(crate) struct CertificatoDiProva {
        contesto: *mut CERT_CONTEXT,
        chiave: usize,
        /// Se la chiave è passata alla custodia di un archivio.
        ceduta: Cell<bool>,
    }

    impl CertificatoDiProva {
        pub(crate) fn nuovo(nome: &str, uso: Uso, scaduto: bool) -> Self {
            let mut fornitore: usize = 0;
            // SAFETY: si apre il fornitore di chiavi software di Windows.
            let esito = unsafe {
                NCryptOpenStorageProvider(&raw mut fornitore, MS_KEY_STORAGE_PROVIDER, 0)
            };
            assert_eq!(esito, 0, "il fornitore di chiavi si deve aprire");
            let mut chiave: usize = 0;
            // SAFETY: senza nome la chiave è effimera e non si salva.
            let esito = unsafe {
                NCryptCreatePersistedKey(
                    fornitore,
                    &raw mut chiave,
                    BCRYPT_RSA_ALGORITHM,
                    std::ptr::null(),
                    0,
                    0,
                )
            };
            assert_eq!(esito, 0, "la chiave effimera si deve creare");
            let bit: u32 = 2048;
            // SAFETY: `bit` è locale e ne dichiariamo i quattro byte.
            let esito = unsafe {
                NCryptSetProperty(
                    chiave,
                    NCRYPT_LENGTH_PROPERTY,
                    (&raw const bit).cast(),
                    4,
                    0,
                )
            };
            assert_eq!(esito, 0);
            // SAFETY: la chiave è aperta e non ancora completata.
            assert_eq!(unsafe { NCryptFinalizeKey(chiave, 0) }, 0);
            // SAFETY: il fornitore non serve più; la chiave lo tiene vivo.
            let _ = unsafe { NCryptFreeObject(fornitore) };

            let x500: Vec<u16> = format!("CN={nome}, O=Prova sintetica NEXUM97\0")
                .encode_utf16()
                .collect();
            let mut nome_codificato = vec![0_u8; 512];
            let mut dimensione = u32::try_from(nome_codificato.len()).unwrap_or(0);
            // SAFETY: `x500` è terminata da zero; il buffer ha la capienza
            // dichiarata.
            let ok = unsafe {
                CertStrToNameW(
                    X509_ASN_ENCODING,
                    x500.as_ptr(),
                    CERT_X500_NAME_STR,
                    std::ptr::null(),
                    nome_codificato.as_mut_ptr(),
                    &raw mut dimensione,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "il nome si deve codificare");
            let soggetto = CRYPT_INTEGER_BLOB {
                cbData: dimensione,
                pbData: nome_codificato.as_mut_ptr(),
            };

            let mut bit_uso = [match uso {
                Uso::Firma | Uso::NessunoDichiarato => {
                    u8::try_from(CERT_DIGITAL_SIGNATURE_KEY_USAGE).unwrap_or(0)
                }
                Uso::SoloCifratura => u8::try_from(CERT_KEY_ENCIPHERMENT_KEY_USAGE).unwrap_or(0),
            }];
            let blob_uso = CRYPT_BIT_BLOB {
                cbData: 1,
                pbData: bit_uso.as_mut_ptr(),
                cUnusedBits: 0,
            };
            let mut uso_codificato = vec![0_u8; 16];
            let mut dimensione_uso = u32::try_from(uso_codificato.len()).unwrap_or(0);
            // SAFETY: `blob_uso` è locale; il buffer ha la capienza dichiarata.
            let ok = unsafe {
                CryptEncodeObject(
                    X509_ASN_ENCODING,
                    X509_KEY_USAGE,
                    (&raw const blob_uso).cast::<c_void>(),
                    uso_codificato.as_mut_ptr(),
                    &raw mut dimensione_uso,
                )
            };
            assert_ne!(ok, 0, "l'uso si deve codificare");
            let mut estensione = CERT_EXTENSION {
                pszObjId: szOID_KEY_USAGE.cast_mut(),
                fCritical: 1,
                Value: CRYPT_INTEGER_BLOB {
                    cbData: dimensione_uso,
                    pbData: uso_codificato.as_mut_ptr(),
                },
            };
            let estensioni = CERT_EXTENSIONS {
                cExtension: u32::from(!matches!(uso, Uso::NessunoDichiarato)),
                rgExtension: &raw mut estensione,
            };
            let algoritmo = CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: szOID_RSA_SHA256RSA.cast_mut(),
                Parameters: CRYPT_INTEGER_BLOB::default(),
            };
            let inizio = SYSTEMTIME {
                wYear: 2000,
                wMonth: 1,
                wDay: 1,
                ..Default::default()
            };
            let fine = SYSTEMTIME {
                wYear: 2001,
                wMonth: 1,
                wDay: 1,
                ..Default::default()
            };
            let (da, a) = if scaduto {
                (&raw const inizio, &raw const fine)
            } else {
                (std::ptr::null(), std::ptr::null())
            };
            // SAFETY: tutto ciò che si passa è locale e vivo per la chiamata;
            // senza informazioni sul contenitore, perché la chiave è effimera.
            let contesto = unsafe {
                CertCreateSelfSignCertificate(
                    chiave,
                    &raw const soggetto,
                    CERT_CREATE_SELFSIGN_NO_KEY_INFO,
                    std::ptr::null(),
                    &raw const algoritmo,
                    da,
                    a,
                    &raw const estensioni,
                )
            };
            assert!(
                !contesto.is_null(),
                "il certificato di prova si deve creare"
            );
            Self {
                contesto,
                chiave,
                ceduta: Cell::new(false),
            }
        }

        pub(crate) fn der(&self) -> Vec<u8> {
            // SAFETY: il contesto è aperto finché la struttura vive.
            unsafe {
                let contesto = &*self.contesto;
                std::slice::from_raw_parts(
                    contesto.pbCertEncoded,
                    usize::try_from(contesto.cbCertEncoded).unwrap_or(0),
                )
                .to_vec()
            }
        }

        pub(crate) fn impronta(&self) -> [u8; 32] {
            impronta(&self.der()).unwrap_or_else(|| panic!("l'impronta si deve calcolare"))
        }
    }

    impl Drop for CertificatoDiProva {
        fn drop(&mut self) {
            // SAFETY: il certificato prima della chiave che vi è legata; la
            // chiave soltanto se nessun archivio l'ha presa in custodia.
            unsafe {
                let _ = CertFreeCertificateContext(self.contesto);
                if !self.ceduta.get() {
                    let _ = NCryptFreeObject(self.chiave);
                }
            }
        }
    }

    /// Un archivio in memoria e un motore di catene che riconosce come
    /// radice SOLTANTO il certificato indicato.
    pub(crate) struct Prova {
        pub(crate) archivio: HCERTSTORE,
        radici: HCERTSTORE,
        motore: HCERTCHAINENGINE,
    }

    impl Prova {
        pub(crate) fn nuova(radice: &[u8]) -> Self {
            // SAFETY: due archivi in memoria, vuoti, posseduti da questa
            // struttura e chiusi in `Drop`.
            let (archivio, radici) = unsafe {
                (
                    CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, std::ptr::null()),
                    CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, std::ptr::null()),
                )
            };
            assert!(!archivio.is_null() && !radici.is_null());
            aggiungi_der(radici, radice);
            let configurazione = CERT_CHAIN_ENGINE_CONFIG {
                cbSize: u32::try_from(size_of::<CERT_CHAIN_ENGINE_CONFIG>()).unwrap_or(0),
                hExclusiveRoot: radici,
                ..Default::default()
            };
            let mut motore: HCERTCHAINENGINE = std::ptr::null_mut();
            // SAFETY: `configurazione` e `motore` sono locali e vivi.
            let ok = unsafe {
                CertCreateCertificateChainEngine(&raw const configurazione, &raw mut motore)
            };
            assert_ne!(ok, 0, "il motore di prova si deve creare");
            Self {
                archivio,
                radici,
                motore,
            }
        }

        /// Mette nell'archivio il certificato con la sua chiave effimera.
        pub(crate) fn con_chiave(&self, certificato: &CertificatoDiProva) {
            let mut nell_archivio: *mut CERT_CONTEXT = std::ptr::null_mut();
            // SAFETY: l'archivio e il certificato sono aperti.
            let ok = unsafe {
                CertAddCertificateContextToStore(
                    self.archivio,
                    certificato.contesto,
                    CERT_STORE_ADD_ALWAYS,
                    &raw mut nell_archivio,
                )
            };
            assert_ne!(ok, 0);
            // La chiave aperta, come la lascia Windows quando la tiene in
            // serbo: da qui la custodisce l'archivio, che è in memoria.
            let contesto_chiave = CERT_KEY_CONTEXT {
                cbSize: u32::try_from(size_of::<CERT_KEY_CONTEXT>()).unwrap_or(0),
                Anonymous: CERT_KEY_CONTEXT_0 {
                    hNCryptKey: certificato.chiave,
                },
                dwKeySpec: CERT_NCRYPT_KEY_SPEC,
            };
            // SAFETY: `contesto_chiave` è locale e vivo per la chiamata;
            // Windows ne copia il contenuto e da qui libera la chiave lui.
            let ok = unsafe {
                CertSetCertificateContextProperty(
                    nell_archivio,
                    CERT_KEY_CONTEXT_PROP_ID,
                    0,
                    (&raw const contesto_chiave).cast::<c_void>(),
                )
            };
            assert_ne!(ok, 0);
            certificato.ceduta.set(true);
            // SAFETY: la copia dell'archivio resta nell'archivio.
            let _ = unsafe { CertFreeCertificateContext(nell_archivio) };
        }

        fn origine(&self) -> Origine {
            Origine::DiProva {
                archivio: self.archivio,
                motore: self.motore,
            }
        }
    }

    impl Drop for Prova {
        fn drop(&mut self) {
            // SAFETY: le maniglie vengono da `nuova` e si liberano una volta
            // sola, il motore prima delle sue radici.
            unsafe {
                CertFreeCertificateChainEngine(self.motore);
                let _ = CertCloseStore(self.radici, 0);
                let _ = CertCloseStore(self.archivio, 0);
            }
        }
    }

    fn aggiungi_der(archivio: HCERTSTORE, der: &[u8]) {
        // SAFETY: `der` è viva e ne dichiariamo la lunghezza; Windows copia.
        let ok = unsafe {
            CertAddEncodedCertificateToStore(
                archivio,
                X509_ASN_ENCODING,
                der.as_ptr(),
                u32::try_from(der.len()).unwrap_or(0),
                CERT_STORE_ADD_ALWAYS,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
    }

    fn contiene(pagliaio: &[u8], ago: &[u8]) -> bool {
        pagliaio.windows(ago.len()).any(|pezzo| pezzo == ago)
    }

    #[test]
    fn una_firma_fatta_qui_si_verifica_con_la_verifica_di_dict_net() {
        let certificato = CertificatoDiProva::nuovo("Ufficio di prova", Uso::Firma, false);
        let prova = Prova::nuova(&certificato.der());
        prova.con_chiave(&certificato);

        let firmata = firma(
            CONTENUTO,
            &certificato.impronta(),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_000_000)),
            &prova.origine(),
        )
        .unwrap_or_else(|rifiuto| panic!("la firma si deve fare: {rifiuto:?}"));
        assert_eq!(firmata.signer_certificate, certificato.der());

        assert_eq!(
            verify(CONTENUTO, &firmata.signature, Radici::DiProva(prova.motore)),
            DetachedVerdict::Verified {
                signer_certificate: certificato.der()
            },
            "la firma deve verificarsi, separata e sul contenuto esatto"
        );
        let mut cambiato = CONTENUTO.to_vec();
        cambiato[0] = b'M';
        assert_eq!(
            verify(&cambiato, &firmata.signature, Radici::DiProva(prova.motore)),
            DetachedVerdict::ContentMismatch
        );
    }

    #[test]
    fn la_firma_porta_il_certificato_e_l_istante_soltanto_se_chiesto() {
        let certificato = CertificatoDiProva::nuovo("Ufficio di prova", Uso::Firma, false);
        let prova = Prova::nuova(&certificato.der());
        prova.con_chiave(&certificato);
        let attributo = signing_certificate_v2(&certificato.impronta());

        let con_istante = firma(
            CONTENUTO,
            &certificato.impronta(),
            Some(SystemTime::now()),
            &prova.origine(),
        )
        .unwrap_or_else(|rifiuto| panic!("{rifiuto:?}"));
        assert!(contiene(&con_istante.signature, DER_SIGNING_CERTIFICATE_V2));
        assert!(
            contiene(&con_istante.signature, &attributo),
            "l'attributo deve portare l'impronta del certificato"
        );
        assert!(contiene(&con_istante.signature, DER_SIGNING_TIME));

        let senza = firma(CONTENUTO, &certificato.impronta(), None, &prova.origine())
            .unwrap_or_else(|rifiuto| panic!("{rifiuto:?}"));
        assert!(contiene(&senza.signature, &attributo));
        assert!(
            !contiene(&senza.signature, DER_SIGNING_TIME),
            "la firma per un PDF non porta l'istante (PAdES)"
        );
        assert_eq!(
            verify(CONTENUTO, &senza.signature, Radici::DiProva(prova.motore)),
            DetachedVerdict::Verified {
                signer_certificate: certificato.der()
            }
        );
    }

    #[test]
    fn un_certificato_che_e_la_propria_radice_non_dice_non_revocato() {
        let certificato =
            CertificatoDiProva::nuovo("Ufficio di prova", Uso::NessunoDichiarato, false);
        let prova = Prova::nuova(&certificato.der());
        prova.con_chiave(&certificato);
        let firmata = firma(CONTENUTO, &certificato.impronta(), None, &prova.origine())
            .unwrap_or_else(|rifiuto| panic!("senza usi dichiarati si firma: {rifiuto:?}"));
        assert_eq!(firmata.revocation, RevocationKnowledge::Unknown);
    }

    #[test]
    fn un_certificato_scaduto_non_firma() {
        let certificato = CertificatoDiProva::nuovo("Ufficio scaduto", Uso::Firma, true);
        let prova = Prova::nuova(&certificato.der());
        prova.con_chiave(&certificato);
        assert_eq!(
            firma(CONTENUTO, &certificato.impronta(), None, &prova.origine()),
            Err(SigningRefusal::NotValidNow)
        );
    }

    #[test]
    fn un_certificato_per_cifrare_non_firma() {
        let certificato = CertificatoDiProva::nuovo("Solo cifratura", Uso::SoloCifratura, false);
        let prova = Prova::nuova(&certificato.der());
        prova.con_chiave(&certificato);
        assert_eq!(
            firma(CONTENUTO, &certificato.impronta(), None, &prova.origine()),
            Err(SigningRefusal::NotForSigning)
        );
    }

    #[test]
    fn un_autorita_sconosciuta_non_firma() {
        let certificato = CertificatoDiProva::nuovo("Ufficio di prova", Uso::Firma, false);
        let altra = CertificatoDiProva::nuovo("Altra autorità", Uso::Firma, false);
        let prova = Prova::nuova(&altra.der());
        prova.con_chiave(&certificato);
        assert!(matches!(
            firma(CONTENUTO, &certificato.impronta(), None, &prova.origine()),
            Err(SigningRefusal::ChainNotTrusted { code }) if code != 0
        ));
    }

    #[test]
    fn senza_il_certificato_o_senza_la_sua_chiave_non_si_firma() {
        let certificato = CertificatoDiProva::nuovo("Ufficio di prova", Uso::Firma, false);
        let prova = Prova::nuova(&certificato.der());
        assert_eq!(
            firma(CONTENUTO, &certificato.impronta(), None, &prova.origine()),
            Err(SigningRefusal::CertificateNotFound)
        );
        // Il certificato senza la chiave: soltanto la parte pubblica.
        aggiungi_der(prova.archivio, &certificato.der());
        assert_eq!(
            firma(CONTENUTO, &certificato.impronta(), None, &prova.origine()),
            Err(SigningRefusal::NoPrivateKey)
        );
    }

    #[test]
    fn si_elencano_soltanto_i_certificati_con_una_chiave() {
        let con_chiave = CertificatoDiProva::nuovo("Ufficio di prova", Uso::Firma, false);
        let senza = CertificatoDiProva::nuovo("Soltanto pubblico", Uso::Firma, false);
        let prova = Prova::nuova(&con_chiave.der());
        prova.con_chiave(&con_chiave);
        aggiungi_der(prova.archivio, &senza.der());

        let elenco = elenca(&prova.origine());
        assert_eq!(elenco.len(), 1, "{elenco:?}");
        let Some(trovato) = elenco.first() else {
            return;
        };
        assert_eq!(trovato.sha256, con_chiave.impronta());
        assert!(trovato.subject.contains("Ufficio di prova"), "{trovato:?}");
        assert!(trovato.not_after_unix > 0);
    }

    #[test]
    fn ogni_rifiuto_si_dice_con_parole() {
        for rifiuto in [
            SigningRefusal::CertificateNotFound,
            SigningRefusal::NoPrivateKey,
            SigningRefusal::NotValidNow,
            SigningRefusal::NotForSigning,
            SigningRefusal::Revoked,
            SigningRefusal::ChainNotTrusted { code: 1 },
            SigningRefusal::Failed {
                reason: String::from("prova"),
            },
        ] {
            let frase = rifiuto.operator_message();
            assert!(!frase.is_empty(), "{rifiuto:?}");
            assert!(
                !frase.contains("qualificat") && !frase.contains("digitale"),
                "le parole non promettono più della firma (ADR-0181, decisione 10)"
            );
        }
    }

    /// La firma non va in rete (invariante 5) e la smart card chiede il PIN:
    /// le bandiere devono restare nel codice.
    #[test]
    fn la_catena_e_la_revoca_si_controllano_senza_rete() {
        let codice = include_str!("document_signing.rs");
        // Le prove sono `pub(crate)`: anche `recipient_encryption` usa i
        // loro certificati effimeri (ADR-0190).
        let produzione = codice
            .split("\npub(crate) mod tests {")
            .next()
            .unwrap_or_default();
        let chiamata = produzione
            .split("CertGetCertificateChain(")
            .nth(1)
            .unwrap_or_default();
        let chiamata = &chiamata[..chiamata.len().min(900)];
        for bandiera in [
            "CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL",
            "CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE",
            "CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY",
        ] {
            assert!(chiamata.contains(bandiera), "manca {bandiera}");
        }
        assert!(
            !produzione.contains("CRYPT_ACQUIRE_SILENT_FLAG"),
            "una smart card deve poter chiedere il PIN"
        );
    }
}

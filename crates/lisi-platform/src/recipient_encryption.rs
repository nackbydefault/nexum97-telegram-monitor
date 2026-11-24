// DICIASSETTESIMO modulo del crate autorizzato a contenere `unsafe`, dopo
// quelli elencati in `lib.rs`. Vedere ADR-0009 per la regola e ADR-0190 per la
// decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Cifrare un file per il certificato di chi lo riceve, chiedendolo a Windows
//! (ENCRYPT-02, ADR-0190).
//!
//! # Che cosa produce
//!
//! Un messaggio CMS `EnvelopedData` (RFC 5652) in DER, il file `.p7m`: il
//! contenuto cifrato con AES-256 in modo CBC, la chiave del contenuto cifrata
//! con la chiave pubblica RSA del destinatario. È la forma che aprono gli
//! strumenti di sempre: `openssl cms -decrypt`, la classe `EnvelopedCms` di
//! .NET, i programmi di posta S/MIME. Nessuna crittografia scritta qui:
//! cifra Windows, con `CryptEncryptMessage`.
//!
//! # Perché soltanto RSA
//!
//! `CryptEncryptMessage` trasporta la chiave del contenuto con RSA. Un
//! certificato con una chiave di altro genere si rifiuta e lo si dice,
//! invece di produrre un file che nessuno apre.
//!
//! # Le invarianti dell'FFI
//!
//! 1. **Ogni maniglia ha un custode.** Il contesto del certificato è
//!    posseduto da una struttura che lo libera in `Drop`.
//! 2. **I byte passati a Windows vivono più a lungo della chiamata.** Il
//!    certificato e il contenuto sono `&[u8]` di chi chiama.
//! 3. **Le strutture di Windows puntano soltanto a memoria viva.** Gli
//!    identificatori di oggetto sono costanti terminate da zero; Windows li
//!    legge e non li scrive, anche dove il tipo dice `*mut`.
//! 4. **Nessun puntatore esce da questo modulo.** Escono copie: il messaggio,
//!    i nomi, l'impronta.
//! 5. **Nessuna rete e nessuna chiave privata.** Si usa la sola chiave
//!    pubblica del destinatario; la catena non si controlla, perché il
//!    certificato lo sceglie una persona che lo ha ricevuto da chi deve
//!    leggere, e il programma ne mostra il titolare e l'impronta.

/// Il certificato di chi riceve, letto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientCertificate {
    /// Il nome del titolare, come Windows lo mostra.
    pub subject: String,
    /// Il nome di chi l'ha emesso.
    pub issuer: String,
    /// Fino a quando vale, in secondi dal 1970 (UTC).
    pub not_after_unix: i64,
    /// L'impronta SHA-256 del certificato in DER.
    pub sha256: [u8; 32],
    /// Il certificato in DER: è ciò che si conserva e con cui si cifra.
    pub der: Vec<u8>,
}

/// Perché non si è cifrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientRefusal {
    /// Il file non è un certificato leggibile.
    NotACertificate,
    /// Il certificato è scaduto, o non vale ancora.
    NotValidNow,
    /// Il certificato dichiara usi che non comprendono la cifratura.
    NotForEncryption,
    /// La chiave del certificato non è RSA.
    NotRsa,
    /// La cifratura non si è potuta fare.
    Failed {
        /// Perché.
        reason: String,
    },
}

impl RecipientRefusal {
    /// La frase per una persona.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::NotACertificate => String::from(
                "Il file scelto non è un certificato leggibile: serve il file del certificato \
                 di chi riceve.",
            ),
            Self::NotValidNow => String::from("Il certificato è scaduto, o non vale ancora."),
            Self::NotForEncryption => {
                String::from("Il certificato non è fatto per ricevere documenti cifrati.")
            }
            Self::NotRsa => String::from(
                "Il certificato usa un genere di chiave che questo programma non sa usare per \
                 la cifratura: va chiesto a chi riceve un altro certificato.",
            ),
            Self::Failed { reason } => format!("La cifratura non si è potuta fare: {reason}."),
        }
    }
}

/// Legge il certificato di chi riceve, in DER o in PEM, e controlla che si
/// possa usare per cifrare adesso.
///
/// # Errors
///
/// [`RecipientRefusal`], con il motivo.
pub fn read_recipient_certificate(file: &[u8]) -> Result<RecipientCertificate, RecipientRefusal> {
    windows_impl::leggi(file)
}

/// Cifra `content` per il certificato indicato, in DER.
///
/// Il certificato si ricontrolla qui: una scelta fatta ieri non vale per un
/// certificato scaduto oggi. Non scrive file, non va in rete.
///
/// # Errors
///
/// [`RecipientRefusal`], con il motivo.
pub fn encrypt_for_recipient(
    content: &[u8],
    certificate_der: &[u8],
) -> Result<Vec<u8>, RecipientRefusal> {
    windows_impl::cifra(content, certificate_der)
}

#[cfg(windows)]
pub(crate) mod windows_impl {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_KEY_ENCIPHERMENT_KEY_USAGE, CRYPT_ALGORITHM_IDENTIFIER,
        CRYPT_ENCRYPT_MESSAGE_PARA, CRYPT_STRING_BASE64HEADER, CertCreateCertificateContext,
        CertFreeCertificateContext, CertGetIntendedKeyUsage, CertVerifyTimeValidity,
        CryptEncryptMessage, CryptStringToBinaryA, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        szOID_NIST_AES256_CBC, szOID_RSA_RSA,
    };

    use super::{RecipientCertificate, RecipientRefusal};
    use crate::document_signing::windows_impl::{impronta, nome, scadenza};

    /// La codifica di messaggi e certificati.
    const CODIFICA: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    /// Il più grande contenuto che si cifra in una volta: Windows misura in
    /// `u32`, e un pacchetto più grande è un pacchetto da dividere.
    const MASSIMO: usize = 2 * 1024 * 1024 * 1024 - 1;

    /// Un certificato aperto da byte, liberato in `Drop` (invariante 1).
    struct Certificato(*mut CERT_CONTEXT);

    impl Drop for Certificato {
        fn drop(&mut self) {
            // SAFETY: il contesto viene da `CertCreateCertificateContext` e
            // si libera una volta sola.
            let _ = unsafe { CertFreeCertificateContext(self.0) };
        }
    }

    /// Il DER di un certificato in PEM; `None` se il testo non lo è.
    fn da_pem(file: &[u8]) -> Option<Vec<u8>> {
        if !file.starts_with(b"-----BEGIN") {
            return None;
        }
        let lunghezza = u32::try_from(file.len()).ok()?;
        let mut dimensione: u32 = 0;
        // SAFETY: `file` è viva e ne dichiariamo la lunghezza; con il buffer
        // nullo Windows scrive soltanto la dimensione.
        let ok = unsafe {
            CryptStringToBinaryA(
                file.as_ptr(),
                lunghezza,
                CRYPT_STRING_BASE64HEADER,
                std::ptr::null_mut(),
                &raw mut dimensione,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || dimensione == 0 {
            return None;
        }
        let mut der = vec![0_u8; usize::try_from(dimensione).ok()?];
        // SAFETY: `der` ha la capienza dichiarata in `dimensione`.
        let ok = unsafe {
            CryptStringToBinaryA(
                file.as_ptr(),
                lunghezza,
                CRYPT_STRING_BASE64HEADER,
                der.as_mut_ptr(),
                &raw mut dimensione,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return None;
        }
        der.truncate(usize::try_from(dimensione).ok()?);
        Some(der)
    }

    /// Apre il certificato e ne controlla genere, uso e validità.
    fn apri(der: &[u8]) -> Result<Certificato, RecipientRefusal> {
        let lunghezza = u32::try_from(der.len()).map_err(|_| RecipientRefusal::NotACertificate)?;
        // SAFETY: `der` è viva per la chiamata e ne dichiariamo la lunghezza;
        // Windows copia i byte nel contesto che restituisce.
        let contesto = unsafe { CertCreateCertificateContext(CODIFICA, der.as_ptr(), lunghezza) };
        if contesto.is_null() {
            return Err(RecipientRefusal::NotACertificate);
        }
        let certificato = Certificato(contesto);

        // SAFETY: il contesto è aperto e `pCertInfo` punta alla sua parte
        // decodificata, viva quanto il contesto; l'identificatore è una
        // stringa terminata da zero di Windows.
        let (rsa, valido, uso) = unsafe {
            let info = (*contesto).pCertInfo;
            let algoritmo = std::ffi::CStr::from_ptr(
                (*info)
                    .SubjectPublicKeyInfo
                    .Algorithm
                    .pszObjId
                    .cast_const()
                    .cast(),
            );
            let rsa = algoritmo == std::ffi::CStr::from_ptr(szOID_RSA_RSA.cast());
            let valido = CertVerifyTimeValidity(std::ptr::null(), info) == 0;
            let mut bit_uso = [0_u8; 2];
            let dichiarato = CertGetIntendedKeyUsage(
                CODIFICA,
                info,
                bit_uso.as_mut_ptr(),
                u32::try_from(bit_uso.len()).unwrap_or(0),
            ) != 0;
            let cifra = !dichiarato
                || bit_uso[0] & u8::try_from(CERT_KEY_ENCIPHERMENT_KEY_USAGE).unwrap_or(0) != 0;
            (rsa, valido, cifra)
        };
        if !rsa {
            return Err(RecipientRefusal::NotRsa);
        }
        if !uso {
            return Err(RecipientRefusal::NotForEncryption);
        }
        if !valido {
            return Err(RecipientRefusal::NotValidNow);
        }
        Ok(certificato)
    }

    pub fn leggi(file: &[u8]) -> Result<RecipientCertificate, RecipientRefusal> {
        let der = da_pem(file).unwrap_or_else(|| file.to_vec());
        let certificato = apri(&der)?;
        let sha256 = impronta(&der).ok_or(RecipientRefusal::NotACertificate)?;
        Ok(RecipientCertificate {
            subject: nome(certificato.0, false),
            issuer: nome(certificato.0, true),
            not_after_unix: scadenza(certificato.0),
            sha256,
            der,
        })
    }

    pub fn cifra(content: &[u8], certificate_der: &[u8]) -> Result<Vec<u8>, RecipientRefusal> {
        if content.len() > MASSIMO {
            return Err(RecipientRefusal::Failed {
                reason: String::from("il contenuto è troppo grande per una cifratura sola"),
            });
        }
        let lunghezza = u32::try_from(content.len()).map_err(|_| RecipientRefusal::Failed {
            reason: String::from("il contenuto è troppo grande per una cifratura sola"),
        })?;
        let certificato = apri(certificate_der)?;
        let parametri = CRYPT_ENCRYPT_MESSAGE_PARA {
            cbSize: u32::try_from(size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>()).unwrap_or(0),
            dwMsgEncodingType: CODIFICA,
            ContentEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: szOID_NIST_AES256_CBC.cast_mut(),
                ..Default::default()
            },
            ..Default::default()
        };
        let destinatari = [certificato.0.cast_const()];

        let mut dimensione: u32 = 0;
        // SAFETY: parametri, destinatari e contenuto sono vivi per la
        // chiamata; con il buffer nullo Windows scrive soltanto la dimensione.
        let ok = unsafe {
            CryptEncryptMessage(
                &raw const parametri,
                1,
                destinatari.as_ptr(),
                content.as_ptr(),
                lunghezza,
                std::ptr::null_mut(),
                &raw mut dimensione,
            )
        };
        if ok == 0 {
            return Err(fallita());
        }
        let mut messaggio = vec![0_u8; usize::try_from(dimensione).unwrap_or(0)];
        // SAFETY: come sopra; `messaggio` ha la capienza dichiarata.
        let ok = unsafe {
            CryptEncryptMessage(
                &raw const parametri,
                1,
                destinatari.as_ptr(),
                content.as_ptr(),
                lunghezza,
                messaggio.as_mut_ptr(),
                &raw mut dimensione,
            )
        };
        if ok == 0 {
            return Err(fallita());
        }
        messaggio.truncate(usize::try_from(dimensione).unwrap_or(0));
        drop(certificato);
        Ok(messaggio)
    }

    fn fallita() -> RecipientRefusal {
        RecipientRefusal::Failed {
            reason: format!("Windows ha risposto {}", std::io::Error::last_os_error()),
        }
    }
}

#[cfg(not(windows))]
mod windows_impl {
    use super::{RecipientCertificate, RecipientRefusal};

    /// Fuori da Windows non si legge.
    pub fn leggi(_file: &[u8]) -> Result<RecipientCertificate, RecipientRefusal> {
        Err(RecipientRefusal::Failed {
            reason: String::from("la cifratura esiste solo su Windows"),
        })
    }

    /// Fuori da Windows la cifratura non esiste, e lo si dice.
    pub fn cifra(_content: &[u8], _certificate_der: &[u8]) -> Result<Vec<u8>, RecipientRefusal> {
        Err(RecipientRefusal::Failed {
            reason: String::from("la cifratura esiste solo su Windows"),
        })
    }
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_DECRYPT_MESSAGE_PARA, CryptDecryptMessage, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    use super::{RecipientRefusal, encrypt_for_recipient, read_recipient_certificate};
    use crate::document_signing::tests::{CertificatoDiProva, Prova, Uso};

    const CONTENUTO: &[u8] = b"pacchetto di prova: un manifest e due file\n";

    /// Apre il messaggio con la chiave del certificato di prova, come farebbe
    /// chi lo riceve.
    fn apri(messaggio: &[u8], prova: &Prova) -> Option<Vec<u8>> {
        let mut archivi = [prova.archivio];
        let parametri = CRYPT_DECRYPT_MESSAGE_PARA {
            cbSize: u32::try_from(size_of::<CRYPT_DECRYPT_MESSAGE_PARA>()).unwrap_or(0),
            dwMsgAndCertEncodingType: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            cCertStore: 1,
            rghCertStore: archivi.as_mut_ptr(),
        };
        let lunghezza = u32::try_from(messaggio.len()).ok()?;
        let mut dimensione: u32 = 0;
        // SAFETY: tutto ciò che si passa è locale e vivo per la chiamata.
        let ok = unsafe {
            CryptDecryptMessage(
                &raw const parametri,
                messaggio.as_ptr(),
                lunghezza,
                std::ptr::null_mut(),
                &raw mut dimensione,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return None;
        }
        let mut chiaro = vec![0_u8; usize::try_from(dimensione).ok()?];
        // SAFETY: `chiaro` ha la capienza dichiarata.
        let ok = unsafe {
            CryptDecryptMessage(
                &raw const parametri,
                messaggio.as_ptr(),
                lunghezza,
                chiaro.as_mut_ptr(),
                &raw mut dimensione,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return None;
        }
        chiaro.truncate(usize::try_from(dimensione).ok()?);
        Some(chiaro)
    }

    #[test]
    fn chi_ha_la_chiave_apre_e_ritrova_il_contenuto() {
        let certificato =
            CertificatoDiProva::nuovo("Destinatario di prova", Uso::SoloCifratura, false);
        let prova = Prova::nuova(&certificato.der());
        prova.con_chiave(&certificato);

        let Ok(messaggio) = encrypt_for_recipient(CONTENUTO, &certificato.der()) else {
            panic!("la cifratura deve riuscire");
        };
        assert!(
            !messaggio.windows(CONTENUTO.len()).any(|w| w == CONTENUTO),
            "il contenuto non deve comparire in chiaro"
        );
        // L'identificatore di AES-256-CBC, in DER, nel messaggio.
        let aes256 = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A,
        ];
        assert!(messaggio.windows(aes256.len()).any(|w| w == aes256));
        assert_eq!(apri(&messaggio, &prova).as_deref(), Some(CONTENUTO));
    }

    #[test]
    fn chi_non_ha_la_chiave_non_apre() {
        let destinatario =
            CertificatoDiProva::nuovo("Destinatario di prova", Uso::SoloCifratura, false);
        let altro = CertificatoDiProva::nuovo("Altro ufficio", Uso::SoloCifratura, false);
        let prova = Prova::nuova(&altro.der());
        prova.con_chiave(&altro);

        let Ok(messaggio) = encrypt_for_recipient(CONTENUTO, &destinatario.der()) else {
            panic!("la cifratura deve riuscire");
        };
        assert_eq!(apri(&messaggio, &prova), None);
    }

    #[test]
    fn il_certificato_si_legge_in_der_e_in_pem() {
        let certificato =
            CertificatoDiProva::nuovo("Destinatario di prova", Uso::SoloCifratura, false);
        let der = certificato.der();
        let Ok(letto) = read_recipient_certificate(&der) else {
            panic!("il certificato in DER si deve leggere");
        };
        assert!(letto.subject.contains("Destinatario di prova"));
        assert_eq!(letto.sha256, certificato.impronta());
        assert_eq!(letto.der, der);

        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64_di_prova(&der)
        );
        let Ok(da_pem) = read_recipient_certificate(pem.as_bytes()) else {
            panic!("il certificato in PEM si deve leggere");
        };
        assert_eq!(da_pem.der, der);
    }

    #[test]
    fn cio_che_non_serve_a_cifrare_si_rifiuta() {
        assert_eq!(
            read_recipient_certificate(b"non sono un certificato"),
            Err(RecipientRefusal::NotACertificate)
        );
        let firma = CertificatoDiProva::nuovo("Solo firma", Uso::Firma, false);
        assert_eq!(
            encrypt_for_recipient(CONTENUTO, &firma.der()),
            Err(RecipientRefusal::NotForEncryption)
        );
        let scaduto = CertificatoDiProva::nuovo("Scaduto", Uso::SoloCifratura, true);
        assert_eq!(
            read_recipient_certificate(&scaduto.der()).map(|c| c.sha256),
            Err(RecipientRefusal::NotValidNow)
        );
        // Un certificato senza usi dichiarati vale per tutti.
        let libero = CertificatoDiProva::nuovo("Senza usi", Uso::NessunoDichiarato, false);
        assert!(encrypt_for_recipient(CONTENUTO, &libero.der()).is_ok());
        for refusal in [
            RecipientRefusal::NotACertificate,
            RecipientRefusal::NotValidNow,
            RecipientRefusal::NotForEncryption,
            RecipientRefusal::NotRsa,
        ] {
            assert!(!refusal.operator_message().is_empty());
        }
    }

    /// Base64 per la sola prova del PEM: il modulo non ne scrive.
    fn base64_di_prova(byte: &[u8]) -> String {
        const ALFABETO: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut testo = String::new();
        for gruppo in byte.chunks(3) {
            let b = [
                gruppo[0],
                gruppo.get(1).copied().unwrap_or(0),
                gruppo.get(2).copied().unwrap_or(0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= gruppo.len() {
                    let indice = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
                    testo.push(char::from(ALFABETO[indice]));
                } else {
                    testo.push('=');
                }
            }
        }
        testo
    }
}

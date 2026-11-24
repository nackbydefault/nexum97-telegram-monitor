// QUINDICESIMO modulo del crate autorizzato a contenere `unsafe`, dopo
// quelli elencati in `lib.rs`. Vedere ADR-0009 per la regola e ADR-0178 per la
// decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Se un file accompagnato da una firma separata è firmato, e da chi.
//!
//! # Perché esiste accanto a `signature`
//!
//! Authenticode firma eseguibili, installatori e cataloghi, non un file di
//! testo. Un dizionario è testo: la sua firma sta in un file a parte, una
//! firma PKCS#7 (CMS, RFC 5652) con il dizionario come contenuto separato.
//! È ciò che produce `signtool sign /p7`, ed è uno standard (ADR-0178).
//!
//! # Perché si chiede a Windows
//!
//! Per la stessa ragione di `signature` (ADR-0037): la firma la verificano le
//! funzioni di crittografia del sistema, e la catena la decide l'archivio dei
//! certificati che l'amministratore già governa. Nessuna crittografia scritta
//! qui, nessuna chiave nel programma.
//!
//! # Che cosa questo modulo NON decide
//!
//! **Chi è ammesso a firmare.** Restituisce il certificato del firmatario; il
//! confronto con l'elenco scritto dall'amministratore lo fa chi conosce la
//! configurazione. Questo modulo non sa che cosa sia un dizionario.
//!
//! # Le invarianti dell'FFI
//!
//! 1. **Ogni maniglia ha un custode.** Il messaggio, l'archivio dei suoi
//!    certificati, il certificato del firmatario, la catena e il motore di
//!    prova sono posseduti da una struttura che li libera in `Drop`. Un
//!    ritorno anticipato non ne perde nessuno, e l'ordine di dichiarazione
//!    fa sì che si liberino in ordine inverso: il certificato prima
//!    dell'archivio, l'archivio prima del messaggio.
//! 2. **I byte passati a Windows vivono più a lungo della chiamata.** Il
//!    contenuto e la firma sono `&[u8]` di chi chiama, letti durante
//!    `CryptMsgUpdate` e mai conservati da Windows dopo.
//! 3. **I parametri letti con `CryptMsgGetParam` stanno in un buffer
//!    allineato.** La prima chiamata dice la dimensione, la seconda riempie
//!    un `Vec<u64>` di almeno quella dimensione: l'allineamento a 8 byte basta
//!    alle strutture di Windows, che contengono puntatori. Le strutture lette
//!    puntano **dentro** quel buffer, che resta vivo finché si leggono.
//! 4. **L'archivio del messaggio vive meno del messaggio.** `CERT_STORE_PROV_MSG`
//!    legge i certificati dal messaggio aperto: il messaggio si chiude dopo.
//! 5. **Nessun puntatore esce da questo modulo.** Esce un esito e, quando c'è,
//!    una copia dei byte del certificato del firmatario.
//! 6. **Nessuna rete.** La catena si costruisce con
//!    `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL` e senza aggiornamento automatico
//!    delle radici, e nessun controllo di revoca: la verifica non apre una
//!    seconda uscita (ADR-0067, ADR-0178 decisione 3).

/// Che cosa Windows dice di un contenuto e della sua firma separata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetachedVerdict {
    /// La firma è valida sul contenuto, e il certificato del firmatario
    /// risale a una radice di questa postazione.
    ///
    /// Porta i byte del certificato del firmatario: chi chiama ne calcola
    /// l'impronta e la confronta con quelle ammesse.
    Verified {
        /// Il certificato del firmatario, in DER.
        signer_certificate: Vec<u8>,
    },
    /// Il file di firma non è una firma PKCS#7 leggibile.
    NotASignature,
    /// La firma ha un numero di firmatari diverso da uno.
    SignerCount {
        /// Quanti firmatari ha.
        found: u32,
    },
    /// L'impronta del contenuto usa un algoritmo non ammesso (non SHA-256,
    /// SHA-384 o SHA-512).
    WeakDigest,
    /// La firma non corrisponde al contenuto: il contenuto è stato cambiato
    /// dopo la firma, o la firma è di un altro contenuto.
    ContentMismatch,
    /// La firma corrisponde al contenuto, ma il certificato non risale a una
    /// radice di questa postazione, o non è valido adesso.
    ChainNotTrusted {
        /// Il codice di Windows, per chi indaga.
        code: u32,
        /// Il certificato del firmatario, in DER.
        signer_certificate: Vec<u8>,
    },
    /// La verifica non si è potuta fare.
    Undeterminable {
        /// Perché.
        reason: String,
    },
}

impl DetachedVerdict {
    /// Vero soltanto per una firma valida con una catena attendibile.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// La frase per una persona.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Verified { .. } => String::from("La firma è valida."),
            Self::NotASignature => String::from("Il file di firma non è una firma leggibile."),
            Self::SignerCount { found } => {
                format!("La firma porta {found} firme: ne è ammessa una sola.")
            }
            Self::WeakDigest => String::from("La firma usa un'impronta debole, che non è ammessa."),
            Self::ContentMismatch => String::from(
                "La firma non corrisponde al file: il file è stato cambiato dopo la firma.",
            ),
            Self::ChainNotTrusted { code, .. } => format!(
                "La firma corrisponde al file, ma questa postazione non riconosce il \
                 certificato. Può essere scaduto o di un'autorità sconosciuta. Codice di \
                 Windows: {code:#010x}."
            ),
            Self::Undeterminable { reason } => {
                format!("La firma non si è potuta verificare: {reason}.")
            }
        }
    }
}

/// Le impronte ammesse per il contenuto, come identificatori di oggetto.
const IMPRONTE_AMMESSE: [&str; 3] = [
    "2.16.840.1.101.3.4.2.1", // SHA-256
    "2.16.840.1.101.3.4.2.2", // SHA-384
    "2.16.840.1.101.3.4.2.3", // SHA-512
];

/// Verifica un contenuto con la sua firma separata.
///
/// Non scrive, non apre finestre, non va in rete: interroga Windows e basta.
#[must_use]
pub fn verify_detached(content: &[u8], signature: &[u8]) -> DetachedVerdict {
    windows_impl::verify(content, signature, windows_impl::Radici::DellaPostazione)
}

// Visibile nel crate perché le prove di `document_signing` verificano con le
// stesse radici di prova le firme che fanno.
#[cfg(windows)]
pub(crate) mod windows_impl {
    use std::ffi::{CStr, c_void};

    use windows_sys::Win32::Security::Cryptography::{
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT,
        CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_BASE,
        CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT, CERT_INFO,
        CERT_STORE_PROV_MSG, CMSG_CTRL_VERIFY_SIGNATURE_EX, CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA,
        CMSG_DETACHED_FLAG, CMSG_SIGNED, CMSG_SIGNER_CERT_INFO_PARAM, CMSG_SIGNER_COUNT_PARAM,
        CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CMSG_TYPE_PARAM, CMSG_VERIFY_SIGNER_CERT,
        CertCloseStore, CertFreeCertificateChain, CertFreeCertificateContext,
        CertGetCertificateChain, CertGetSubjectCertificateFromStore, CertOpenStore,
        CertVerifyCertificateChainPolicy, CryptMsgClose, CryptMsgControl, CryptMsgGetParam,
        CryptMsgOpenToDecode, CryptMsgUpdate, HCERTCHAINENGINE, HCERTSTORE, PKCS_7_ASN_ENCODING,
        X509_ASN_ENCODING,
    };

    use super::{DetachedVerdict, IMPRONTE_AMMESSE};

    /// La codifica di messaggi e certificati.
    const CODIFICA: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    /// Contro quali radici si costruisce la catena.
    pub enum Radici {
        /// Quelle dell'archivio di Windows: l'unico caso fuori dalle prove.
        DellaPostazione,
        /// Soltanto quelle di un motore di prova (vedi `tests`).
        #[cfg(test)]
        DiProva(HCERTCHAINENGINE),
    }

    /// Il messaggio PKCS#7 aperto.
    struct Messaggio(*mut c_void);
    impl Drop for Messaggio {
        fn drop(&mut self) {
            // SAFETY: la maniglia viene da `CryptMsgOpenToDecode`, non è nulla
            // (lo controlla chi costruisce) e si chiude una volta sola.
            let _ = unsafe { CryptMsgClose(self.0) };
        }
    }

    /// L'archivio dei certificati portati dal messaggio.
    struct Archivio(HCERTSTORE);
    impl Drop for Archivio {
        fn drop(&mut self) {
            // SAFETY: la maniglia viene da `CertOpenStore`, non è nulla e si
            // chiude una volta sola. Zero come bandiere: i certificati ancora
            // aperti la tengono viva finché non sono liberati.
            let _ = unsafe { CertCloseStore(self.0, 0) };
        }
    }

    /// Il certificato del firmatario.
    struct Certificato(*mut CERT_CONTEXT);
    impl Drop for Certificato {
        fn drop(&mut self) {
            // SAFETY: il contesto viene da `CertGetSubjectCertificateFromStore`,
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

    /// Legge un parametro del messaggio in un buffer allineato (invariante 3).
    fn parametro(messaggio: &Messaggio, tipo: u32) -> Option<Vec<u64>> {
        let mut dimensione: u32 = 0;
        // SAFETY: con il puntatore ai dati nullo Windows scrive soltanto la
        // dimensione in `dimensione`, che vive per tutta la chiamata.
        let ok = unsafe {
            CryptMsgGetParam(
                messaggio.0,
                tipo,
                0,
                std::ptr::null_mut(),
                &raw mut dimensione,
            )
        };
        if ok == 0 || dimensione == 0 {
            return None;
        }
        let parole = usize::try_from(dimensione).ok()?.div_ceil(8);
        let mut buffer = vec![0_u64; parole];
        // SAFETY: `buffer` ha almeno `dimensione` byte, allineati a 8, e vive
        // per tutta la chiamata; `dimensione` dice a Windows quanti ne ha.
        let ok = unsafe {
            CryptMsgGetParam(
                messaggio.0,
                tipo,
                0,
                buffer.as_mut_ptr().cast::<c_void>(),
                &raw mut dimensione,
            )
        };
        (ok != 0).then_some(buffer)
    }

    /// Legge un parametro che è un `u32`.
    fn numero(messaggio: &Messaggio, tipo: u32) -> Option<u32> {
        let mut valore: u32 = 0;
        let mut dimensione = u32::try_from(size_of::<u32>()).ok()?;
        // SAFETY: `valore` è un `u32` locale vivo per tutta la chiamata, e
        // `dimensione` ne dichiara la grandezza.
        let ok = unsafe {
            CryptMsgGetParam(
                messaggio.0,
                tipo,
                0,
                (&raw mut valore).cast::<c_void>(),
                &raw mut dimensione,
            )
        };
        (ok != 0).then_some(valore)
    }

    /// Il corpo della verifica, nell'ordine di ADR-0178.
    pub fn verify(content: &[u8], signature: &[u8], radici: Radici) -> DetachedVerdict {
        let (Ok(lunghezza_firma), Ok(lunghezza_contenuto)) =
            (u32::try_from(signature.len()), u32::try_from(content.len()))
        else {
            return DetachedVerdict::Undeterminable {
                reason: String::from("il file è troppo grande"),
            };
        };
        if signature.is_empty() {
            return DetachedVerdict::NotASignature;
        }

        // SAFETY: nessun puntatore in ingresso: si chiede soltanto un messaggio
        // nuovo da decodificare, con il contenuto separato.
        let maniglia = unsafe {
            CryptMsgOpenToDecode(
                CODIFICA,
                CMSG_DETACHED_FLAG,
                0,
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if maniglia.is_null() {
            return DetachedVerdict::Undeterminable {
                reason: String::from("Windows non ha aperto il messaggio"),
            };
        }
        let messaggio = Messaggio(maniglia);

        // Prima la firma, tutta.
        // SAFETY: `signature` è viva per tutta la chiamata e ne dichiariamo la
        // lunghezza esatta (invariante 2).
        let ok = unsafe { CryptMsgUpdate(messaggio.0, signature.as_ptr(), lunghezza_firma, 1) };
        if ok == 0 || numero(&messaggio, CMSG_TYPE_PARAM) != Some(CMSG_SIGNED) {
            return DetachedVerdict::NotASignature;
        }

        // Poi il contenuto separato, tutto.
        // SAFETY: come sopra, per `content`.
        let ok = unsafe { CryptMsgUpdate(messaggio.0, content.as_ptr(), lunghezza_contenuto, 1) };
        if ok == 0 {
            return DetachedVerdict::Undeterminable {
                reason: String::from("Windows non ha letto il contenuto"),
            };
        }

        // UN FIRMATARIO SOLO.
        match numero(&messaggio, CMSG_SIGNER_COUNT_PARAM) {
            Some(1) => {}
            Some(found) => return DetachedVerdict::SignerCount { found },
            None => return DetachedVerdict::NotASignature,
        }

        // L'IMPRONTA DEL CONTENUTO: soltanto SHA-2.
        let Some(info) = parametro(&messaggio, CMSG_SIGNER_INFO_PARAM) else {
            return DetachedVerdict::NotASignature;
        };
        // SAFETY: il buffer è stato riempito da Windows con un
        // `CMSG_SIGNER_INFO`, è allineato a 8 e resta vivo finché `info` vive.
        // `pszObjId` punta dentro il buffer a una stringa terminata da zero.
        let ammessa = unsafe {
            let firmatario = &*info.as_ptr().cast::<CMSG_SIGNER_INFO>();
            let oid = firmatario.HashAlgorithm.pszObjId;
            !oid.is_null()
                && CStr::from_ptr(oid.cast_const().cast())
                    .to_str()
                    .is_ok_and(|testo| IMPRONTE_AMMESSE.contains(&testo))
        };
        if !ammessa {
            return DetachedVerdict::WeakDigest;
        }

        // IL CERTIFICATO DEL FIRMATARIO, DAI CERTIFICATI DEL MESSAGGIO.
        // SAFETY: `messaggio.0` è una maniglia valida che vive più a lungo
        // dell'archivio (invariante 4).
        let archivio = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MSG,
                CODIFICA,
                0,
                0,
                messaggio.0.cast_const(),
            )
        };
        if archivio.is_null() {
            return DetachedVerdict::NotASignature;
        }
        let archivio = Archivio(archivio);
        let Some(identita) = parametro(&messaggio, CMSG_SIGNER_CERT_INFO_PARAM) else {
            return DetachedVerdict::NotASignature;
        };
        // SAFETY: il buffer contiene un `CERT_INFO` scritto da Windows, vivo
        // per tutta la chiamata; l'archivio è aperto.
        let contesto = unsafe {
            CertGetSubjectCertificateFromStore(
                archivio.0,
                CODIFICA,
                identita.as_ptr().cast::<CERT_INFO>(),
            )
        };
        if contesto.is_null() {
            // La firma non porta il certificato di chi l'ha fatta.
            return DetachedVerdict::NotASignature;
        }
        let certificato = Certificato(contesto);

        // LA FIRMA SUL CONTENUTO.
        let parametri = CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA {
            cbSize: u32::try_from(size_of::<CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA>()).unwrap_or(0),
            hCryptProv: 0,
            dwSignerIndex: 0,
            dwSignerType: CMSG_VERIFY_SIGNER_CERT,
            pvSigner: certificato.0.cast::<c_void>(),
        };
        // SAFETY: `parametri` è locale e vivo per la chiamata, e punta a un
        // certificato ancora aperto.
        let ok = unsafe {
            CryptMsgControl(
                messaggio.0,
                0,
                CMSG_CTRL_VERIFY_SIGNATURE_EX,
                (&raw const parametri).cast::<c_void>(),
            )
        };
        if ok == 0 {
            return DetachedVerdict::ContentMismatch;
        }

        // SAFETY: il contesto è aperto; `pbCertEncoded` punta a
        // `cbCertEncoded` byte che restano validi finché il contesto vive, e
        // qui se ne fa una copia (invariante 5).
        let der = unsafe {
            let contesto = &*certificato.0;
            let lunghezza = usize::try_from(contesto.cbCertEncoded).unwrap_or(0);
            if contesto.pbCertEncoded.is_null() || lunghezza == 0 {
                return DetachedVerdict::NotASignature;
            }
            std::slice::from_raw_parts(contesto.pbCertEncoded, lunghezza).to_vec()
        };

        // LA CATENA, SENZA RETE (invariante 6).
        let motore: HCERTCHAINENGINE = match radici {
            Radici::DellaPostazione => std::ptr::null_mut(),
            #[cfg(test)]
            Radici::DiProva(motore) => motore,
        };
        let parametri_catena = CERT_CHAIN_PARA {
            cbSize: u32::try_from(size_of::<CERT_CHAIN_PARA>()).unwrap_or(0),
            ..Default::default()
        };
        let mut catena: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        // SAFETY: il certificato e l'archivio sono aperti; `parametri_catena`
        // e `catena` sono locali e vivi per la chiamata. Un tempo nullo vuol
        // dire adesso.
        let ok = unsafe {
            CertGetCertificateChain(
                motore,
                certificato.0,
                std::ptr::null(),
                archivio.0,
                &raw const parametri_catena,
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE,
                std::ptr::null(),
                &raw mut catena,
            )
        };
        if ok == 0 || catena.is_null() {
            return DetachedVerdict::Undeterminable {
                reason: String::from("Windows non ha costruito la catena del certificato"),
            };
        }
        let catena = Catena(catena);

        let politica = CERT_CHAIN_POLICY_PARA {
            cbSize: u32::try_from(size_of::<CERT_CHAIN_POLICY_PARA>()).unwrap_or(0),
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
        drop(catena);
        drop(certificato);
        drop(archivio);
        drop(messaggio);

        if ok == 0 {
            return DetachedVerdict::Undeterminable {
                reason: String::from("Windows non ha valutato la catena del certificato"),
            };
        }
        if stato.dwError != 0 {
            return DetachedVerdict::ChainNotTrusted {
                code: stato.dwError,
                signer_certificate: der,
            };
        }
        DetachedVerdict::Verified {
            signer_certificate: der,
        }
    }
}

#[cfg(not(windows))]
mod windows_impl {
    use super::DetachedVerdict;

    /// Contro quali radici si costruisce la catena.
    pub enum Radici {
        /// Quelle della postazione.
        DellaPostazione,
    }

    /// Fuori da Windows la verifica non esiste, e lo si dice.
    pub fn verify(_content: &[u8], _signature: &[u8], _radici: Radici) -> DetachedVerdict {
        DetachedVerdict::Undeterminable {
            reason: String::from("la verifica della firma esiste solo su Windows"),
        }
    }
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use windows_sys::Win32::Security::Cryptography::{
        CERT_CHAIN_ENGINE_CONFIG, CERT_STORE_ADD_ALWAYS, CERT_STORE_PROV_MEMORY,
        CertAddEncodedCertificateToStore, CertCloseStore, CertCreateCertificateChainEngine,
        CertFreeCertificateChainEngine, CertOpenStore, HCERTCHAINENGINE, X509_ASN_ENCODING,
    };

    use super::windows_impl::{Radici, verify};
    use super::{DetachedVerdict, verify_detached};

    const CONTENUTO: &[u8] = include_bytes!("../tests/fixtures/firma_separata/dizionario.json");
    const FIRMA: &[u8] = include_bytes!("../tests/fixtures/firma_separata/dizionario.json.p7s");
    const FIRMA_SHA1: &[u8] = include_bytes!("../tests/fixtures/firma_separata/sha1.p7s");
    const DUE_FIRMATARI: &[u8] =
        include_bytes!("../tests/fixtures/firma_separata/due_firmatari.p7s");
    const FIRMATARIO_A: &[u8] = include_bytes!("../tests/fixtures/firma_separata/firmatario_a.cer");
    const FIRMATARIO_B: &[u8] = include_bytes!("../tests/fixtures/firma_separata/firmatario_b.cer");

    /// Un motore di catene che riconosce come radice SOLTANTO il certificato
    /// indicato: così la prova esercita il caso verificato senza toccare
    /// l'archivio dei certificati della postazione.
    struct MotoreDiProva {
        motore: HCERTCHAINENGINE,
        radici: *mut c_void,
    }

    impl MotoreDiProva {
        fn con_radice(certificato: &[u8]) -> Self {
            // SAFETY: si apre un archivio in memoria, vuoto, che questa
            // struttura possiede e chiude in `Drop`.
            let radici =
                unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, std::ptr::null()) };
            assert!(!radici.is_null(), "l'archivio in memoria si deve aprire");
            let lunghezza = u32::try_from(certificato.len()).unwrap_or(0);
            // SAFETY: `certificato` è vivo per la chiamata e ne dichiariamo la
            // lunghezza; Windows copia i byte nell'archivio.
            let ok = unsafe {
                CertAddEncodedCertificateToStore(
                    radici,
                    X509_ASN_ENCODING,
                    certificato.as_ptr(),
                    lunghezza,
                    CERT_STORE_ADD_ALWAYS,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "il certificato di prova si deve aggiungere");
            let configurazione = CERT_CHAIN_ENGINE_CONFIG {
                cbSize: u32::try_from(size_of::<CERT_CHAIN_ENGINE_CONFIG>()).unwrap_or(0),
                hExclusiveRoot: radici,
                ..Default::default()
            };
            let mut motore: HCERTCHAINENGINE = std::ptr::null_mut();
            // SAFETY: `configurazione` e `motore` sono locali e vivi per la
            // chiamata; l'archivio delle radici resta aperto finché il motore
            // vive.
            let ok = unsafe {
                CertCreateCertificateChainEngine(&raw const configurazione, &raw mut motore)
            };
            assert_ne!(ok, 0, "il motore di prova si deve creare");
            Self { motore, radici }
        }
    }

    impl Drop for MotoreDiProva {
        fn drop(&mut self) {
            // SAFETY: le due maniglie vengono da `con_radice` e si liberano una
            // volta sola, il motore prima del suo archivio.
            unsafe {
                CertFreeCertificateChainEngine(self.motore);
                let _ = CertCloseStore(self.radici, 0);
            }
        }
    }

    #[test]
    fn una_firma_valida_di_un_firmatario_riconosciuto_si_verifica() {
        let motore = MotoreDiProva::con_radice(FIRMATARIO_A);
        assert_eq!(
            verify(CONTENUTO, FIRMA, Radici::DiProva(motore.motore)),
            DetachedVerdict::Verified {
                signer_certificate: FIRMATARIO_A.to_vec()
            },
            "con la radice di prova la firma deve verificarsi, e dire chi ha firmato"
        );
    }

    #[test]
    fn un_certificato_che_la_postazione_non_conosce_non_basta() {
        // Lo stesso file, la stessa firma, con le radici della postazione: il
        // certificato è autofirmato e nessuno lo ha messo fra le radici.
        match verify_detached(CONTENUTO, FIRMA) {
            DetachedVerdict::ChainNotTrusted {
                code,
                signer_certificate,
            } => {
                assert_ne!(code, 0);
                assert_eq!(
                    signer_certificate, FIRMATARIO_A,
                    "chi ha firmato si dice comunque"
                );
            }
            altro => panic!("un certificato sconosciuto non deve verificarsi: {altro:?}"),
        }
    }

    #[test]
    fn un_contenuto_cambiato_dopo_la_firma_si_rifiuta() {
        let motore = MotoreDiProva::con_radice(FIRMATARIO_A);
        let mut cambiato = CONTENUTO.to_vec();
        let Some(posizione) = cambiato.iter().position(|byte| *byte == b'1') else {
            panic!("il dizionario di prova ha un livello 1");
        };
        cambiato[posizione] = b'3';
        assert_eq!(
            verify(&cambiato, FIRMA, Radici::DiProva(motore.motore)),
            DetachedVerdict::ContentMismatch
        );
    }

    #[test]
    fn un_impronta_sha1_si_rifiuta_anche_se_la_firma_e_valida() {
        let motore = MotoreDiProva::con_radice(FIRMATARIO_A);
        assert_eq!(
            verify(CONTENUTO, FIRMA_SHA1, Radici::DiProva(motore.motore)),
            DetachedVerdict::WeakDigest
        );
    }

    #[test]
    fn due_firmatari_sono_uno_di_troppo() {
        let motore = MotoreDiProva::con_radice(FIRMATARIO_B);
        assert_eq!(
            verify(CONTENUTO, DUE_FIRMATARI, Radici::DiProva(motore.motore)),
            DetachedVerdict::SignerCount { found: 2 }
        );
    }

    #[test]
    fn cio_che_non_e_una_firma_non_e_una_firma() {
        for falso in [&b""[..], b"non sono una firma", CONTENUTO] {
            assert_eq!(
                verify_detached(CONTENUTO, falso),
                DetachedVerdict::NotASignature,
                "«{}» non è una firma",
                String::from_utf8_lossy(&falso[..falso.len().min(20)])
            );
        }
    }

    #[test]
    fn una_firma_troncata_non_e_una_firma() {
        let troncata = &FIRMA[..FIRMA.len() / 2];
        assert_eq!(
            verify_detached(CONTENUTO, troncata),
            DetachedVerdict::NotASignature
        );
    }

    #[test]
    fn soltanto_la_firma_verificata_e_verificata() {
        assert!(
            DetachedVerdict::Verified {
                signer_certificate: vec![1]
            }
            .is_verified()
        );
        for altro in [
            DetachedVerdict::NotASignature,
            DetachedVerdict::SignerCount { found: 2 },
            DetachedVerdict::WeakDigest,
            DetachedVerdict::ContentMismatch,
            DetachedVerdict::ChainNotTrusted {
                code: 1,
                signer_certificate: vec![1],
            },
            DetachedVerdict::Undeterminable {
                reason: String::from("prova"),
            },
        ] {
            assert!(!altro.is_verified(), "{altro:?}");
            assert!(!altro.operator_message().is_empty());
        }
    }

    /// La verifica non va in rete (invariante 6): le bandiere che lo
    /// impediscono devono restare nel codice.
    #[test]
    fn la_catena_si_costruisce_senza_rete() {
        let codice = include_str!("detached_signature.rs");
        let produzione = codice.split("\nmod tests {").next().unwrap_or_default();
        assert!(
            produzione.contains(
                "CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE"
            ),
            "la catena deve costruirsi soltanto con ciò che la postazione ha già"
        );
        assert!(
            !produzione.contains("REVOCATION_CHECK_CHAIN"),
            "un controllo di revoca andrebbe in rete (ADR-0178, decisione 3)"
        );
    }
}

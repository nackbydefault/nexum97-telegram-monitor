// QUINTO modulo del crate autorizzato a contenere `unsafe`, dopo `browser`,
// `window_chrome`, `title_bar` e `autostart`. Vedere ADR-0009 per la regola e
// ADR-0037 per la decisione che ha portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! Se un file è firmato, e da chi.
//!
//! # Perché si chiede a Windows invece di verificare da soli
//!
//! Windows ha un meccanismo di firma del codice — Authenticode — che l'intero
//! sistema usa, che le politiche aziendali sanno governare, e che un
//! amministratore può ispezionare senza sapere nulla di questo prodotto.
//!
//! Uno schema di firma scritto qui sembrerebbe più semplice e sarebbe peggiore.
//! Un errore in un verificatore scritto da noi è un errore che nessuno ha mai
//! cercato; un errore in Authenticode è un errore che l'intera industria cerca
//! da vent'anni. La motivazione completa è in ADR-0037.
//!
//! # Che cosa questo modulo NON dice
//!
//! Authenticode dice **chi** ha firmato, non che il contenuto sia innocuo. Un
//! certificato rubato produce file che superano la verifica. La firma sposta la
//! domanda da «questo file è integro?» a «mi fido di chi lo ha firmato?»: è una
//! domanda migliore, non è la stessa cosa della sicurezza.
//!
//! # Le invarianti dell'FFI
//!
//! `WinVerifyTrust` riceve due strutture che questo modulo costruisce e possiede
//! per l'intera durata della chiamata:
//!
//! 1. `WINTRUST_FILE_INFO` porta un puntatore al percorso in UTF-16 terminato da
//!    zero. Il vettore che lo contiene resta vivo fino alla chiusura dello stato,
//!    perché la funzione lo legge anche nella seconda chiamata.
//! 2. `WINTRUST_DATA` porta un puntatore alla struttura precedente, e viene
//!    passata **due volte**: la prima con `WTD_STATEACTION_VERIFY`, che alloca
//!    uno stato interno, la seconda con `WTD_STATEACTION_CLOSE`, che lo libera.
//!    **Saltare la seconda chiamata perde memoria a ogni verifica.**
//! 3. `dwUIChoice` è `WTD_UI_NONE`: senza, Windows aprirebbe una finestra di
//!    dialogo modale, che in un programma con la propria interfaccia significa
//!    bloccarla in attesa di un clic che nessuno si aspetta.

use std::path::Path;

/// Che cosa Windows dice della firma di un file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureState {
    /// Firmato, e la catena dei certificati è valida e attendibile.
    Trusted,
    /// Non firmato affatto.
    Unsigned,
    /// Firmato, ma la firma non è attendibile: certificato scaduto, revocato,
    /// autofirmato, o emesso da un'autorità che questa postazione non riconosce.
    ///
    /// Porta con sé il codice di Windows, perché le ragioni sono molte e
    /// appiattirle in una sola parola toglierebbe a chi indaga l'unica cosa
    /// utile.
    Untrusted {
        /// Il codice restituito da `WinVerifyTrust`.
        code: i32,
    },
    /// Il file è firmato ma il contenuto non corrisponde alla firma: è stato
    /// modificato dopo essere stato firmato.
    Tampered,
    /// La verifica non è stata possibile.
    ///
    /// **Non è «non firmato».** Un file su una condivisione di rete irraggiungibile
    /// e un file senza firma sono due situazioni diverse, e dire la seconda al
    /// posto della prima manderebbe chi legge a cercare il problema sbagliato.
    Undeterminable {
        /// La ragione, in italiano piano.
        reason: String,
    },
}

impl SignatureState {
    /// Vero solo se il file è firmato **e** la firma è attendibile.
    ///
    /// Ogni altro caso — compresa l'impossibilità di verificare — è falso.
    /// Davanti a una firma che non si è potuta stabilire, la risposta prudente è
    /// «no».
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }

    /// L'esito, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Trusted => String::from(
                "Il file è firmato e la firma è valida. Questo dice CHI lo ha \
                 prodotto, non che il contenuto sia innocuo.",
            ),
            Self::Unsigned => String::from(
                "Il file non è firmato. Windows non può dire chi lo ha prodotto né \
                 se è stato modificato dopo la produzione.",
            ),
            Self::Untrusted { code } => format!(
                "Il file è firmato, ma questa postazione non riconosce la firma come \
                 attendibile: il certificato può essere scaduto, revocato, o emesso \
                 da un'autorità non riconosciuta. Codice di Windows: {code:#010x}."
            ),
            Self::Tampered => String::from(
                "Il file è firmato ma il contenuto NON corrisponde alla firma: è \
                 stato modificato dopo essere stato firmato. Non eseguirlo.",
            ),
            Self::Undeterminable { reason } => format!(
                "Non è stato possibile verificare la firma: {reason}. Questo non \
                 significa che il file non sia firmato."
            ),
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    };

    use super::SignatureState;

    /// Nessuna firma nel file.
    const TRUST_E_NOSIGNATURE: i32 = -2_146_762_496; // 0x800B0100
    /// Il contenuto non corrisponde alla firma.
    const TRUST_E_BAD_DIGEST: i32 = -2_146_869_232; // 0x80096010
    /// Il soggetto non è attendibile per l'azione richiesta.
    ///
    /// Non compare in `interpreta`: ricade nel caso generale, insieme a tutte
    /// le altre ragioni per cui una firma esiste ma non convince. Esiste perché
    /// la prova possa **nominare** cio' che verifica invece di scrivere un
    /// numero, ed e' per questo che vive solo nelle prove.
    #[cfg(test)]
    const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = -2_146_762_751; // 0x800B0004
    /// Il file non è riconosciuto come un tipo firmabile.
    const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = -2_146_762_477; // 0x800B0003
    /// Il provider non riconosce il soggetto.
    const TRUST_E_PROVIDER_UNKNOWN: i32 = -2_146_762_478; // 0x800B0001

    /// Chiede a Windows che cosa sa della firma di un file **già aperto**.
    ///
    /// # Perché l'handle e non solo il percorso
    ///
    /// Un percorso si può ri-risolvere, e fra due aperture può indicare un file
    /// diverso: è il TOCTOU che ADR-0070 chiude. Passando l'handle, Windows
    /// verifica **quel file aperto**, e se chi lo ha aperto ha negato la
    /// condivisione in scrittura, quei byte non possono cambiare mentre la
    /// verifica avviene.
    ///
    /// Il percorso serve comunque — Windows lo usa per capire il tipo di
    /// soggetto — ma **non è più ciò che identifica il file**.
    pub fn verify_open(path: &Path, file: &std::fs::File) -> SignatureState {
        use std::os::windows::io::AsRawHandle;
        verify_with(path, file.as_raw_handle())
    }

    /// Chiede a Windows che cosa sa della firma del file indicato.
    pub fn verify(path: &Path) -> SignatureState {
        verify_with(path, std::ptr::null_mut())
    }

    /// Il corpo comune, con o senza handle.
    ///
    /// # Perché una funzione sola
    ///
    /// Le due verifiche differiscono in **un campo**. Scriverle due volte
    /// significherebbe due copie di codice `unsafe` con le stesse invarianti, e
    /// la seconda sarebbe quella che un giorno non riceve una correzione.
    fn verify_with(path: &Path, handle: *mut std::ffi::c_void) -> SignatureState {
        // Con un handle gia' aperto questo controllo non serve — il file
        // esiste, e' aperto e non puo' sparire — e sarebbe anzi una seconda
        // risoluzione del percorso, cioe' proprio cio' che ADR-0070 evita.
        if handle.is_null() && !path.is_file() {
            return SignatureState::Undeterminable {
                reason: format!("«{}» non è un file leggibile", path.display()),
            };
        }

        // Il percorso in UTF-16 terminato da zero. Il vettore deve restare vivo
        // per l'intera durata delle DUE chiamate: `WinVerifyTrust` lo rilegge
        // anche alla chiusura dello stato.
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            // Un percorso con uno zero dentro verrebbe troncato in silenzio, e
            // si finirebbe per verificare un file diverso da quello chiesto.
            return SignatureState::Undeterminable {
                reason: String::from("il percorso contiene un carattere non ammesso"),
            };
        }
        wide.push(0);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or(0),
            pcwszFilePath: wide.as_ptr(),
            // ADR-0070: se chi chiama ha gia' aperto il file negando la
            // condivisione in scrittura, Windows verifica QUELL'apertura e non
            // un percorso che nel frattempo potrebbe indicare altro.
            hFile: handle,
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(0);
        // Senza WTD_UI_NONE Windows aprirebbe una finestra modale, bloccando
        // l'interfaccia in attesa di un clic che nessuno si aspetta.
        data.dwUIChoice = WTD_UI_NONE;
        // Nessun controllo di revoca: richiede la rete, e una postazione
        // d'ufficio senza uscita verso Internet vedrebbe ogni file come non
        // verificabile. La revoca e' una domanda separata, non un dettaglio di
        // questa.
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &raw mut file_info;
        data.dwStateAction = WTD_STATEACTION_VERIFY;

        // SAFETY: `action` e `data` sono possedute da questa funzione e vive per
        // l'intera chiamata. `data.Anonymous.pFile` punta a `file_info`, che vive
        // anch'essa fino alla fine della funzione, e `file_info.pcwszFilePath`
        // punta a `wide`, terminato da zero e privo di zeri interni (verificato
        // sopra). `cbStruct` dichiara la dimensione reale delle strutture.
        let esito = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &raw mut action,
                (&raw mut data).cast::<std::ffi::c_void>(),
            )
        };

        // Lo stato interno allocato dalla prima chiamata va liberato SEMPRE,
        // anche quando la verifica e' fallita: saltarlo perde memoria a ogni
        // verifica, e questa funzione viene chiamata a ogni avvio.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: le stesse invarianti della chiamata precedente. `data` porta
        // lo stato allocato allora, che questa chiamata libera.
        let _ = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &raw mut action,
                (&raw mut data).cast::<std::ffi::c_void>(),
            )
        };

        interpreta(esito)
    }

    /// Traduce il codice di `WinVerifyTrust` in uno stato del dominio.
    pub const fn interpreta(esito: i32) -> SignatureState {
        match esito {
            0 => SignatureState::Trusted,
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
                SignatureState::Unsigned
            }
            TRUST_E_BAD_DIGEST => SignatureState::Tampered,
            // Ogni altro codice e' una firma che c'e' ma non convince. Non si
            // appiattisce in «non firmato»: sono due situazioni diverse e
            // portano a due azioni diverse.
            code => SignatureState::Untrusted { code },
        }
        .const_self()
    }

    impl SignatureState {
        /// Identità, per poter usare `match` in un contesto `const`.
        const fn const_self(self) -> Self {
            self
        }
    }

    /// I codici noti, per le prove.
    #[cfg(test)]
    pub const CODICI: [(i32, &str); 5] = [
        (TRUST_E_NOSIGNATURE, "nessuna firma"),
        (TRUST_E_BAD_DIGEST, "contenuto alterato"),
        (TRUST_E_SUBJECT_NOT_TRUSTED, "soggetto non attendibile"),
        (TRUST_E_SUBJECT_FORM_UNKNOWN, "tipo non firmabile"),
        (
            TRUST_E_PROVIDER_UNKNOWN,
            "componente di verifica di Windows sconosciuto",
        ),
    ];
}

#[cfg(not(windows))]
mod windows_impl {
    use std::path::Path;

    use super::SignatureState;

    /// Fuori da Windows non esiste Authenticode.
    ///
    /// Restituisce «non verificabile» e non «non firmato»: dire la seconda
    /// sarebbe un'affermazione su un file, quando il fatto riguarda il sistema.
    pub fn verify(_path: &Path) -> SignatureState {
        SignatureState::Undeterminable {
            reason: String::from("la verifica della firma esiste solo su Windows"),
        }
    }

    /// Come sopra: fuori da Windows un handle non cambia la risposta.
    pub fn verify_open(_path: &Path, _file: &std::fs::File) -> SignatureState {
        verify(_path)
    }
}

/// Che cosa Windows dice della firma del file indicato.
///
/// Non lancia nulla, non apre finestre, non scrive: interroga e basta.
#[must_use]
pub fn verify_file(path: &Path) -> SignatureState {
    windows_impl::verify(path)
}

/// Che cosa Windows dice della firma di un file **già aperto**.
///
/// # Perché esiste accanto a [`verify_file`]
///
/// Un percorso si può ri-risolvere, e fra due aperture può indicare un file
/// diverso. Chi ha aperto il file negando la condivisione in scrittura sa che
/// quei byte non possono cambiare: passando l'handle, la verifica riguarda
/// **quella** apertura e non una seconda risoluzione del percorso (ADR-0070).
///
/// Il percorso serve comunque, perché Windows lo usa per capire il tipo di
/// soggetto, ma non è più ciò che identifica il file.
#[must_use]
pub fn verify_open_file(path: &Path, file: &std::fs::File) -> SignatureState {
    windows_impl::verify_open(path, file)
}

/// Che cosa Windows dice della firma **di questo stesso programma**.
///
/// # Perché è una domanda che il prodotto deve saper porre a sé stesso
///
/// Un amministratore che trova un programma di monitoraggio su una postazione
/// vuole sapere se è la copia originale. Oggi la risposta è «non è firmato»,
/// perché non esiste ancora un certificato (HVQ-07), e va detta così com'è: una
/// schermata che tacesse sarebbe più comoda e meno vera.
#[must_use]
pub fn verify_self() -> SignatureState {
    match std::env::current_exe() {
        Ok(path) => verify_file(&path),
        Err(errore) => SignatureState::Undeterminable {
            reason: format!("il percorso del programma non è leggibile: {errore}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{SignatureState, verify_file, verify_self};

    #[test]
    fn un_file_che_non_esiste_non_e_un_file_non_firmato() {
        // Sono due situazioni diverse, e dire la seconda al posto della prima
        // manderebbe chi legge a cercare il problema sbagliato.
        let stato = verify_file(std::path::Path::new("C:/questo/non/esiste.exe"));
        assert!(matches!(stato, SignatureState::Undeterminable { .. }));
        assert!(!stato.is_trusted());
    }

    #[test]
    fn davanti_a_una_firma_incerta_la_risposta_e_no() {
        // Ogni stato che non sia «firmato e attendibile» non e' attendibile,
        // compresa l'impossibilita' di verificare.
        for stato in [
            SignatureState::Unsigned,
            SignatureState::Tampered,
            SignatureState::Untrusted { code: -1 },
            SignatureState::Undeterminable {
                reason: String::from("prova"),
            },
        ] {
            assert!(
                !stato.is_trusted(),
                "{stato:?} non deve risultare attendibile"
            );
        }
        assert!(SignatureState::Trusted.is_trusted());
    }

    #[test]
    fn ogni_esito_dice_qualcosa_di_utile_a_chi_legge() {
        for stato in [
            SignatureState::Trusted,
            SignatureState::Unsigned,
            SignatureState::Tampered,
            SignatureState::Untrusted {
                code: -2_146_762_751,
            },
            SignatureState::Undeterminable {
                reason: String::from("la rete non risponde"),
            },
        ] {
            let messaggio = stato.operator_message();
            assert!(!messaggio.is_empty(), "{stato:?} non dice nulla");
            assert!(
                messaggio.len() > 40,
                "{stato:?} liquida la questione in una parola: «{messaggio}»"
            );
        }
    }

    #[test]
    fn il_messaggio_di_un_file_firmato_non_promette_che_sia_innocuo() {
        // Authenticode dice CHI ha firmato, non che il contenuto sia sicuro.
        // Lasciarlo credere sarebbe la bugia piu' comoda di tutto il modulo.
        let messaggio = SignatureState::Trusted.operator_message();
        assert!(
            messaggio.contains("non che il contenuto sia innocuo"),
            "il messaggio promette piu' di quanto Authenticode dica: «{messaggio}»"
        );
    }

    #[test]
    fn il_messaggio_di_un_file_alterato_dice_di_non_eseguirlo() {
        let messaggio = SignatureState::Tampered.operator_message();
        assert!(
            messaggio.contains("Non eseguirlo"),
            "davanti a un file alterato la cosa da dire e' una sola: «{messaggio}»"
        );
    }

    #[test]
    fn il_prodotto_sa_rispondere_su_se_stesso() {
        // Non si asserisce QUALE sia l'esito: finche' non esiste un certificato
        // (HVQ-07) il binario di prova non e' firmato, e una prova che
        // pretendesse «attendibile» diventerebbe rossa il giorno in cui il
        // prodotto viene firmato — cioe' esattamente al contrario.
        let stato = verify_self();
        assert!(
            !stato.operator_message().is_empty(),
            "il prodotto deve saper dire qualcosa della propria firma"
        );
    }

    /// **Un binario firmato da Microsoft deve risultare firmato.**
    ///
    /// È l'unico modo di esercitare il percorso positivo oggi: non esiste ancora
    /// un certificato per questo prodotto (HVQ-07), e senza un file davvero
    /// firmato la prova verificherebbe solo che il modulo sa dire «no».
    #[cfg(windows)]
    #[test]
    fn un_binario_di_sistema_risulta_firmato_e_attendibile() {
        let Ok(system) = std::env::var("SystemRoot") else {
            // Senza la variabile non si sa dove guardare. Si dichiara e si
            // passa: inventare un percorso renderebbe la prova rossa su
            // configurazioni legittime.
            return;
        };
        let percorso = std::path::Path::new(&system)
            .join("System32")
            .join("kernel32.dll");
        if !percorso.is_file() {
            return;
        }

        let stato = verify_file(&percorso);
        assert!(
            stato.is_trusted(),
            "kernel32.dll deve risultare firmata e attendibile, invece: {stato:?} — \
             «{}»",
            stato.operator_message()
        );
    }

    /// **Un file qualunque non deve risultare firmato.**
    #[cfg(windows)]
    #[test]
    fn un_file_qualunque_non_risulta_firmato() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("qualunque.exe");
        let Ok(()) = std::fs::write(&percorso, b"non sono un eseguibile firmato") else {
            panic!("il file di prova deve potersi scrivere");
        };

        let stato = verify_file(&percorso);
        assert!(
            !stato.is_trusted(),
            "un file qualunque non deve risultare firmato: {stato:?}"
        );
    }

    /// **Nessun codice noto deve finire nel cestino dei «non attendibili».**
    #[cfg(windows)]
    #[test]
    fn i_codici_noti_sono_distinti_e_non_appiattiti() {
        use super::windows_impl::{CODICI, interpreta};

        assert!(matches!(interpreta(0), SignatureState::Trusted));

        for (codice, nome) in CODICI {
            let stato = interpreta(codice);
            assert!(
                !stato.is_trusted(),
                "«{nome}» ({codice:#010x}) non deve risultare attendibile"
            );
        }

        // Nessuna firma e contenuto alterato sono due cose diverse e portano a
        // due azioni diverse: appiattirle toglierebbe a chi indaga l'unica cosa
        // utile.
        assert!(matches!(interpreta(CODICI[0].0), SignatureState::Unsigned));
        assert!(matches!(interpreta(CODICI[1].0), SignatureState::Tampered));
        assert!(matches!(
            interpreta(CODICI[2].0),
            SignatureState::Untrusted { .. }
        ));
    }
}

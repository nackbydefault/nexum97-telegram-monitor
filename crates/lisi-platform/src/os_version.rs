//! La versione di Windows in esecuzione.
//!
//! # Perché serve
//!
//! Il manifesto di aggiornamento dichiara un `minimum_windows`, e finché nessuno
//! sapeva leggere la versione della postazione quel campo **non veniva
//! controllato da niente**: un aggiornamento che richiede una build più recente
//! sarebbe stato offerto e installato su una macchina che non lo regge.
//!
//! # Perché WinRT e non il registro
//!
//! I valori di versione nel registro sono noti per **mentire alle applicazioni
//! vecchie**: Microsoft li congela deliberatamente perché programmi che
//! confrontano numeri di versione in modo ingenuo continuino a funzionare.
//! `AnalyticsInfo.VersionInfo.DeviceFamilyVersion` non è soggetto a quel
//! congelamento, ed è un oggetto WinRT: **non serve `unsafe`**, e questo modulo
//! resta fuori dall'elenco dei moduli FFI che ADR-0009 governa.
//!
//! # Perché non basta il numero, serve anche «non lo so»
//!
//! Una postazione che non sa dire la propria versione non è una postazione
//! aggiornata né una vecchia. Chi chiama deve poter distinguere i due casi, e la
//! decisione su che farne non sta qui.

/// La versione del sistema, nella forma `maggiore.minore.build`.
///
/// # Perché una stringa e non tre numeri
///
/// È la stessa forma che il manifesto usa per `minimum_windows`, e confrontarle
/// è compito di chi conosce le regole degli aggiornamenti — non di questo crate,
/// che è il livello più basso e non conosce il dominio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsVersion {
    /// La versione letta dal sistema.
    Known(String),
    /// La versione non è stata leggibile.
    ///
    /// **Non è «vecchia» e non è «recente».** Chi chiama decide, e deve dirlo
    /// invece di scegliere in silenzio.
    Undeterminable,
}

impl WindowsVersion {
    /// La versione, quando è nota.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Known(versione) => Some(versione.as_str()),
            Self::Undeterminable => None,
        }
    }

    /// La versione, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Known(versione) => format!("Windows {versione}."),
            Self::Undeterminable => String::from(
                "Non è stato possibile leggere la versione di Windows su questa \
                 postazione.",
            ),
        }
    }
}

/// Ricompone `maggiore.minore.build` dal valore compatto di `AnalyticsInfo`.
///
/// # La codifica, e perché si scarta l'ultimo pezzo
///
/// I quattro numeri stanno in un intero a 64 bit, sedici bit ciascuno, dal più
/// significativo: maggiore, minore, build, revisione.
///
/// La **revisione** non entra nella stringa: cambia a ogni aggiornamento
/// cumulativo mensile, e un `minimum_windows` scritto con quattro numeri
/// costringerebbe chi pubblica a inseguire il calendario delle patch di
/// Microsoft. Le tre cifre che contano sono quelle che identificano una
/// versione di Windows.
#[must_use]
pub fn decode_device_family_version(raw: u64) -> String {
    let maggiore = (raw >> 48) & 0xFFFF;
    let minore = (raw >> 32) & 0xFFFF;
    let build = (raw >> 16) & 0xFFFF;
    format!("{maggiore}.{minore}.{build}")
}

/// La versione di Windows su cui questa copia sta girando.
#[cfg(windows)]
#[must_use]
pub fn windows_version() -> WindowsVersion {
    use windows::System::Profile::AnalyticsInfo;

    let Ok(info) = AnalyticsInfo::VersionInfo() else {
        return WindowsVersion::Undeterminable;
    };
    let Ok(compatta) = info.DeviceFamilyVersion() else {
        return WindowsVersion::Undeterminable;
    };
    // Il valore arriva come TESTO che rappresenta un intero a 64 bit: e' cosi'
    // che WinRT lo espone, e interpretarlo puo' fallire.
    let Ok(numero) = compatta.to_string().parse::<u64>() else {
        return WindowsVersion::Undeterminable;
    };
    if numero == 0 {
        return WindowsVersion::Undeterminable;
    }
    WindowsVersion::Known(decode_device_family_version(numero))
}

/// Fuori da Windows non c'è alcuna versione di Windows da leggere.
#[cfg(not(windows))]
#[must_use]
pub fn windows_version() -> WindowsVersion {
    WindowsVersion::Undeterminable
}

#[cfg(test)]
mod tests {
    use super::{WindowsVersion, decode_device_family_version, windows_version};

    /// **La codifica si decodifica come Microsoft la scrive.**
    ///
    /// I quattro numeri sono tutti diversi e tutti non nulli: con uno zero fra
    /// loro, uno scambio fra due campi passerebbe inosservato. Il valore e'
    /// quello di una 6.3.9600.1234, cioe' una Windows 8.1 reale.
    #[test]
    fn i_quattro_numeri_si_ricompongono_dai_bit() {
        let compatto = (6_u64 << 48) | (3_u64 << 32) | (9_600_u64 << 16) | 1_234_u64;
        assert_eq!(decode_device_family_version(compatto), "6.3.9600");
    }

    /// **La revisione non entra nella stringa.**
    ///
    /// Cambia a ogni aggiornamento cumulativo mensile: includerla
    /// costringerebbe chi pubblica a inseguire il calendario delle patch.
    #[test]
    fn la_revisione_non_cambia_la_versione_dichiarata() {
        let gennaio = (10_u64 << 48) | (26_200_u64 << 16) | 1_u64;
        let dicembre = (10_u64 << 48) | (26_200_u64 << 16) | 9_999_u64;
        assert_eq!(
            decode_device_family_version(gennaio),
            decode_device_family_version(dicembre),
            "due aggiornamenti cumulativi della stessa Windows non devono \
             risultare due versioni diverse"
        );
    }

    /// **Su questa macchina la versione si legge davvero.**
    ///
    /// La prova esercita il percorso WinRT vero, non un simulacro. Fuori da
    /// Windows dichiara «non leggibile», che e' la verita' li'.
    #[test]
    fn la_versione_di_questa_postazione_si_legge() {
        let letta = windows_version();
        if cfg!(windows) {
            let Some(versione) = letta.as_str() else {
                panic!(
                    "su Windows la versione deve essere leggibile: se non lo e', il \
                     controllo del minimo richiesto dagli aggiornamenti non puo' \
                     essere fatto e va dichiarato, non taciuto"
                );
            };
            assert_eq!(
                versione.split('.').count(),
                3,
                "la versione «{versione}» non ha la forma maggiore.minore.build"
            );
            assert!(
                versione.starts_with("10."),
                "la versione «{versione}» non comincia per 10: Windows 10 e 11 si \
                 dichiarano entrambe cosi', e un altro valore vuol dire che la \
                 decodifica sta leggendo i bit sbagliati"
            );
        } else {
            assert_eq!(letta, WindowsVersion::Undeterminable);
        }
    }

    /// Il sorgente di questo modulo, letto a tempo di compilazione.
    const SORGENTE: &str = include_str!("os_version.rs");

    /// Il manifesto del crate, per sapere quali gruppi di API sono abilitati.
    const MANIFESTO: &str = include_str!("../Cargo.toml");

    /// **La versione non si chiede alle API che Windows falsifica.**
    ///
    /// # Perche' questa guardia esiste
    ///
    /// ADR-0039, decisione 3: «Windows MENTE sulla versione ai programmi senza
    /// il manifest giusto, per compatibilita': un controllo di versione puo'
    /// leggere 6.2 su Windows 11».
    ///
    /// Questo prodotto **non ha alcun manifest applicativo**. Un controllo fatto
    /// con `GetVersionEx` o `VerifyVersionInfo` leggerebbe quindi un numero
    /// falso, e il confronto con il minimo richiesto da un aggiornamento
    /// darebbe una risposta sbagliata **senza fallire**.
    ///
    /// Nemmeno dal registro: `CurrentVersion` e' congelato per la stessa
    /// ragione.
    ///
    /// `AnalyticsInfo` non e' soggetto a quel meccanismo, e la misura su questa
    /// macchina lo conferma: legge la versione vera.
    ///
    /// Sostituire la sorgente con una di quelle non romperebbe niente. La
    /// risposta diventerebbe semplicemente falsa.
    #[test]
    fn la_versione_non_si_chiede_a_chi_la_falsifica() {
        // La riga che nomina i proibiti sta dentro la prova stessa: si guarda
        // solo il codice di produzione, altrimenti la guardia troverebbe se'
        // stessa.
        let Some(produzione) = SORGENTE.split("#[cfg(test)]").next() else {
            panic!("il modulo deve avere una parte di produzione");
        };

        for falsificata in [
            "GetVersionEx",
            "VerifyVersionInfo",
            "RtlGetVersion",
            "CurrentBuildNumber",
            "CurrentVersion",
        ] {
            assert!(
                !produzione.contains(falsificata),
                "il modulo usa «{falsificata}», che su un programma senza manifest \
                 applicativo restituisce un numero FALSO: il confronto con il \
                 minimo richiesto da un aggiornamento darebbe una risposta \
                 sbagliata senza fallire (ADR-0039, decisione 3)"
            );
        }

        assert!(
            produzione.contains("AnalyticsInfo"),
            "la sorgente della versione e' cambiata: questa prova non sta piu' \
             guardando cio' che crede"
        );
        assert!(
            !MANIFESTO.contains("Win32_System_SystemInformation"),
            "il crate abilita il gruppo di API che contiene i controlli di \
             versione falsificati: abilitarlo li rende disponibili a chiunque \
             modifichi questo modulo"
        );
    }
}

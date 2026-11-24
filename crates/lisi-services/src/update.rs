//! Il manifesto degli aggiornamenti, e la decisione se accettarne uno.
//!
//! # La regola che governa tutto il modulo
//!
//! **Il manifesto è dato non fidato.** Nulla di ciò che dice viene creduto: è un
//! suggerimento su dove guardare, e ogni sua affermazione va verificata contro
//! il file scaricato (ADR-0040).
//!
//! L'ancoraggio di fiducia è **Authenticode**, non una firma nostra: chi
//! sostituisse il manifesto per puntare a un file ostile otterrebbe un file che
//! non supera la verifica e viene cancellato.
//!
//! # L'unico attacco che il manifesto può portare a segno
//!
//! Puntare a una versione **più vecchia, legittimamente firmata, con una falla
//! nota**. Non lo ferma una firma: lo ferma una regola, e la regola è che si
//! accetta soltanto una versione **strettamente maggiore** di quella in
//! esecuzione.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non scarica nulla. Non tocca la rete. Decide, dato un manifesto già in
//! memoria e lo stato della postazione, se quell'aggiornamento sia accettabile —
//! e questa parte si prova senza rete, senza certificato e senza server.
//!
//! Lo scaricamento arriverà quando esisterà un certificato (HVQ-07): costruire
//! il pezzo che scarica prima del pezzo che lo rende sicuro è l'ordine sbagliato.

use serde::{Deserialize, Serialize};

/// Lo schema di manifesto che questa copia sa leggere.
///
/// È una delle **quattro versioni distinte** del prodotto, e confonderle è il
/// modo in cui un aggiornamento rompe un archivio: versione di prodotto, schema
/// dell'archivio, schema del manifesto, protocollo di squadra.
pub const MANIFEST_SCHEMA: u32 = 1;

/// Il nome del prodotto atteso nel manifesto.
pub const PRODUCT: &str = "nexum97-telegram-monitor";

/// L'architettura di questo binario.
pub const ARCHITECTURE: &str = "x86_64";

/// La dimensione massima ammessa per un manifesto, in byte.
///
/// Un manifesto è qualche riga di testo. Il limite agisce **prima**
/// dell'interpretazione: un file enorme non deve poter consumare memoria mentre
/// viene analizzato.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Il canale di pubblicazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Il canale ordinario. È il predefinito.
    #[default]
    Stable,
    /// Lo stesso artefatto, firmato allo stesso modo, pubblicato prima.
    ///
    /// **Non** è un canale meno verificato: un canale che allentasse le
    /// verifiche sarebbe una porta di servizio.
    Pilot,
}

impl Channel {
    /// L'etichetta stabile.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Pilot => "pilot",
        }
    }

    /// Interpreta l'etichetta conservata in archivio.
    ///
    /// # Perché `None` e non un ripiego sul canale stabile
    ///
    /// Ripiegare sarebbe comodo e sbagliato: una postazione che qualcuno ha
    /// messo sul pilota tornerebbe **in silenzio** su stabile perché
    /// un'etichetta non si è capita, e la scelta scritta in archivio direbbe
    /// una cosa mentre il programma ne fa un'altra. Chi legge decide che cosa
    /// farne, e lo dice.
    #[must_use]
    pub fn from_stored(raw: &str) -> Option<Self> {
        match raw {
            "stable" => Some(Self::Stable),
            "pilot" => Some(Self::Pilot),
            _ => None,
        }
    }

    /// L'etichetta che l'operatore legge.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Stable => "Stabile",
            Self::Pilot => "Pilota",
        }
    }
}

/// Una versione di prodotto, nella forma `maggiore.minore.correzione`.
///
/// # Perché un tipo e non una stringa
///
/// Confrontare versioni come stringhe dice che `0.10.0` viene prima di `0.9.0`,
/// che è falso e passerebbe inosservato finché il decimo rilascio non arriva.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Componente maggiore.
    pub major: u32,
    /// Componente minore.
    pub minor: u32,
    /// Componente di correzione.
    pub patch: u32,
}

impl Version {
    /// La versione di questo binario.
    #[must_use]
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Self {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }

    /// Riconosce una versione dalla propria forma testuale.
    ///
    /// Restituisce `None` per qualunque cosa non sia esattamente tre numeri
    /// separati da punti: una versione che non si capisce non si confronta.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parti = raw.trim().split('.');
        let major = parti.next()?.parse().ok()?;
        let minor = parti.next()?.parse().ok()?;
        let patch = parti.next()?.parse().ok()?;
        if parti.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Il manifesto pubblicato.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    /// Lo schema del manifesto.
    pub schema: u32,
    /// Il prodotto a cui si riferisce.
    pub product: String,
    /// La versione offerta.
    pub version: String,
    /// Il canale.
    pub channel: Channel,
    /// Quando è stato pubblicato, in forma leggibile.
    pub published: String,
    /// L'architettura dell'artefatto.
    pub architecture: String,
    /// Il minimo Windows dichiarato per questa versione.
    pub minimum_windows: String,
    /// La versione di prodotto minima da cui si può aggiornare.
    ///
    /// # Perché esiste
    ///
    /// Un aggiornamento che porta uno schema d'archivio molto più recente può
    /// non sapere migrare da una versione troppo lontana. Dichiararlo evita che
    /// qualcuno lo scopra sul proprio archivio.
    pub minimum_product: String,
    /// Dove si scarica.
    pub artifact_url: String,
    /// Quanto pesa, in byte.
    pub artifact_bytes: u64,
    /// L'impronta SHA-256 dell'artefatto.
    ///
    /// **Non è una garanzia di provenienza.** Dice che il file scaricato è
    /// quello che il manifesto descrive; chi ha scritto il manifesto resta da
    /// stabilire, e lo stabilisce Authenticode sul file.
    pub artifact_sha256: String,
    /// Le note di rilascio, in italiano piano.
    pub notes: String,
    /// La firma del manifesto, quando esisterà un'infrastruttura di chiavi.
    ///
    /// Oggi sempre assente. Il campo esiste perché aggiungerla domani non
    /// richieda un cambio di schema che romperebbe i client vecchi: l'obiezione
    /// di ADR-0037 riguardava **la chiave dentro il binario**, non le firme.
    #[serde(default)]
    pub signature: Option<String>,
    /// L'algoritmo della firma, quando c'è.
    #[serde(default)]
    pub signature_algorithm: Option<String>,
    /// Quando il manifesto è stato prodotto, in millisecondi dall'epoca.
    ///
    /// # Che cosa protegge, e che cosa no
    ///
    /// Distingue **uno specchio fermo** — una cache dimenticata, un canale che
    /// ha smesso di essere pubblicato — da «non c'è nulla di nuovo». Oggi le due
    /// cose sono indistinguibili, e una postazione può dire «aggiornato» per
    /// mesi mentre il canale è morto.
    ///
    /// **Non protegge da chi controlla il canale.** Chi può servire un manifesto
    /// vecchio può anche riscriverne la data: un campo non firmato non vincola
    /// chi scrive il file. Contro un avversario attivo serve un metadato
    /// firmato, ed è la ragione per cui ADR-0045 lascia la questione aperta
    /// invece di dichiararla chiusa.
    ///
    /// Facoltativo: un manifesto che non lo dichiara non viene rifiutato, e la
    /// postazione dice che non lo sa invece di indovinare.
    #[serde(default)]
    pub published_at_ms: Option<i64>,
}

/// Oltre quanti giorni un manifesto si considera fermo.
///
/// # Perché trenta e non sette
///
/// Un prodotto che non rilascia da tre settimane non ha un canale rotto: ha un
/// mese tranquillo. Una soglia stretta trasformerebbe la normalità in un avviso,
/// e un avviso che compare quando tutto va bene smette di essere letto.
pub const MANIFEST_STALE_AFTER_DAYS: i64 = 30;

/// Millisecondi in un giorno.
const MILLIS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;

/// Che cosa si sa della freschezza del manifesto.
///
/// Tre stati e non due: «non lo dichiara» non è «è fermo», e confonderli
/// farebbe comparire un avviso su ogni manifesto prodotto da una versione
/// precedente a questa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestFreshness {
    /// Il manifesto non dichiara quando è stato prodotto.
    Undeclared,
    /// Prodotto entro la soglia.
    Fresh,
    /// Più vecchio della soglia: il canale potrebbe essere fermo.
    Stale {
        /// Da quanti giorni.
        days: i64,
    },
}

impl ManifestFreshness {
    /// Che cosa si può dire, in una frase per l'operatore.
    ///
    /// La frase dichiara anche **che cosa il controllo non garantisce**: chi
    /// legge non deve credersi protetto da un avversario attivo.
    #[must_use]
    pub fn as_sentence(self) -> String {
        match self {
            Self::Undeclared => String::from(
                "Il file che descrive l'aggiornamento non dichiara quando è stato prodotto: non è possibile \
                 dire se il canale sia aggiornato.",
            ),
            Self::Fresh => String::new(),
            Self::Stale { days } => format!(
                "Il file che descrive l'aggiornamento è stato prodotto {days} giorni fa. Il canale degli \
                 aggiornamenti potrebbe essere fermo, e questa postazione non se ne \
                 accorgerebbe altrimenti. Il controllo riconosce uno specchio fermo, \
                 non un file sostituito da chi controlla il canale.",
            ),
        }
    }

    /// Se vale la pena dirlo all'operatore.
    #[must_use]
    pub const fn worth_saying(self) -> bool {
        !matches!(self, Self::Fresh)
    }
}

/// Quanto è fresco il manifesto, rispetto all'istante indicato.
///
/// # Perché l'istante si riceve invece di leggerlo
///
/// Leggere l'orologio qui renderebbe la funzione non provabile: due esecuzioni
/// darebbero due risposte. È la stessa ragione per cui il resto del prodotto
/// riceve `now` invece di chiederlo.
#[must_use]
pub fn freshness(manifest: &UpdateManifest, now_ms: i64) -> ManifestFreshness {
    let Some(prodotto) = manifest.published_at_ms else {
        return ManifestFreshness::Undeclared;
    };

    // Un manifesto datato nel FUTURO non e' fresco: e' un orologio sbagliato da
    // qualche parte, e trattarlo come fresco nasconderebbe il problema. Si dice
    // «non dichiarato», che e' la risposta onesta a una data che non si puo'
    // usare.
    if prodotto > now_ms {
        return ManifestFreshness::Undeclared;
    }

    let giorni = (now_ms - prodotto) / MILLIS_PER_DAY;
    if giorni > MANIFEST_STALE_AFTER_DAYS {
        ManifestFreshness::Stale { days: giorni }
    } else {
        ManifestFreshness::Fresh
    }
}

/// Lo stato della postazione, per decidere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationState {
    /// La versione in esecuzione.
    pub current_version: Version,
    /// Il canale scelto dall'ufficio.
    pub channel: Channel,
    /// La versione di Windows, nella forma `maggiore.minore.build`.
    pub windows_version: Option<String>,
}

/// Perché un aggiornamento non è stato accettato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateRefusal {
    /// Troppo grande per essere anche solo letto.
    TooLarge {
        /// Quanti byte.
        bytes: usize,
    },
    /// Non è interpretabile.
    Malformed {
        /// La ragione.
        reason: String,
    },
    /// Uno schema di manifesto che questa copia non conosce.
    UnknownSchema {
        /// Lo schema trovato.
        found: u32,
    },
    /// Un altro prodotto.
    WrongProduct {
        /// Il prodotto dichiarato.
        found: String,
    },
    /// Un'altra architettura.
    WrongArchitecture {
        /// L'architettura dichiarata.
        found: String,
    },
    /// Un altro canale.
    WrongChannel {
        /// Il canale dichiarato.
        found: Channel,
    },
    /// La versione non si capisce.
    UnreadableVersion {
        /// Il campo trovato.
        found: String,
    },
    /// Non è più recente di quella in esecuzione.
    ///
    /// È l'unico attacco che un manifesto sostituito potrebbe portare a segno,
    /// e questa è la regola che lo ferma.
    NotNewer {
        /// La versione offerta.
        offered: Version,
        /// La versione in esecuzione.
        current: Version,
    },
    /// Richiede una versione di prodotto più recente di quella in esecuzione.
    NeedsIntermediate {
        /// Il minimo richiesto.
        minimum: Version,
        /// La versione in esecuzione.
        current: Version,
    },
    /// L'impronta manca o non è una SHA-256.
    UnusableDigest,
    /// L'indirizzo dell'artefatto non è accettabile.
    UnusableUrl {
        /// La ragione.
        reason: String,
    },
    /// Richiede una versione di Windows più recente di quella in esecuzione.
    ///
    /// # Perché è un rifiuto e non un avviso
    ///
    /// Un aggiornamento installato su una Windows che non lo regge non fallisce
    /// al momento dell'installazione: fallisce **la prima volta che serve**, e a
    /// quel punto la versione precedente non c'è più.
    NeedsNewerWindows {
        /// Il minimo dichiarato dal manifesto.
        minimum: String,
        /// La versione della postazione.
        current: String,
    },
    /// Nessun firmatario degli aggiornamenti è ammesso su questa postazione
    /// (ADR-0183, decisione 5): senza, nessun manifesto si accetta.
    NoSignerAdmitted,
    /// Il manifesto non ha la sua firma accanto.
    Unsigned,
    /// La firma accanto al manifesto non si verifica.
    SignatureNotValid {
        /// Perché, come lo dice la verifica.
        reason: String,
    },
    /// La firma è valida, ma di un certificato che non è fra i firmatari
    /// ammessi.
    SignerNotAdmitted {
        /// L'impronta SHA-256 del certificato.
        sha256: String,
    },
    /// La firma è di un firmatario ritirato (ADR-0045, requisito 4).
    SignerRetired {
        /// Il nome del firmatario ritirato.
        name: String,
    },
}

impl std::fmt::Display for UpdateRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes } => write!(
                formatter,
                "l'informazione sull'aggiornamento occupa {bytes} byte e supera il \
                 limite di {MAX_MANIFEST_BYTES}: non è stata nemmeno letta."
            ),
            Self::Malformed { reason } => write!(
                formatter,
                "l'informazione sull'aggiornamento non è leggibile: {reason}."
            ),
            Self::UnknownSchema { found } => write!(
                formatter,
                "l'aggiornamento è descritto in un formato (schema {found}) che questa \
                 copia non conosce. Aggiornare a mano dal pacchetto ufficiale."
            ),
            Self::WrongProduct { found } => write!(
                formatter,
                "l'aggiornamento riguarda un altro prodotto («{found}»). Non è stato \
                 scaricato nulla."
            ),
            Self::WrongArchitecture { found } => write!(
                formatter,
                "l'aggiornamento è per un'altra architettura («{found}»). Non è stato \
                 scaricato nulla."
            ),
            Self::WrongChannel { found } => write!(
                formatter,
                "l'aggiornamento appartiene al canale {} e questa postazione segue un \
                 altro canale.",
                found.label()
            ),
            Self::UnreadableVersion { found } => write!(
                formatter,
                "la versione offerta («{found}») non è in una forma riconoscibile. \
                 Una versione che non si capisce non si confronta."
            ),
            Self::NotNewer { offered, current } => write!(
                formatter,
                "la versione offerta ({offered}) NON è più recente di quella in uso \
                 ({current}). Non è stato scaricato nulla: un aggiornamento che porta \
                 indietro riaprirebbe difetti già corretti."
            ),
            Self::NeedsIntermediate { minimum, current } => write!(
                formatter,
                "questo aggiornamento richiede almeno la versione {minimum} e qui gira \
                 la {current}. Installare prima una versione intermedia."
            ),
            Self::UnusableDigest => write!(
                formatter,
                "l'aggiornamento non dichiara un'impronta utilizzabile: senza, il file \
                 scaricato non sarebbe verificabile."
            ),
            Self::UnusableUrl { reason } => write!(
                formatter,
                "l'indirizzo dell'aggiornamento non è accettabile: {reason}."
            ),
            Self::NoSignerAdmitted => write!(
                formatter,
                "nessun firmatario degli aggiornamenti è ammesso su questa postazione. \
                 Lo ammette l'amministratore, con l'impronta del certificato del produttore."
            ),
            Self::Unsigned => write!(
                formatter,
                "l'informazione sull'aggiornamento non ha la sua firma accanto. Senza \
                 firma non si sa chi l'ha scritta."
            ),
            Self::SignatureNotValid { reason } => write!(
                formatter,
                "la firma dell'informazione sull'aggiornamento non si verifica. {reason}"
            ),
            Self::SignerNotAdmitted { sha256 } => write!(
                formatter,
                "la firma è valida, ma il certificato non è fra i firmatari ammessi. \
                 Impronta del certificato: {sha256}."
            ),
            Self::SignerRetired { name } => write!(
                formatter,
                "la firma è di «{name}», un firmatario ritirato. Una chiave ritirata non \
                 vale più."
            ),
            Self::NeedsNewerWindows { minimum, current } => write!(
                formatter,
                "questa versione richiede Windows {minimum} e la postazione ha \
                 {current}. Non è stato scaricato nulla: installarla la \
                 renderebbe inutilizzabile, e la versione precedente non ci \
                 sarebbe più."
            ),
        }
    }
}

impl std::error::Error for UpdateRefusal {}

/// Che cosa fare, dato un manifesto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDecision {
    /// C'è una versione più recente, e passa tutti i controlli.
    Offer {
        /// La versione offerta.
        version: Version,
        /// Le note di rilascio.
        notes: String,
        /// Quanto pesa.
        bytes: u64,
        /// Se il manifesto porta una firma propria.
        ///
        /// Oggi sempre falso. Serve perché la schermata non finga che il
        /// manifesto sia autenticato quando non lo è.
        manifest_signed: bool,
        /// Se il minimo di Windows è stato davvero confrontato.
        ///
        /// Falso quando la postazione non sa dire la propria versione. Serve
        /// perché la schermata non finga di aver verificato ciò che non ha
        /// potuto verificare — lo stesso motivo per cui esiste
        /// `manifest_signed`.
        windows_checked: bool,
    },
    /// Non c'è nulla da fare.
    UpToDate,
    /// L'aggiornamento è stato rifiutato, e si dice perché.
    Refused(UpdateRefusal),
}

impl UpdateDecision {
    /// L'esito, in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::UpToDate => String::from("Questa copia è già aggiornata."),
            Self::Refused(motivo) => {
                let mut testo = String::from("Aggiornamento non accettato: ");
                testo.push_str(&motivo.to_string());
                testo
            }
            Self::Offer {
                version,
                bytes,
                manifest_signed,
                windows_checked,
                ..
            } => {
                let mega = *bytes as f64 / (1024.0 * 1024.0);
                let mut testo = format!(
                    "È disponibile la versione {version} ({mega:.0} MB). Nulla è stato \
                     ancora scaricato."
                );
                if !manifest_signed {
                    testo.push_str(
                        " Questa informazione non è firmata: prima di installare, il \
                         file scaricato verrà comunque verificato con la firma di \
                         Windows.",
                    );
                }
                if !windows_checked {
                    testo.push_str(
                        " Non è stato possibile leggere la versione di Windows di \
                         questa postazione: il requisito minimo dichiarato non è \
                         stato verificato.",
                    );
                }
                testo
            }
        }
    }
}

/// Legge un manifesto e decide.
///
/// # L'ordine dei controlli non è arbitrario
///
/// Dimensione, forma, schema, identità del prodotto, architettura, canale,
/// versione, versione minima di prodotto, versione minima di Windows, impronta,
/// indirizzo. Ogni passo evita lavoro su qualcosa che il precedente avrebbe
/// scartato, e il limite di dimensione viene per primo perché è l'unico che
/// protegge **dall'analisi stessa**.
///
/// La **versione** viene prima dei requisiti della macchina di proposito: dire a
/// un ufficio che serve una Windows più recente, per un aggiornamento che poi
/// risulta essere quello già installato, manda a cercare un problema che non
/// c'è.
#[must_use]
pub fn decide(document: &str, station: &StationState) -> UpdateDecision {
    if document.len() > MAX_MANIFEST_BYTES {
        return UpdateDecision::Refused(UpdateRefusal::TooLarge {
            bytes: document.len(),
        });
    }

    let manifest: UpdateManifest = match serde_json::from_str(document) {
        Ok(manifest) => manifest,
        Err(errore) => {
            return UpdateDecision::Refused(UpdateRefusal::Malformed {
                reason: errore.to_string(),
            });
        }
    };

    evaluate(&manifest, station)
}

/// Decide su un manifesto già interpretato.
#[must_use]
pub fn evaluate(manifest: &UpdateManifest, station: &StationState) -> UpdateDecision {
    if manifest.schema != MANIFEST_SCHEMA {
        return UpdateDecision::Refused(UpdateRefusal::UnknownSchema {
            found: manifest.schema,
        });
    }
    if manifest.product != PRODUCT {
        return UpdateDecision::Refused(UpdateRefusal::WrongProduct {
            found: manifest.product.clone(),
        });
    }
    if manifest.architecture != ARCHITECTURE {
        return UpdateDecision::Refused(UpdateRefusal::WrongArchitecture {
            found: manifest.architecture.clone(),
        });
    }
    if manifest.channel != station.channel {
        return UpdateDecision::Refused(UpdateRefusal::WrongChannel {
            found: manifest.channel,
        });
    }

    let Some(offerta) = Version::parse(&manifest.version) else {
        return UpdateDecision::Refused(UpdateRefusal::UnreadableVersion {
            found: manifest.version.clone(),
        });
    };

    // La regola che ferma l'unico attacco che un manifesto sostituito potrebbe
    // portare a segno: una versione piu' vecchia, legittimamente firmata, con
    // una falla nota.
    if offerta <= station.current_version {
        if offerta == station.current_version {
            return UpdateDecision::UpToDate;
        }
        return UpdateDecision::Refused(UpdateRefusal::NotNewer {
            offered: offerta,
            current: station.current_version,
        });
    }

    let Some(minimo) = Version::parse(&manifest.minimum_product) else {
        return UpdateDecision::Refused(UpdateRefusal::UnreadableVersion {
            found: manifest.minimum_product.clone(),
        });
    };
    if station.current_version < minimo {
        return UpdateDecision::Refused(UpdateRefusal::NeedsIntermediate {
            minimum: minimo,
            current: station.current_version,
        });
    }

    // Il minimo di Windows dichiarato dal manifesto. Finche' nessuno sapeva
    // leggere la versione della postazione, questo campo non veniva confrontato
    // con niente: un aggiornamento che richiede una build piu' recente sarebbe
    // stato offerto e installato su una macchina che non lo regge.
    let mut windows_checked = false;
    if let Some(postazione) = station.windows_version.as_deref() {
        let Some(minimo_windows) = Version::parse(&manifest.minimum_windows) else {
            return UpdateDecision::Refused(UpdateRefusal::UnreadableVersion {
                found: manifest.minimum_windows.clone(),
            });
        };
        let Some(corrente_windows) = Version::parse(postazione) else {
            return UpdateDecision::Refused(UpdateRefusal::UnreadableVersion {
                found: String::from(postazione),
            });
        };
        if corrente_windows < minimo_windows {
            return UpdateDecision::Refused(UpdateRefusal::NeedsNewerWindows {
                minimum: manifest.minimum_windows.clone(),
                current: String::from(postazione),
            });
        }
        windows_checked = true;
    }

    if !is_sha256(&manifest.artifact_sha256) {
        return UpdateDecision::Refused(UpdateRefusal::UnusableDigest);
    }
    if let Err(motivo) = check_url(&manifest.artifact_url) {
        return UpdateDecision::Refused(UpdateRefusal::UnusableUrl { reason: motivo });
    }

    UpdateDecision::Offer {
        version: offerta,
        notes: manifest.notes.clone(),
        bytes: manifest.artifact_bytes,
        manifest_signed: manifest.signature.is_some() && manifest.signature_algorithm.is_some(),
        windows_checked,
    }
}

/// Se la stringa è un'impronta SHA-256 in esadecimale.
fn is_sha256(raw: &str) -> bool {
    raw.len() == 64 && raw.chars().all(|carattere| carattere.is_ascii_hexdigit())
}

/// Se l'indirizzo è accettabile.
///
/// # Perché solo HTTPS
///
/// In chiaro, chi controlla la rete può sostituire il file. Authenticode lo
/// fermerebbe comunque — è l'ancoraggio — ma far scaricare all'ufficio decine di
/// megabyte di qualcosa che verrà buttato è uno spreco che si evita chiedendo
/// una connessione protetta.
pub(crate) fn check_url(raw: &str) -> Result<(), String> {
    if !raw.starts_with("https://") {
        return Err(String::from(
            "deve cominciare con «https://»: in chiaro, chi controlla la rete può \
             sostituire il file",
        ));
    }
    if raw.len() > 2048 {
        return Err(String::from("è troppo lungo"));
    }
    // Un indirizzo con caratteri di controllo finirebbe in una riga di comando o
    // in un registro, e li' significherebbe altro.
    if raw.chars().any(char::is_control) {
        return Err(String::from("contiene caratteri non ammessi"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ARCHITECTURE, Channel, MANIFEST_SCHEMA, MANIFEST_STALE_AFTER_DAYS, MAX_MANIFEST_BYTES,
        ManifestFreshness, PRODUCT, StationState, UpdateDecision, UpdateManifest, UpdateRefusal,
        Version, decide, evaluate, freshness,
    };

    fn versione(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    fn postazione() -> StationState {
        StationState {
            current_version: versione(1, 0, 0),
            channel: Channel::Stable,
            windows_version: Some(String::from("10.0.26200")),
        }
    }

    fn manifesto() -> UpdateManifest {
        UpdateManifest {
            schema: MANIFEST_SCHEMA,
            product: String::from(PRODUCT),
            version: String::from("1.1.0"),
            channel: Channel::Stable,
            published: String::from("2026-09-01"),
            architecture: String::from(ARCHITECTURE),
            minimum_windows: String::from("10.0.19045"),
            minimum_product: String::from("1.0.0"),
            artifact_url: String::from("https://esempio.test/nexum97-1.1.0.exe"),
            artifact_bytes: 26_000_000,
            artifact_sha256: "a".repeat(64),
            notes: String::from("Correzioni e migliorie."),
            signature: None,
            signature_algorithm: None,
            published_at_ms: None,
        }
    }

    #[test]
    fn una_versione_piu_recente_viene_offerta() {
        let decisione = evaluate(&manifesto(), &postazione());
        let UpdateDecision::Offer { version, .. } = decisione else {
            panic!("una versione piu' recente deve essere offerta: {decisione:?}");
        };
        assert_eq!(version, versione(1, 1, 0));
    }

    /// **La regola che ferma l'unico attacco possibile.**
    ///
    /// Un manifesto sostituito puo' puntare a una versione piu' vecchia,
    /// legittimamente firmata, con una falla nota. Authenticode non la
    /// fermerebbe — e' firmata davvero. La ferma questa regola.
    #[test]
    fn una_versione_piu_vecchia_viene_rifiutata() {
        let mut manifesto = manifesto();
        manifesto.version = String::from("0.9.0");

        let UpdateDecision::Refused(motivo) = evaluate(&manifesto, &postazione()) else {
            panic!("un ritorno indietro non deve essere offerto");
        };
        assert!(matches!(motivo, UpdateRefusal::NotNewer { .. }));

        let messaggio = motivo.to_string();
        assert!(
            messaggio.contains("riaprirebbe difetti"),
            "il rifiuto deve dire PERCHE' un ritorno indietro e' pericoloso: \
             «{messaggio}»"
        );
    }

    #[test]
    fn la_stessa_versione_significa_gia_aggiornato() {
        let mut manifesto = manifesto();
        manifesto.version = String::from("1.0.0");
        assert_eq!(
            evaluate(&manifesto, &postazione()),
            UpdateDecision::UpToDate
        );
    }

    /// **Confrontare versioni come stringhe direbbe che 0.10.0 viene prima di
    /// 0.9.0.**
    ///
    /// Falso, e passerebbe inosservato finche' il decimo rilascio non arriva.
    #[test]
    fn le_versioni_si_confrontano_da_numeri_e_non_da_stringhe() {
        assert!(versione(0, 10, 0) > versione(0, 9, 0));
        assert!(versione(1, 0, 0) > versione(0, 99, 99));
        assert!(versione(1, 0, 10) > versione(1, 0, 9));

        let mut manifesto = manifesto();
        manifesto.version = String::from("0.10.0");
        // Il minimo va abbassato con la postazione: altrimenti a parlare sarebbe
        // il controllo sul salto, e la prova misurerebbe quello invece del
        // confronto fra versioni.
        manifesto.minimum_product = String::from("0.9.0");
        let mut postazione = postazione();
        postazione.current_version = versione(0, 9, 0);

        assert!(matches!(
            evaluate(&manifesto, &postazione),
            UpdateDecision::Offer { .. }
        ));
    }

    #[test]
    fn una_versione_illeggibile_non_si_confronta() {
        for illeggibile in ["ultima", "1.0", "1.0.0.0", "", "v1.0.0"] {
            let mut manifesto = manifesto();
            manifesto.version = String::from(illeggibile);
            assert!(
                matches!(
                    evaluate(&manifesto, &postazione()),
                    UpdateDecision::Refused(UpdateRefusal::UnreadableVersion { .. })
                ),
                "«{illeggibile}» non deve essere confrontata"
            );
        }
    }

    #[test]
    fn un_altro_prodotto_o_un_altra_architettura_si_rifiutano() {
        let mut altro = manifesto();
        altro.product = String::from("qualcos-altro");
        assert!(matches!(
            evaluate(&altro, &postazione()),
            UpdateDecision::Refused(UpdateRefusal::WrongProduct { .. })
        ));

        let mut arm = manifesto();
        arm.architecture = String::from("aarch64");
        assert!(matches!(
            evaluate(&arm, &postazione()),
            UpdateDecision::Refused(UpdateRefusal::WrongArchitecture { .. })
        ));
    }

    /// **Un canale conservato che non si riconosce non diventa «stabile».**
    ///
    /// Ripiegare sarebbe comodo e sbagliato: una postazione messa sul pilota
    /// tornerebbe indietro IN SILENZIO perche' un'etichetta non si e' capita, e
    /// la scelta scritta in archivio direbbe una cosa mentre il programma ne fa
    /// un'altra.
    #[test]
    fn un_canale_conservato_illeggibile_non_diventa_stabile() {
        assert_eq!(Channel::from_stored("stable"), Some(Channel::Stable));
        assert_eq!(Channel::from_stored("pilot"), Some(Channel::Pilot));

        for inventato in ["interno", "Stable", "stabile", "", " pilot"] {
            assert_eq!(
                Channel::from_stored(inventato),
                None,
                "«{inventato}» non deve diventare un canale"
            );
        }
    }

    /// Il sorgente di questo modulo, letto a tempo di compilazione.
    const QUESTO_MODULO: &str = include_str!("update.rs");

    /// **IL CANALE DICE QUANDO, NON QUANTO CI SI FIDA** (ADR-0066, decisione 1).
    ///
    /// Il canale decide QUALE manifesto riguarda questa postazione. Da quel
    /// punto in avanti — versione, salto minimo, Windows, impronta, indirizzo —
    /// non deve piu' comparire.
    ///
    /// **Perche' una guardia strutturale e non una prova di comportamento.** La
    /// scorciatoia non arrivera' come un difetto: arrivera' come una comodita',
    /// il giorno in cui il pilota servira' davvero e qualcuno dira' «sul pilota
    /// accettiamo anche senza firma, tanto e' per provare». Sarebbe una porta di
    /// servizio, e la migliore che un attaccante possa desiderare: gli
    /// basterebbe convincere UNA postazione a mettersi su pilota. Una prova di
    /// comportamento la vedrebbe solo per il caso che qualcuno ha pensato di
    /// scrivere; questa la vede sempre.
    #[test]
    fn il_canale_non_entra_in_nessuna_verifica() {
        // L'ancora e' il blocco intero, rifiuto compreso: fermarsi alla prima
        // riga lascerebbe dentro il rifiuto stesso, che il canale lo nomina per
        // forza.
        const SCELTA: &str = "    if manifest.channel != station.channel {\n\
                               \x20       return UpdateDecision::Refused(UpdateRefusal::WrongChannel {\n\
                               \x20           found: manifest.channel,\n\
                               \x20       });\n\
                               \x20   }\n";

        let Some(corpo) = QUESTO_MODULO.split("pub fn evaluate(").nth(1) else {
            panic!("«evaluate» non si trova in questo modulo");
        };
        let Some(verifiche) = corpo.split(SCELTA).nth(1) else {
            panic!(
                "il confronto fra i canali non si trova piu' in «evaluate»: \
                 se e' stato riscritto, questa guardia va riscritta insieme"
            );
        };
        // La coda di «evaluate» finisce alla prima parentesi a inizio riga: cio'
        // che viene dopo e' un'altra funzione, e ha diritto di nominare il
        // canale (la freschezza, per esempio, e' un'osservazione SUL canale).
        let Some(verifiche) = verifiche.split("\n}\n").next() else {
            panic!("la parte di verifica non si delimita");
        };

        // I due aiutanti che «evaluate» chiama dopo la scelta: la verifica non
        // finisce dove finisce la funzione.
        let mut da_guardare = vec![("le verifiche di «evaluate»", verifiche)];
        for aiutante in ["fn is_sha256(", "fn check_url("] {
            let Some(corpo) = QUESTO_MODULO.split(aiutante).nth(1) else {
                panic!("«{aiutante}» non si trova piu': la guardia va riscritta insieme");
            };
            let Some(corpo) = corpo.split("\n}\n").next() else {
                panic!("il corpo di «{aiutante}» non si delimita");
            };
            da_guardare.push((aiutante, corpo));
        }

        for (dove, sorgente) in da_guardare {
            let minuscolo = sorgente.to_lowercase();
            assert!(
                !minuscolo.contains("channel") && !minuscolo.contains("canale"),
                "il canale compare in {dove}: firma, impronta, versione e \
                 requisiti devono essere gli stessi sui due canali, altrimenti il \
                 pilota diventa una porta di servizio (ADR-0066)"
            );
        }
    }

    /// **Il canale si confronta una volta sola.**
    ///
    /// Due confronti sono due regole, e la seconda e' quella che nessuno
    /// rilegge: e' cosi' che un giorno una delle due dice «se pilota, salta».
    #[test]
    fn il_canale_si_confronta_una_volta_sola() {
        let Some(corpo) = QUESTO_MODULO.split("pub fn evaluate(").nth(1) else {
            panic!("«evaluate» non si trova in questo modulo");
        };
        let Some(corpo) = corpo.split("#[cfg(test)]").next() else {
            panic!("il corpo di «evaluate» non si delimita");
        };
        assert_eq!(
            corpo.matches("station.channel").count(),
            1,
            "il canale della postazione va confrontato una volta sola"
        );
    }

    #[test]
    fn un_canale_diverso_si_rifiuta() {
        let mut pilota = manifesto();
        pilota.channel = Channel::Pilot;
        assert!(matches!(
            evaluate(&pilota, &postazione()),
            UpdateDecision::Refused(UpdateRefusal::WrongChannel { .. })
        ));
    }

    /// **Un salto troppo lungo si dichiara invece di tentarlo.**
    #[test]
    fn un_aggiornamento_che_richiede_una_versione_intermedia_lo_dice() {
        let mut manifesto = manifesto();
        manifesto.version = String::from("3.0.0");
        manifesto.minimum_product = String::from("2.0.0");

        let UpdateDecision::Refused(motivo) = evaluate(&manifesto, &postazione()) else {
            panic!("un salto troppo lungo non deve essere offerto");
        };
        assert!(matches!(motivo, UpdateRefusal::NeedsIntermediate { .. }));
        assert!(motivo.to_string().contains("versione intermedia"));
    }

    #[test]
    fn un_impronta_inutilizzabile_ferma_tutto() {
        for cattiva in ["", "abc", &"z".repeat(64), &"a".repeat(63)] {
            let mut manifesto = manifesto();
            manifesto.artifact_sha256 = String::from(cattiva);
            assert!(
                matches!(
                    evaluate(&manifesto, &postazione()),
                    UpdateDecision::Refused(UpdateRefusal::UnusableDigest)
                ),
                "«{cattiva}» non e' un'impronta utilizzabile"
            );
        }
    }

    /// **Solo HTTPS.**
    ///
    /// Authenticode fermerebbe comunque un file sostituito, ma far scaricare
    /// all'ufficio decine di megabyte di qualcosa che verra' buttato e' uno
    /// spreco che si evita chiedendo una connessione protetta.
    #[test]
    fn un_indirizzo_in_chiaro_si_rifiuta() {
        let mut manifesto = manifesto();
        manifesto.artifact_url = String::from("http://esempio.test/x.exe");

        let UpdateDecision::Refused(motivo) = evaluate(&manifesto, &postazione()) else {
            panic!("un indirizzo in chiaro non deve essere accettato");
        };
        assert!(matches!(motivo, UpdateRefusal::UnusableUrl { .. }));
        assert!(motivo.to_string().contains("https"));
    }

    #[test]
    fn un_manifesto_enorme_non_viene_nemmeno_letto() {
        let enorme = "x".repeat(MAX_MANIFEST_BYTES + 1);
        let UpdateDecision::Refused(motivo) = decide(&enorme, &postazione()) else {
            panic!("un manifesto oltre il limite non deve essere letto");
        };
        assert!(matches!(motivo, UpdateRefusal::TooLarge { .. }));
        assert!(motivo.to_string().contains("non è stata nemmeno letta"));
    }

    #[test]
    fn un_campo_sconosciuto_viene_rifiutato_invece_che_ignorato() {
        let con_extra = r#"{"schema":1,"product":"nexum97-telegram-monitor","version":"1.1.0","channel":"stable","published":"x","architecture":"x86_64","minimum_windows":"10.0","minimum_product":"1.0.0","artifact_url":"https://x.test/a","artifact_bytes":1,"artifact_sha256":"aaaa","notes":"","sorpresa":true}"#;
        assert!(matches!(
            decide(con_extra, &postazione()),
            UpdateDecision::Refused(UpdateRefusal::Malformed { .. })
        ));
    }

    #[test]
    fn uno_schema_futuro_si_rifiuta_invece_di_interpretarlo_a_meta() {
        let mut manifesto = manifesto();
        manifesto.schema = MANIFEST_SCHEMA + 1;

        let UpdateDecision::Refused(motivo) = evaluate(&manifesto, &postazione()) else {
            panic!("uno schema sconosciuto non deve essere interpretato");
        };
        assert!(matches!(motivo, UpdateRefusal::UnknownSchema { .. }));
        assert!(motivo.to_string().contains("Aggiornare a mano"));
    }

    /// **Il prodotto non finge che il manifesto sia autenticato.**
    ///
    /// Finche' non esiste un'infrastruttura di chiavi, la firma e' assente e va
    /// detto dove l'operatore lo legge.
    #[test]
    fn un_manifesto_non_firmato_lo_dichiara() {
        let decisione = evaluate(&manifesto(), &postazione());
        let UpdateDecision::Offer {
            manifest_signed, ..
        } = decisione
        else {
            panic!("l'aggiornamento deve essere offerto");
        };
        assert!(!manifest_signed);

        let messaggio = decisione.operator_message();
        assert!(
            messaggio.contains("non è firmata"),
            "l'operatore deve sapere che l'informazione non e' autenticata: \
             «{messaggio}»"
        );
        assert!(
            messaggio.contains("firma di Windows"),
            "e deve sapere che cosa la protegge davvero: «{messaggio}»"
        );
    }

    #[test]
    fn nulla_viene_scaricato_prima_che_qualcuno_lo_chieda() {
        let messaggio = evaluate(&manifesto(), &postazione()).operator_message();
        assert!(
            messaggio.contains("Nulla è stato ancora scaricato"),
            "l'operatore deve sapere che il prodotto non ha ancora toccato la rete \
             per l'artefatto: «{messaggio}»"
        );
    }

    /// **Un aggiornamento che richiede una Windows piu' recente si rifiuta.**
    ///
    /// # Il difetto che questa prova chiude
    ///
    /// Il manifesto dichiarava `minimum_windows` e la postazione portava
    /// `windows_version`, e **nessuno dei due veniva confrontato con niente**.
    /// Un aggiornamento pensato per una build piu' recente sarebbe stato
    /// offerto e installato su una macchina che non lo regge — e non
    /// fallirebbe all'installazione: fallirebbe la prima volta che serve, con
    /// la versione precedente ormai sostituita.
    #[test]
    fn un_aggiornamento_che_chiede_una_windows_piu_recente_si_rifiuta() {
        let mut manifesto = manifesto();
        manifesto.minimum_windows = String::from("10.0.99999");

        let decisione = evaluate(&manifesto, &postazione());
        let UpdateDecision::Refused(UpdateRefusal::NeedsNewerWindows { minimum, current }) =
            decisione
        else {
            panic!("una Windows troppo vecchia deve fermare l'aggiornamento: {decisione:?}");
        };
        assert_eq!(minimum, "10.0.99999");
        assert_eq!(current, "10.0.26200");
    }

    /// **Una Windows sufficiente non ferma niente.**
    ///
    /// Il controllo negativo del controllo: se rifiutasse sempre, la prova
    /// precedente sarebbe verde per la ragione sbagliata.
    #[test]
    fn una_windows_sufficiente_lascia_passare_l_aggiornamento() {
        let mut manifesto = manifesto();
        manifesto.minimum_windows = String::from("10.0.19045");

        let decisione = evaluate(&manifesto, &postazione());
        let UpdateDecision::Offer {
            windows_checked, ..
        } = decisione
        else {
            panic!("una Windows sufficiente non deve fermare nulla: {decisione:?}");
        };
        assert!(
            windows_checked,
            "il requisito e' stato confrontato: dichiararlo non verificato \
             sarebbe falso al contrario"
        );
    }

    /// **Chi non sa la propria Windows lo dichiara invece di fingere.**
    ///
    /// Rifiutare tutto renderebbe una postazione simile impossibile da
    /// aggiornare per sempre; offrire in silenzio farebbe credere che il
    /// requisito sia stato verificato. La terza via e' dirlo, ed e' la stessa
    /// scelta gia' fatta per il manifesto non firmato.
    #[test]
    fn una_postazione_che_non_sa_la_propria_windows_lo_dichiara() {
        let mut postazione = postazione();
        postazione.windows_version = None;

        let decisione = evaluate(&manifesto(), &postazione);
        let UpdateDecision::Offer {
            windows_checked, ..
        } = &decisione
        else {
            panic!(
                "non saper leggere la versione non deve impedire ogni aggiornamento: {decisione:?}"
            );
        };
        assert!(!windows_checked);

        let messaggio = decisione.operator_message();
        assert!(
            messaggio.contains("non è stato verificato"),
            "il messaggio non dichiara che il requisito non e' stato \
             verificato: «{messaggio}»"
        );
    }

    /// **Un minimo di Windows illeggibile non si interpreta a meta'.**
    #[test]
    fn un_minimo_di_windows_illeggibile_non_si_confronta() {
        let mut manifesto = manifesto();
        manifesto.minimum_windows = String::from("undici");

        let decisione = evaluate(&manifesto, &postazione());
        assert!(
            matches!(
                decisione,
                UpdateDecision::Refused(UpdateRefusal::UnreadableVersion { .. })
            ),
            "un minimo illeggibile deve fermare, non essere ignorato: {decisione:?}"
        );
    }

    /// **Il minimo di Windows si confronta da numeri, non da stringhe.**
    ///
    /// «10.0.26200» e «10.0.9000»: per un ordinamento alfabetico la prima viene
    /// PRIMA della seconda, e una postazione aggiornata risulterebbe troppo
    /// vecchia. Il caso e' scelto apposta perche' le due letture diano risposte
    /// opposte: con numeri uguali o vicini una svista non si vedrebbe.
    #[test]
    fn il_minimo_di_windows_si_confronta_da_numeri() {
        let mut manifesto = manifesto();
        manifesto.minimum_windows = String::from("10.0.9000");

        let decisione = evaluate(&manifesto, &postazione());
        assert!(
            matches!(decisione, UpdateDecision::Offer { .. }),
            "10.0.26200 e' piu' recente di 10.0.9000: {decisione:?}"
        );
    }
    #[test]
    fn ogni_rifiuto_dice_quale_controllo_ha_fallito() {
        // «non aggiornato» senza ragione manda chi legge a indovinare.
        for motivo in [
            UpdateRefusal::TooLarge { bytes: 1 },
            UpdateRefusal::Malformed {
                reason: String::from("x"),
            },
            UpdateRefusal::UnknownSchema { found: 9 },
            UpdateRefusal::WrongProduct {
                found: String::from("x"),
            },
            UpdateRefusal::WrongArchitecture {
                found: String::from("x"),
            },
            UpdateRefusal::WrongChannel {
                found: Channel::Pilot,
            },
            UpdateRefusal::UnreadableVersion {
                found: String::from("x"),
            },
            UpdateRefusal::NotNewer {
                offered: versione(0, 1, 0),
                current: versione(1, 0, 0),
            },
            UpdateRefusal::NeedsIntermediate {
                minimum: versione(2, 0, 0),
                current: versione(1, 0, 0),
            },
            UpdateRefusal::UnusableDigest,
            UpdateRefusal::UnusableUrl {
                reason: String::from("x"),
            },
            UpdateRefusal::NeedsNewerWindows {
                minimum: String::from("10.0.26100"),
                current: String::from("10.0.19045"),
            },
        ] {
            let messaggio = motivo.to_string();
            assert!(
                messaggio.len() > 40,
                "{motivo:?} liquida il rifiuto: «{messaggio}»"
            );
        }
    }

    /// **Il canale predefinito e' quello stabile.**
    #[test]
    fn il_canale_predefinito_e_stabile() {
        assert_eq!(Channel::default(), Channel::Stable);
    }

    #[test]
    fn la_versione_di_questo_binario_si_legge() {
        // Se il manifesto del pacchetto smettesse di avere una versione in tre
        // parti, ogni confronto ricadrebbe su 0.0.0 e QUALUNQUE aggiornamento
        // sembrerebbe piu' recente.
        let corrente = Version::current();
        assert_ne!(
            corrente,
            versione(0, 0, 0),
            "la versione del binario non e' leggibile: ogni aggiornamento \
             sembrerebbe piu' recente di questa copia"
        );
    }

    // --------------------------------- la freschezza del canale (ADR-0045)

    /// Un istante di riferimento, e uno spostato dei giorni indicati.
    fn adesso() -> i64 {
        1_756_000_000_000
    }

    /// **Un manifesto che non dichiara la data non viene rifiutato.**
    ///
    /// Un manifesto prodotto da una versione precedente a questa non porta il
    /// campo. Trattare «non lo dichiara» come «e' fermo» farebbe comparire un
    /// avviso su ogni manifesto vecchio, e un avviso che compare quando tutto va
    /// bene smette di essere letto.
    #[test]
    fn un_manifesto_senza_data_non_diventa_un_avviso() {
        let manifesto = manifesto();
        assert_eq!(manifesto.published_at_ms, None);
        assert_eq!(
            freshness(&manifesto, adesso()),
            ManifestFreshness::Undeclared
        );

        // La decisione non cambia: la freschezza non e' un rifiuto.
        assert!(matches!(
            evaluate(&manifesto, &postazione()),
            UpdateDecision::Offer { .. }
        ));
    }

    /// **Un manifesto fermo si riconosce, e la frase dice fino a dove arriva.**
    ///
    /// La meta' che conta e' la seconda: il controllo riconosce uno specchio
    /// fermo, NON un manifesto sostituito da chi controlla il canale. Chi legge
    /// non deve credersi protetto da un avversario attivo.
    #[test]
    fn un_manifesto_fermo_si_riconosce_e_dichiara_il_proprio_limite() {
        let vecchio = MANIFEST_STALE_AFTER_DAYS + 15;
        let manifesto = UpdateManifest {
            published_at_ms: Some(adesso() - vecchio * 24 * 60 * 60 * 1_000),
            ..manifesto()
        };

        let ManifestFreshness::Stale { days } = freshness(&manifesto, adesso()) else {
            panic!("un manifesto di {vecchio} giorni deve risultare fermo");
        };
        assert_eq!(days, vecchio);

        let frase = ManifestFreshness::Stale { days }.as_sentence();
        assert!(
            frase.contains("potrebbe essere fermo"),
            "la frase deve dire che cosa e' successo: «{frase}»"
        );
        assert!(
            frase.contains("non un file sostituito"),
            "e deve dire fino a dove il controllo NON arriva: «{frase}»"
        );

        // E l'aggiornamento resta offerto: un canale fermo non e' un
        // aggiornamento rifiutato.
        assert!(matches!(
            evaluate(&manifesto, &postazione()),
            UpdateDecision::Offer { .. }
        ));
    }

    /// **Un manifesto entro la soglia non dice nulla.**
    ///
    /// Il caso ordinario, e un avviso che comparisse comunque insegnerebbe a
    /// ignorarlo.
    #[test]
    fn un_manifesto_fresco_non_ha_nulla_da_dire() {
        let manifesto = UpdateManifest {
            published_at_ms: Some(adesso() - 3 * 24 * 60 * 60 * 1_000),
            ..manifesto()
        };

        assert_eq!(freshness(&manifesto, adesso()), ManifestFreshness::Fresh);
        assert!(!ManifestFreshness::Fresh.worth_saying());
        assert!(ManifestFreshness::Fresh.as_sentence().is_empty());
    }

    /// **Una data nel futuro non conta come fresca.**
    ///
    /// E' un orologio sbagliato da qualche parte — sulla postazione o su chi ha
    /// prodotto il manifesto — e trattarla come fresca nasconderebbe il
    /// problema. Si dice «non dichiarata», che e' la risposta onesta a una data
    /// che non si puo' usare.
    #[test]
    fn una_data_nel_futuro_non_e_freschezza() {
        let manifesto = UpdateManifest {
            published_at_ms: Some(adesso() + 10 * 24 * 60 * 60 * 1_000),
            ..manifesto()
        };

        assert_eq!(
            freshness(&manifesto, adesso()),
            ManifestFreshness::Undeclared,
            "una data futura non deve passare per fresca"
        );
    }

    /// **Il campo nuovo non rompe un manifesto scritto senza di esso.**
    ///
    /// E' la ragione per cui e' facoltativo: un client nuovo deve poter leggere
    /// un manifesto vecchio, altrimenti aggiungere un campo significherebbe
    /// cambiare schema e rompere ogni canale gia' pubblicato.
    #[test]
    fn un_manifesto_scritto_senza_il_campo_si_legge_lo_stesso() {
        let documento = r#"{
            "schema": 1,
            "product": "NEXUM/97",
            "version": "1.1.0",
            "channel": "stable",
            "published": "2026-09-01",
            "architecture": "x86_64",
            "minimum_windows": "10.0.19045",
            "minimum_product": "1.0.0",
            "artifact_url": "https://esempio.test/x.exe",
            "artifact_bytes": 100,
            "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "notes": "niente"
        }"#;

        let letto: UpdateManifest =
            serde_json::from_str(documento).expect("un manifesto senza il campo deve leggersi");
        assert_eq!(letto.published_at_ms, None);
    }
}

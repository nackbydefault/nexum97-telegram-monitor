//! L'handshake applicativo: il primo scambio dentro il TLS verificato.
//!
//! # La sequenza
//!
//! ```text
//! postazione                                     Hub
//!     | -- Hello { protocollo, versioni,          |
//!     |           capacità, dispositivo, gettone } ->
//!     |                                            |  versioni in comune?
//!     |                                            |  gettone riconosciuto?
//!     | <- Welcome { versione, capacità,           |
//!     |              versioni dell'Hub }           |
//!     |    oppure Refused { motivo, versioni }  -- |
//! ```
//!
//! # Il gettone, una volta per connessione
//!
//! ADR-0082 decisione 4: il gettone si presenta **una volta**, subito dopo il TLS
//! verificato e **prima di qualunque altro messaggio**, e non viaggia nei
//! comandi. Per questo sta nell'`Hello`, che è il primo frame, e in nessun altro
//! messaggio di questo protocollo.
//!
//! # Che cosa il rifiuto non dice
//!
//! «Non riconosciuto» **non distingue** un dispositivo sconosciuto da un gettone
//! sbagliato (ADR-0047 decisione 5). Un dispositivo **ritirato** è rifiutato come
//! tale, perché chi amministra deve vederlo accadere (ADR-0082 decisione 4): la
//! decisione su quale dei due dire spetta a chi autentica (HUB-AUTHZ-01), e
//! questo modulo non la può rendere più loquace.
//!
//! # Rigido, di proposito
//!
//! I messaggi dell'handshake rifiutano i campi sconosciuti: ciò che cambia in
//! essi cambia la versione. L'estensione ordinaria passa dalle capacità.
//!
//! # L'arruolamento: l'altro primo frame (ADR-0132)
//!
//! ```text
//! postazione                                     Hub
//!     | -- Enroll { protocollo, versioni,         |
//!     |            dispositivo, nome, codice,     |
//!     |            sale, impronta del gettone } ->|  freno, dispositivo, codice
//!     | <- Enrolled { hub, istante }              |
//!     |    oppure EnrollmentRefused { motivo }  --|  e la connessione si chiude
//! ```
//!
//! Il codice parte **solo** dentro un canale il cui capo ha dimostrato di
//! possedere la chiave del foglietto (ADR-0082 decisione 2): il verificatore TLS
//! lo controlla prima che questo modulo scriva un byte. Dopo la risposta la
//! connessione si chiude: chi è appena entrato si ripresenta con il gettone,
//! come tutti.

use std::time::{Duration, Instant};

use lisi_core::digest::Sha256Digest;
use lisi_core::model::enrollment::{
    DeviceToken, EnrollmentCode, EnrollmentRequest, EnrollmentSalt,
};
use lisi_core::model::identity::DeviceId;
use lisi_core::text::DisplayName;
use serde::{Deserialize, Serialize};

use crate::protocol::frame::{FrameError, TimedStream, read_frame, write_frame};
use crate::protocol::negotiation::{
    KNOWN_CAPABILITIES, VersionRange, accept_capabilities, highest_common, is_valid_capability_list,
};

/// Il nome del protocollo, identico all'ALPN.
pub const PROTOCOL_NAME: &str = "nexum97-hub";

/// Il tetto dei frame dell'handshake. Un `Hello` pieno sta sotto i due kibibyte.
pub const HANDSHAKE_MAX_FRAME_BYTES: u32 = 4 * 1024;

/// Quanto può durare l'handshake applicativo, dal primo byte all'ultimo.
///
/// Scelto da noi, non misurato: in LAN l'`Hello` e la risposta sono due frame
/// piccoli, e il tempo vero è quello dell'autenticazione sull'Hub.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Il gettone come l'Hub lo riceve.
///
/// Come `DeviceToken`: niente `Display`, niente `Clone`, niente
/// serializzazione, `Debug` redatto, azzerato quando cade. L'Hub non lo
/// conserva: ne calcola l'impronta e la confronta.
pub struct PresentedToken([u8; 32]);

impl PresentedToken {
    /// L'impronta da confrontare con quella conservata all'arruolamento.
    #[must_use]
    pub fn verifier(&self) -> Sha256Digest {
        Sha256Digest::of_bytes(&self.0)
    }
}

impl core::fmt::Debug for PresentedToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PresentedToken(«redatto»)")
    }
}

impl Drop for PresentedToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Che cosa decide chi autentica il dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// Dispositivo arruolato, gettone corretto.
    Accepted,
    /// Sconosciuto **o** gettone sbagliato: non si distingue.
    NotRecognized,
    /// Dispositivo ritirato, con gettone corretto.
    Revoked,
}

/// Perché l'Hub rifiuta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// Il primo frame non è un `Hello` ben formato.
    Malformed,
    /// Nessuna versione in comune.
    UnsupportedVersion,
    /// Dispositivo non riconosciuto.
    NotRecognized,
    /// Dispositivo ritirato.
    DeviceRevoked,
}

/// Perché l'Hub non ha ammesso una postazione (ADR-0132).
///
/// Ricalca `EnrollmentRefusal` di `lisi-core`, con una voce in più: un guasto
/// dell'Hub, che **non** è un tentativo andato a vuoto. La ragione del ritiro
/// non viaggia: la legge chi amministra l'Hub, non chi bussa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentRefusalReason {
    /// Codice inesistente o sbagliato: non si distingue (ADR-0047 decisione 5).
    CodeNotRecognised,
    /// Codice scaduto.
    CodeExpired,
    /// Codice già usato.
    CodeAlreadyUsed,
    /// Dispositivo già ammesso da questo Hub.
    DeviceAlreadyEnrolled,
    /// Dispositivo ritirato.
    DeviceRevoked,
    /// Troppi tentativi a vuoto di recente.
    TooManyRecentFailures,
    /// L'Hub non è riuscito a registrare la richiesta.
    HubFault,
}

/// Che cosa l'Hub risponde a una richiesta di arruolamento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentAnswer {
    /// La postazione è entrata.
    Admitted {
        /// Il nome dell'Hub, come l'Hub lo dichiara: **dato remoto**, da
        /// rivalidare.
        hub: String,
        /// Quando, in millisecondi dall'epoca, secondo l'orologio dell'Hub.
        enrolled_at_ms: i64,
    },
    /// La postazione non è entrata.
    Refused {
        /// Perché.
        reason: EnrollmentRefusalReason,
        /// Fra quanti minuti riprovare, quando il freno è chiuso.
        retry_in_minutes: Option<i64>,
    },
}

/// Che cosa l'Hub ha concluso dal primo frame.
#[derive(Debug)]
pub enum HubOpening {
    /// Una postazione arruolata si è presentata: comincia la sessione.
    Session(AcceptedDevice),
    /// Una postazione ha chiesto di entrare, e ha avuto la risposta. La
    /// connessione **si chiude** (ADR-0132 decisione 1).
    Enrollment,
}

/// Ciò su cui le due estremità si sono accordate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// La versione del protocollo in uso.
    pub version: u16,
    /// Le capacità accettate da entrambe.
    pub capabilities: Vec<String>,
}

/// Un dispositivo che ha concluso l'handshake con l'Hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedDevice {
    /// Il dispositivo **autenticato** dal gettone.
    pub device: DeviceId,
    /// L'accordo.
    pub negotiated: Negotiated,
}

/// Che cosa la postazione offre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOffer {
    /// Le versioni che sa parlare.
    pub versions: VersionRange,
    /// Le capacità che offre.
    pub capabilities: Vec<String>,
    /// Le capacità senza le quali non vuole proseguire.
    pub required: Vec<String>,
}

impl Default for ClientOffer {
    /// L'offerta del programma: tutto ciò che sa parlare, **sempre la stessa**.
    fn default() -> Self {
        Self {
            versions: VersionRange::SUPPORTED,
            capabilities: KNOWN_CAPABILITIES
                .iter()
                .map(|nome| String::from(*nome))
                .collect(),
            required: Vec::new(),
        }
    }
}

/// Che cosa l'Hub sa parlare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubOffer {
    /// Le versioni.
    pub versions: VersionRange,
    /// Le capacità conosciute.
    pub capabilities: Vec<String>,
}

impl Default for HubOffer {
    fn default() -> Self {
        Self {
            versions: VersionRange::SUPPORTED,
            capabilities: KNOWN_CAPABILITIES
                .iter()
                .map(|nome| String::from(*nome))
                .collect(),
        }
    }
}

/// Perché l'handshake non è riuscito.
///
/// Nessuna variante porta il gettone, il testo ricevuto o l'identificativo del
/// dispositivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Il frame non si è potuto leggere o scrivere.
    Frame(FrameError),
    /// L'altro capo ha mandato qualcosa che non è un messaggio dell'handshake.
    Malformed,
    /// L'Hub ha rifiutato, e dichiara le versioni che parla.
    Refused {
        /// Il motivo.
        reason: RefusalReason,
        /// Le versioni dell'Hub.
        hub_versions: VersionRange,
    },
    /// L'Hub ha scelto una versione diversa dalla più alta in comune.
    Downgrade,
    /// L'Hub ha risposto violando il protocollo: capacità mai offerte,
    /// intervallo malformato.
    ProtocolViolation,
    /// Manca una capacità che la postazione ha dichiarato necessaria.
    MissingCapability,
    /// L'offerta locale non è ben formata: un difetto di questo programma.
    InvalidOffer,
}

impl From<FrameError> for HandshakeError {
    fn from(errore: FrameError) -> Self {
        Self::Frame(errore)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientFrame {
    Hello {
        protocol: String,
        versions: VersionRange,
        capabilities: Vec<String>,
        device: String,
        token: String,
    },
    /// La richiesta di arruolamento (ADR-0132): i campi di `EnrollmentRequest`.
    Enroll {
        protocol: String,
        versions: VersionRange,
        device: String,
        label: String,
        code: String,
        salt: String,
        verifier: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum HubFrame {
    Welcome {
        version: u16,
        capabilities: Vec<String>,
        hub_versions: VersionRange,
    },
    Refused {
        reason: RefusalReason,
        hub_versions: VersionRange,
    },
    Enrolled {
        hub: String,
        enrolled_at: i64,
    },
    EnrollmentRefused {
        reason: EnrollmentRefusalReason,
        retry_in_minutes: Option<i64>,
    },
}

// ---------------------------------------------------------------------------
// Lato della postazione
// ---------------------------------------------------------------------------

/// Si presenta all'Hub e ne verifica la risposta.
///
/// # Errori
///
/// Vedere [`HandshakeError`]. In particolare [`HandshakeError::Downgrade`] se
/// l'Hub sceglie una versione che non è la più alta in comune.
pub fn client_handshake<S: TimedStream + ?Sized>(
    stream: &mut S,
    device: &DeviceId,
    token: &DeviceToken,
    offer: &ClientOffer,
) -> Result<Negotiated, HandshakeError> {
    if !offer.versions.is_well_formed()
        || !is_valid_capability_list(&offer.capabilities)
        || !offer
            .required
            .iter()
            .all(|nome| offer.capabilities.contains(nome))
    {
        return Err(HandshakeError::InvalidOffer);
    }
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;

    let mut hello = ClientFrame::Hello {
        protocol: String::from(PROTOCOL_NAME),
        versions: offer.versions,
        capabilities: offer.capabilities.clone(),
        device: String::from(device.as_str()),
        token: to_hex(token.expose()),
    };
    let serializzato = serde_json::to_vec(&hello).map_err(|_| HandshakeError::InvalidOffer);
    // Il gettone in esadecimale va azzerato comunque vada: best-effort, come
    // ogni segreto del prodotto (limite dichiarato in ADR-0084).
    if let ClientFrame::Hello {
        token: esadecimale, ..
    } = &mut hello
    {
        azzera(esadecimale);
    }
    let mut serializzato = serializzato?;
    let scritto = write_frame(stream, &serializzato, HANDSHAKE_MAX_FRAME_BYTES);
    serializzato.fill(0);
    scritto?;

    let risposta = read_frame(stream, HANDSHAKE_MAX_FRAME_BYTES, deadline)?;
    let risposta: HubFrame =
        serde_json::from_slice(&risposta).map_err(|_| HandshakeError::Malformed)?;

    match risposta {
        HubFrame::Refused {
            reason,
            hub_versions,
        } => Err(HandshakeError::Refused {
            reason,
            hub_versions,
        }),
        // A un Hello non si risponde con l'esito di un arruolamento.
        HubFrame::Enrolled { .. } | HubFrame::EnrollmentRefused { .. } => {
            Err(HandshakeError::ProtocolViolation)
        }
        HubFrame::Welcome {
            version,
            capabilities,
            hub_versions,
        } => {
            // IL RIFIUTO DELLA RETROCESSIONE: la versione attesa si ricalcola
            // da ciò che l'Hub dichiara di parlare, e ogni altra è rifiutata.
            let Some(attesa) = highest_common(offer.versions, hub_versions) else {
                return Err(HandshakeError::ProtocolViolation);
            };
            if version != attesa {
                return Err(HandshakeError::Downgrade);
            }
            if !is_valid_capability_list(&capabilities)
                || !capabilities
                    .iter()
                    .all(|nome| offer.capabilities.contains(nome))
            {
                return Err(HandshakeError::ProtocolViolation);
            }
            if !offer
                .required
                .iter()
                .all(|nome| capabilities.contains(nome))
            {
                return Err(HandshakeError::MissingCapability);
            }
            Ok(Negotiated {
                version,
                capabilities,
            })
        }
    }
}

/// Chiede all'Hub di ammettere questa postazione (ADR-0132).
///
/// Il canale **deve** essere già verificato con l'attesa del foglietto: è il
/// chiamante che lo apre con `HubExpectation::Enrollment`, e il verificatore
/// TLS ha già rifiutato ogni altra chiave prima che questa funzione scriva.
///
/// Dopo la risposta la connessione non serve più: chi chiama la chiude.
///
/// # Errori
///
/// [`HandshakeError::Refused`] quando l'Hub non sa leggere la richiesta — un
/// Hub di una generazione precedente risponde `Malformed` — o non ha una
/// versione in comune; [`HandshakeError::ProtocolViolation`] se l'Hub risponde
/// con un frame che non è l'esito di un arruolamento. **Un rifiuto
/// dell'arruolamento non è un errore**: è un esito, in [`EnrollmentAnswer`].
pub fn client_enroll<S: TimedStream + ?Sized>(
    stream: &mut S,
    request: &EnrollmentRequest,
    versions: VersionRange,
) -> Result<EnrollmentAnswer, HandshakeError> {
    if !versions.is_well_formed() {
        return Err(HandshakeError::InvalidOffer);
    }
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;

    let mut richiesta = ClientFrame::Enroll {
        protocol: String::from(PROTOCOL_NAME),
        versions,
        device: String::from(request.device_id.as_str()),
        label: String::from(request.label.as_str()),
        // L'unico accesso al codice in chiaro. Qui esce verso l'Hub che ha già
        // dimostrato la chiave del foglietto, ed è il suo unico scopo.
        code: String::from(request.code.reveal_to_administrator()),
        salt: String::from(request.salt.as_str()),
        verifier: String::from(request.verifier.as_str()),
    };
    let serializzato = serde_json::to_vec(&richiesta).map_err(|_| HandshakeError::InvalidOffer);
    if let ClientFrame::Enroll { code, .. } = &mut richiesta {
        azzera(code);
    }
    let mut serializzato = serializzato?;
    let scritto = write_frame(stream, &serializzato, HANDSHAKE_MAX_FRAME_BYTES);
    serializzato.fill(0);
    scritto?;

    let risposta = read_frame(stream, HANDSHAKE_MAX_FRAME_BYTES, deadline)?;
    let risposta: HubFrame =
        serde_json::from_slice(&risposta).map_err(|_| HandshakeError::Malformed)?;
    match risposta {
        HubFrame::Enrolled { hub, enrolled_at } => Ok(EnrollmentAnswer::Admitted {
            hub,
            enrolled_at_ms: enrolled_at,
        }),
        HubFrame::EnrollmentRefused {
            reason,
            retry_in_minutes,
        } => Ok(EnrollmentAnswer::Refused {
            reason,
            retry_in_minutes,
        }),
        HubFrame::Refused {
            reason,
            hub_versions,
        } => Err(HandshakeError::Refused {
            reason,
            hub_versions,
        }),
        HubFrame::Welcome { .. } => Err(HandshakeError::ProtocolViolation),
    }
}

// ---------------------------------------------------------------------------
// Lato dell'Hub
// ---------------------------------------------------------------------------

/// Riceve il `Hello`, lo verifica, chiede a `authenticate` e risponde.
///
/// `authenticate` è chiamata **solo** dopo che il messaggio è ben formato e
/// una versione in comune esiste, e al più una volta.
///
/// Una richiesta di arruolamento è rifiutata come malformata: questa forma
/// serve chi non arruola, come il banco dei guasti. L'Hub del prodotto usa
/// [`hub_opening`].
///
/// # Errori
///
/// Vedere [`HandshakeError`]. Quando l'Hub rifiuta, l'errore restituito è
/// [`HandshakeError::Refused`] con il motivo che ha mandato; chi chiama chiude
/// la connessione.
pub fn hub_handshake<S, A>(
    stream: &mut S,
    offer: &HubOffer,
    authenticate: A,
) -> Result<AcceptedDevice, HandshakeError>
where
    S: TimedStream + ?Sized,
    A: FnOnce(&DeviceId, &PresentedToken) -> AuthDecision,
{
    match primo_frame(
        stream,
        offer,
        authenticate,
        None::<fn(EnrollmentRequest) -> EnrollmentAnswer>,
    )? {
        HubOpening::Session(accettato) => Ok(accettato),
        // Senza chi ammette, una richiesta di arruolamento e' gia' stata
        // rifiutata come malformata: questo ramo non si raggiunge.
        HubOpening::Enrollment => Err(HandshakeError::Malformed),
    }
}

/// Riceve il primo frame: una postazione che si presenta **o** una che chiede
/// di entrare (ADR-0132).
///
/// `enroll` è chiamata **solo** con una richiesta ben formata — ogni campo
/// riattraversa i tipi del dominio — e con una versione in comune; al più una
/// volta. La sua risposta parte, e la connessione non serve più.
///
/// # Errori
///
/// Gli stessi di [`hub_handshake`].
pub fn hub_opening<S, A, E>(
    stream: &mut S,
    offer: &HubOffer,
    authenticate: A,
    enroll: E,
) -> Result<HubOpening, HandshakeError>
where
    S: TimedStream + ?Sized,
    A: FnOnce(&DeviceId, &PresentedToken) -> AuthDecision,
    E: FnOnce(EnrollmentRequest) -> EnrollmentAnswer,
{
    primo_frame(stream, offer, authenticate, Some(enroll))
}

/// Il corpo comune delle due forme dell'Hub.
fn primo_frame<S, A, E>(
    stream: &mut S,
    offer: &HubOffer,
    authenticate: A,
    enroll: Option<E>,
) -> Result<HubOpening, HandshakeError>
where
    S: TimedStream + ?Sized,
    A: FnOnce(&DeviceId, &PresentedToken) -> AuthDecision,
    E: FnOnce(EnrollmentRequest) -> EnrollmentAnswer,
{
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut ricevuto = read_frame(stream, HANDSHAKE_MAX_FRAME_BYTES, deadline)?;
    let letto = serde_json::from_slice::<ClientFrame>(&ricevuto);
    // Il frame contiene il gettone, o il codice, in chiaro: si azzera appena
    // letto.
    ricevuto.fill(0);

    let (protocol, versions, capabilities, device, mut token) = match letto {
        Ok(ClientFrame::Hello {
            protocol,
            versions,
            capabilities,
            device,
            token,
        }) => (protocol, versions, capabilities, device, token),
        Ok(ClientFrame::Enroll {
            protocol,
            versions,
            device,
            label,
            mut code,
            salt,
            verifier,
        }) => {
            let Some(enroll) = enroll else {
                azzera(&mut code);
                return refuse(stream, offer, RefusalReason::Malformed);
            };
            let richiesta = richiesta_dal_filo(&device, &label, &code, &salt, &verifier);
            azzera(&mut code);
            let Some(richiesta) = richiesta else {
                return refuse(stream, offer, RefusalReason::Malformed);
            };
            if protocol != PROTOCOL_NAME {
                return refuse(stream, offer, RefusalReason::Malformed);
            }
            if highest_common(versions, offer.versions).is_none() {
                return refuse(stream, offer, RefusalReason::UnsupportedVersion);
            }
            let risposta = match enroll(richiesta) {
                EnrollmentAnswer::Admitted {
                    hub,
                    enrolled_at_ms,
                } => HubFrame::Enrolled {
                    hub,
                    enrolled_at: enrolled_at_ms,
                },
                EnrollmentAnswer::Refused {
                    reason,
                    retry_in_minutes,
                } => HubFrame::EnrollmentRefused {
                    reason,
                    retry_in_minutes,
                },
            };
            let serializzato =
                serde_json::to_vec(&risposta).map_err(|_| HandshakeError::InvalidOffer)?;
            write_frame(stream, &serializzato, HANDSHAKE_MAX_FRAME_BYTES)?;
            return Ok(HubOpening::Enrollment);
        }
        Err(_) => return refuse(stream, offer, RefusalReason::Malformed),
    };

    let presentato = from_hex_32(&token).map(PresentedToken);
    azzera(&mut token);
    let dispositivo = DeviceId::parse(&device);
    let (Some(presentato), Ok(dispositivo)) = (presentato, dispositivo) else {
        return refuse(stream, offer, RefusalReason::Malformed);
    };
    if protocol != PROTOCOL_NAME || !is_valid_capability_list(&capabilities) {
        return refuse(stream, offer, RefusalReason::Malformed);
    }

    let Some(versione) = highest_common(versions, offer.versions) else {
        return refuse(stream, offer, RefusalReason::UnsupportedVersion);
    };

    match authenticate(&dispositivo, &presentato) {
        AuthDecision::Accepted => {}
        AuthDecision::NotRecognized => {
            return refuse(stream, offer, RefusalReason::NotRecognized);
        }
        AuthDecision::Revoked => return refuse(stream, offer, RefusalReason::DeviceRevoked),
    }
    drop(presentato);

    let known: Vec<&str> = offer.capabilities.iter().map(String::as_str).collect();
    let accettate = accept_capabilities(&capabilities, &known);
    let welcome = HubFrame::Welcome {
        version: versione,
        capabilities: accettate.clone(),
        hub_versions: offer.versions,
    };
    let serializzato = serde_json::to_vec(&welcome).map_err(|_| HandshakeError::InvalidOffer)?;
    write_frame(stream, &serializzato, HANDSHAKE_MAX_FRAME_BYTES)?;

    Ok(HubOpening::Session(AcceptedDevice {
        device: dispositivo,
        negotiated: Negotiated {
            version: versione,
            capabilities: accettate,
        },
    }))
}

/// Riporta ai tipi del dominio una richiesta di arruolamento arrivata dal filo.
///
/// Ciò che arriva dalla rete **riattraversa i tipi validati** (ADR-0091
/// decisione 4): un campo che non li attraversa rende malformata la richiesta,
/// e la richiesta non arriva a chi ammette — quindi non conta come tentativo.
fn richiesta_dal_filo(
    device: &str,
    label: &str,
    code: &str,
    salt: &str,
    verifier: &str,
) -> Option<EnrollmentRequest> {
    let verifier = Sha256Digest::from_hex(verifier).ok()?;
    Some(EnrollmentRequest {
        device_id: DeviceId::parse(device).ok()?,
        label: DisplayName::try_new(label).ok()?,
        code: EnrollmentCode::parse(code).ok()?,
        salt: EnrollmentSalt::parse(salt).ok()?,
        verifier,
    })
}

/// Manda il rifiuto, e restituisce l'errore corrispondente.
fn refuse<S: TimedStream + ?Sized, T>(
    stream: &mut S,
    offer: &HubOffer,
    reason: RefusalReason,
) -> Result<T, HandshakeError> {
    let rifiuto = HubFrame::Refused {
        reason,
        hub_versions: offer.versions,
    };
    // Best-effort: chi ha mandato un frame malformato può non leggere più.
    if let Ok(serializzato) = serde_json::to_vec(&rifiuto) {
        let _ = write_frame(stream, &serializzato, HANDSHAKE_MAX_FRAME_BYTES);
    }
    Err(HandshakeError::Refused {
        reason,
        hub_versions: offer.versions,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    const CIFRE: &[u8; 16] = b"0123456789abcdef";
    let mut testo = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        testo.push(char::from(CIFRE[usize::from(byte >> 4)]));
        testo.push(char::from(CIFRE[usize::from(byte & 0x0F)]));
    }
    testo
}

fn from_hex_32(testo: &str) -> Option<[u8; 32]> {
    let testo = testo.as_bytes();
    if testo.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (indice, coppia) in testo.chunks_exact(2).enumerate() {
        let alto = valore_esadecimale(coppia[0])?;
        let basso = valore_esadecimale(coppia[1])?;
        bytes[indice] = (alto << 4) | basso;
    }
    Some(bytes)
}

const fn valore_esadecimale(carattere: u8) -> Option<u8> {
    match carattere {
        b'0'..=b'9' => Some(carattere - b'0'),
        b'a'..=b'f' => Some(carattere - b'a' + 10),
        _ => None,
    }
}

/// Sovrascrive i byte di una stringa di sole cifre ASCII.
fn azzera(testo: &mut String) {
    let mut bytes = core::mem::take(testo).into_bytes();
    bytes.fill(0);
    let _ = core::hint::black_box(&bytes);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use lisi_core::model::enrollment::{
        DeviceToken, EnrollmentCode, EnrollmentRequest, EnrollmentSalt,
    };
    use lisi_core::model::identity::{DeviceId, DeviceSecret};
    use lisi_core::text::DisplayName;

    use super::{
        AuthDecision, ClientOffer, EnrollmentAnswer, EnrollmentRefusalReason, HandshakeError,
        HubOffer, HubOpening, PROTOCOL_NAME, PresentedToken, RefusalReason, client_enroll,
        client_handshake, from_hex_32, hub_handshake, hub_opening, to_hex,
    };
    use crate::protocol::frame::tests::Memoria;
    use crate::protocol::frame::{FrameError, read_frame, write_frame};
    use crate::protocol::negotiation::{
        MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION, VersionRange,
    };

    fn dispositivo() -> DeviceId {
        DeviceId::from_random_bytes(&[3; 15])
    }

    fn gettone() -> DeviceToken {
        DeviceToken::derive(
            &EnrollmentSalt::from_random_bytes(&[9; 16]),
            &DeviceSecret::from_random_bytes([7; 32]),
        )
    }

    fn frame(json: &str) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(write_frame(&mut out, json.as_bytes(), 4096).is_ok());
        out
    }

    fn hello(versions: &str, capabilities: &str) -> String {
        format!(
            "{{\"type\":\"hello\",\"protocol\":\"{PROTOCOL_NAME}\",\"versions\":{versions},\
             \"capabilities\":{capabilities},\"device\":\"{}\",\"token\":\"{}\"}}",
            dispositivo().as_str(),
            to_hex(gettone().expose())
        )
    }

    /// Ciò che l'Hub ha scritto, riletto come testo.
    fn risposta(flusso: &mut Memoria) -> String {
        let mut scritto = Memoria::con(std::mem::take(&mut flusso.output));
        match read_frame(
            &mut scritto,
            4096,
            std::time::Instant::now() + Duration::from_secs(1),
        ) {
            Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
            Err(errore) => panic!("l'Hub non ha risposto con un frame: {errore:?}"),
        }
    }

    fn welcome(version: u16, caps: &str, min: u16, max: u16) -> Vec<u8> {
        frame(&format!(
            "{{\"type\":\"welcome\",\"version\":{version},\"capabilities\":{caps},\
             \"hub_versions\":{{\"min\":{min},\"max\":{max}}}}}"
        ))
    }

    // --- lato dell'Hub --------------------------------------------------

    #[test]
    fn the_hub_accepts_a_well_formed_hello_and_checks_the_token() {
        let mut flusso = Memoria::con(frame(&hello("{\"min\":1,\"max\":1}", "[]")));
        let mut chiamate = 0;
        let atteso = gettone().verifier();
        let esito = hub_handshake(&mut flusso, &HubOffer::default(), |id, presentato| {
            chiamate += 1;
            assert_eq!(id, &dispositivo());
            assert_eq!(format!("{presentato:?}"), "PresentedToken(«redatto»)");
            if presentato.verifier() == atteso {
                AuthDecision::Accepted
            } else {
                AuthDecision::NotRecognized
            }
        });
        let Ok(accettato) = esito else {
            panic!("un Hello corretto deve essere accettato: {esito:?}");
        };
        assert_eq!(chiamate, 1);
        assert_eq!(accettato.negotiated.version, 1);
        assert!(risposta(&mut flusso).contains("\"type\":\"welcome\""));
    }

    #[test]
    fn not_recognized_says_nothing_more_and_revoked_says_revoked() {
        for (decisione, motivo, testo) in [
            (
                AuthDecision::NotRecognized,
                RefusalReason::NotRecognized,
                "not_recognized",
            ),
            (
                AuthDecision::Revoked,
                RefusalReason::DeviceRevoked,
                "device_revoked",
            ),
        ] {
            let mut flusso = Memoria::con(frame(&hello("{\"min\":1,\"max\":1}", "[]")));
            let esito = hub_handshake(&mut flusso, &HubOffer::default(), |_, _| decisione);
            assert!(
                matches!(esito, Err(HandshakeError::Refused { reason, .. }) if reason == motivo)
            );
            let scritto = risposta(&mut flusso);
            assert_eq!(
                scritto,
                format!(
                    "{{\"type\":\"refused\",\"reason\":\"{testo}\",\"hub_versions\":{{\"min\":{},\"max\":{}}}}}",
                    MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION
                ),
                "il rifiuto non deve portare altro"
            );
        }
    }

    #[test]
    fn without_a_common_version_nobody_is_asked_for_the_token() {
        // Un intervallo che comincia sopra la versione piu' alta che questo
        // programma parla: nessuna versione in comune, qualunque sia il tetto.
        let fuori = MAX_SUPPORTED_VERSION + 1;
        let mut flusso = Memoria::con(frame(&hello(
            &format!("{{\"min\":{fuori},\"max\":{}}}", fuori + 5),
            "[]",
        )));
        let esito = hub_handshake(&mut flusso, &HubOffer::default(), |_, _| {
            panic!("l'autenticazione non deve essere chiamata senza una versione in comune")
        });
        assert!(matches!(
            esito,
            Err(HandshakeError::Refused {
                reason: RefusalReason::UnsupportedVersion,
                hub_versions: VersionRange {
                    min: MIN_SUPPORTED_VERSION,
                    max: MAX_SUPPORTED_VERSION
                }
            })
        ));
        assert!(risposta(&mut flusso).contains("unsupported_version"));
    }

    #[test]
    fn malformed_hellos_are_refused_before_authentication() {
        let token = to_hex(gettone().expose());
        let device = dispositivo();
        let device = device.as_str();
        let casi = [
            String::from("non json"),
            String::from("{\"type\":\"welcome\"}"),
            // campo in più: l'handshake è rigido
            hello("{\"min\":1,\"max\":1}", "[]").replacen('{', "{\"extra\":1,", 1),
            // protocollo diverso
            hello("{\"min\":1,\"max\":1}", "[]").replace(PROTOCOL_NAME, "altro"),
            // gettone corto, maiuscolo, non esadecimale
            hello("{\"min\":1,\"max\":1}", "[]").replace(&token, "abcd"),
            hello("{\"min\":1,\"max\":1}", "[]").replace(&token, &token.to_uppercase()),
            hello("{\"min\":1,\"max\":1}", "[]").replace(&token, &"zz".repeat(32)),
            // dispositivo non valido
            hello("{\"min\":1,\"max\":1}", "[]").replace(device, "UUUU"),
            // capacità non ammesse
            hello("{\"min\":1,\"max\":1}", "[\"Con Spazio\"]"),
            hello("{\"min\":1,\"max\":1}", "[\"a\",\"a\"]"),
        ];
        for caso in casi {
            let mut flusso = Memoria::con(frame(&caso));
            let esito = hub_handshake(&mut flusso, &HubOffer::default(), |_, _| {
                panic!("un Hello malformato non arriva all'autenticazione: {caso}")
            });
            assert!(
                matches!(
                    esito,
                    Err(HandshakeError::Refused {
                        reason: RefusalReason::Malformed,
                        ..
                    })
                ),
                "{caso}: {esito:?}"
            );
        }
    }

    #[test]
    fn an_oversized_first_frame_is_dropped_without_a_reply() {
        let mut flusso = Memoria::con(8192_u32.to_be_bytes().to_vec());
        let esito = hub_handshake(&mut flusso, &HubOffer::default(), |_, _| {
            panic!("nessuna autenticazione")
        });
        assert_eq!(esito, Err(HandshakeError::Frame(FrameError::TooLarge)));
        assert!(flusso.output.is_empty());
    }

    #[test]
    fn unknown_capabilities_are_ignored_by_the_hub() {
        let mut flusso = Memoria::con(frame(&hello(
            "{\"min\":1,\"max\":1}",
            "[\"futura\",\"nota\"]",
        )));
        let offerta = HubOffer {
            capabilities: vec![String::from("nota")],
            ..HubOffer::default()
        };
        let Ok(accettato) = hub_handshake(&mut flusso, &offerta, |_, _| AuthDecision::Accepted)
        else {
            panic!("le capacità sconosciute non devono far rifiutare");
        };
        assert_eq!(
            accettato.negotiated.capabilities,
            vec![String::from("nota")]
        );
    }

    // --- lato della postazione ------------------------------------------

    fn client(
        risposta: Vec<u8>,
        offerta: &ClientOffer,
    ) -> (Result<super::Negotiated, HandshakeError>, Vec<u8>) {
        let mut flusso = Memoria::con(risposta);
        let esito = client_handshake(&mut flusso, &dispositivo(), &gettone(), offerta);
        (esito, flusso.output)
    }

    #[test]
    fn the_client_sends_one_hello_with_the_token_and_accepts_the_highest_common_version() {
        let offerta = ClientOffer {
            versions: VersionRange { min: 1, max: 3 },
            ..ClientOffer::default()
        };
        let (esito, scritto) = client(welcome(2, "[]", 1, 2), &offerta);
        assert_eq!(esito.map(|n| n.version), Ok(2));

        let mut uscito = Memoria::con(scritto);
        let Ok(hello) = read_frame(
            &mut uscito,
            4096,
            std::time::Instant::now() + Duration::from_secs(1),
        ) else {
            panic!("il client deve aver mandato un frame");
        };
        let hello = String::from_utf8(hello).unwrap_or_default();
        assert!(hello.contains(&to_hex(gettone().expose())));
        assert_eq!(
            uscito.posizione,
            uscito.input.len(),
            "un solo frame: il gettone viaggia una volta"
        );
    }

    #[test]
    fn a_hub_that_picks_a_lower_version_than_both_speak_is_a_downgrade() {
        let offerta = ClientOffer {
            versions: VersionRange { min: 1, max: 3 },
            ..ClientOffer::default()
        };
        // L'Hub dichiara di parlare fino alla 3, e sceglie la 1.
        let (esito, _) = client(welcome(1, "[]", 1, 3), &offerta);
        assert_eq!(esito, Err(HandshakeError::Downgrade));
        // Una versione mai offerta è anch'essa rifiutata.
        let (esito, _) = client(welcome(4, "[]", 1, 4), &offerta);
        assert_eq!(esito, Err(HandshakeError::Downgrade));
    }

    #[test]
    fn a_welcome_with_capabilities_never_offered_is_a_violation() {
        let (esito, _) = client(
            welcome(1, "[\"mai-offerta\"]", 1, 1),
            &ClientOffer::default(),
        );
        assert_eq!(esito, Err(HandshakeError::ProtocolViolation));
        let (esito, _) = client(welcome(1, "[]", 3, 2), &ClientOffer::default());
        assert_eq!(esito, Err(HandshakeError::ProtocolViolation));
    }

    #[test]
    fn a_required_capability_that_the_hub_does_not_accept_stops_the_client() {
        let offerta = ClientOffer {
            capabilities: vec![String::from("eventi")],
            required: vec![String::from("eventi")],
            ..ClientOffer::default()
        };
        let (esito, _) = client(welcome(1, "[]", 1, 1), &offerta);
        assert_eq!(esito, Err(HandshakeError::MissingCapability));
    }

    #[test]
    fn a_refusal_carries_the_hub_versions_for_the_operator() {
        let rifiuto = frame(
            "{\"type\":\"refused\",\"reason\":\"unsupported_version\",\"hub_versions\":{\"min\":2,\"max\":2}}",
        );
        let (esito, _) = client(rifiuto, &ClientOffer::default());
        assert_eq!(
            esito,
            Err(HandshakeError::Refused {
                reason: RefusalReason::UnsupportedVersion,
                hub_versions: VersionRange { min: 2, max: 2 }
            })
        );
        let (esito, _) = client(
            frame("{\"type\":\"welcome\",\"version\":1}"),
            &ClientOffer::default(),
        );
        assert_eq!(esito, Err(HandshakeError::Malformed));
    }

    #[test]
    fn the_default_offer_is_everything_the_program_speaks() {
        let offerta = ClientOffer::default();
        assert_eq!(offerta.versions, VersionRange::SUPPORTED);
        assert!(offerta.required.is_empty());
    }

    #[test]
    fn hex_round_trips_and_errors_never_carry_the_token() {
        let bytes = [0xAB_u8; 32];
        assert_eq!(from_hex_32(&to_hex(&bytes)), Some(bytes));
        assert_eq!(from_hex_32("ab"), None);
        let errore = format!("{:?}", HandshakeError::Malformed);
        assert!(!errore.contains(&to_hex(gettone().expose())));
    }

    // --- l'arruolamento (ADR-0132) -----------------------------------------

    fn codice() -> EnrollmentCode {
        EnrollmentCode::from_random_bytes(&[5; 10])
    }

    fn richiesta() -> EnrollmentRequest {
        let Ok(nome) = DisplayName::try_new("Postazione 3") else {
            panic!("nome di prova");
        };
        EnrollmentRequest {
            device_id: dispositivo(),
            label: nome,
            code: codice(),
            salt: EnrollmentSalt::from_random_bytes(&[9; 16]),
            verifier: gettone().verifier(),
        }
    }

    fn enroll(codice: &str) -> String {
        format!(
            "{{\"type\":\"enroll\",\"protocol\":\"{PROTOCOL_NAME}\",\"versions\":{{\"min\":1,\
             \"max\":2}},\"device\":\"{}\",\"label\":\"Postazione 3\",\"code\":\"{codice}\",\
             \"salt\":\"{}\",\"verifier\":\"{}\"}}",
            dispositivo().as_str(),
            EnrollmentSalt::from_random_bytes(&[9; 16]).as_str(),
            gettone().verifier().as_str()
        )
    }

    fn nessuna_sessione(_: &DeviceId, _: &PresentedToken) -> AuthDecision {
        panic!("una richiesta di arruolamento non autentica nessun gettone");
    }

    #[test]
    fn the_hub_hands_a_well_formed_request_to_whoever_admits_and_answers_once() {
        let mut flusso = Memoria::con(frame(&enroll(codice().reveal_to_administrator())));
        let mut ricevuta = None;
        let esito = hub_opening(
            &mut flusso,
            &HubOffer::default(),
            nessuna_sessione,
            |richiesta| {
                ricevuta = Some(richiesta);
                EnrollmentAnswer::Admitted {
                    hub: String::from("Hub della centrale"),
                    enrolled_at_ms: 42,
                }
            },
        );
        assert!(matches!(esito, Ok(HubOpening::Enrollment)), "{esito:?}");
        let Some(ricevuta) = ricevuta else {
            panic!("chi ammette deve aver ricevuto la richiesta");
        };
        assert_eq!(ricevuta, richiesta());
        let detto = risposta(&mut flusso);
        assert!(detto.contains("\"type\":\"enrolled\""), "{detto}");
        assert!(detto.contains("Hub della centrale"));
        // La risposta non ripete il codice.
        assert!(!detto.contains(codice().reveal_to_administrator()));
    }

    #[test]
    fn a_malformed_code_never_reaches_whoever_admits() {
        let mut flusso = Memoria::con(frame(&enroll("NON-E-UN-CODICE")));
        let mut chiamate = 0;
        let esito = hub_opening(&mut flusso, &HubOffer::default(), nessuna_sessione, |_| {
            chiamate += 1;
            EnrollmentAnswer::Refused {
                reason: EnrollmentRefusalReason::CodeNotRecognised,
                retry_in_minutes: None,
            }
        });
        assert_eq!(chiamate, 0, "un codice malformato non e' un tentativo");
        assert!(matches!(
            esito,
            Err(HandshakeError::Refused {
                reason: RefusalReason::Malformed,
                ..
            })
        ));
    }

    /// Il banco dei guasti e ogni Hub che non arruola: la richiesta si
    /// rifiuta come un frame che non si sa leggere, ed è ciò che riceve una
    /// postazione da un Hub della generazione precedente.
    #[test]
    fn an_hub_that_does_not_enroll_refuses_the_request_as_malformed() {
        let mut flusso = Memoria::con(frame(&enroll(codice().reveal_to_administrator())));
        let esito = hub_handshake(&mut flusso, &HubOffer::default(), nessuna_sessione);
        assert!(matches!(
            esito,
            Err(HandshakeError::Refused {
                reason: RefusalReason::Malformed,
                ..
            })
        ));
    }

    #[test]
    fn the_hub_refuses_an_enrollment_without_a_common_version() {
        let json = enroll(codice().reveal_to_administrator())
            .replace("{\"min\":1,\"max\":2}", "{\"min\":9,\"max\":9}");
        let mut flusso = Memoria::con(frame(&json));
        let esito = hub_opening(&mut flusso, &HubOffer::default(), nessuna_sessione, |_| {
            panic!("senza una versione in comune non si ammette")
        });
        assert!(matches!(
            esito,
            Err(HandshakeError::Refused {
                reason: RefusalReason::UnsupportedVersion,
                ..
            })
        ));
    }

    #[test]
    fn the_station_sends_the_request_and_reads_both_answers() {
        let mut flusso = Memoria::con(frame(
            "{\"type\":\"enrolled\",\"hub\":\"Hub della centrale\",\"enrolled_at\":7}",
        ));
        let esito = client_enroll(&mut flusso, &richiesta(), VersionRange::SUPPORTED);
        assert_eq!(
            esito,
            Ok(EnrollmentAnswer::Admitted {
                hub: String::from("Hub della centrale"),
                enrolled_at_ms: 7
            })
        );
        let mandato = risposta(&mut flusso);
        assert!(mandato.contains("\"type\":\"enroll\""));
        // Il gettone non viaggia: viaggia la sua impronta.
        assert!(!mandato.contains(&to_hex(gettone().expose())));

        let mut flusso = Memoria::con(frame(
            "{\"type\":\"enrollment_refused\",\"reason\":\"too_many_recent_failures\",\
             \"retry_in_minutes\":4}",
        ));
        let esito = client_enroll(&mut flusso, &richiesta(), VersionRange::SUPPORTED);
        assert_eq!(
            esito,
            Ok(EnrollmentAnswer::Refused {
                reason: EnrollmentRefusalReason::TooManyRecentFailures,
                retry_in_minutes: Some(4)
            })
        );
    }

    #[test]
    fn a_welcome_is_not_the_answer_to_an_enrollment_nor_an_enrollment_to_a_hello() {
        let mut flusso = Memoria::con(welcome(2, "[]", 1, 2));
        let esito = client_enroll(&mut flusso, &richiesta(), VersionRange::SUPPORTED);
        assert_eq!(esito, Err(HandshakeError::ProtocolViolation));

        let mut flusso = Memoria::con(frame(
            "{\"type\":\"enrolled\",\"hub\":\"Hub\",\"enrolled_at\":7}",
        ));
        let esito = client_handshake(
            &mut flusso,
            &dispositivo(),
            &gettone(),
            &ClientOffer::default(),
        );
        assert_eq!(esito, Err(HandshakeError::ProtocolViolation));
    }
}

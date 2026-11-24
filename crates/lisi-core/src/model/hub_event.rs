//! La sequenza autorevole degli eventi dell'Hub (HUB-EVENT-01, ADR-0086).
//!
//! # Che cosa è un numero di sequenza
//!
//! ADR-0042 decisione 7: ogni evento ha un numero progressivo, e un client che
//! torna dice l'ultimo numero visto e riceve ciò che manca. Perché quella frase
//! sia vera servono tre proprietà, e nessuna è gratuita:
//!
//! 1. **Il numero lo assegna l'Hub**, dentro la stessa transazione che scrive
//!    l'evento. Nessun client lo propone, nessun orologio lo decide.
//! 2. **Non ci sono salti.** Il numero è «il più alto finora, più uno», e una
//!    transazione annullata non ne consuma nessuno. Serve perché un client che
//!    riceve il numero 41 dopo il 39 possa dire **con certezza** che qualcosa è
//!    andato perso: con i salti, «manca» e «non è mai esistito» sarebbero la
//!    stessa cosa.
//! 3. **L'ordine è il numero, mai l'ora.** L'istante è un fatto da mostrare;
//!    l'orologio di una macchina si sposta, e un ordinamento per ora
//!    riordinerebbe la storia a posteriori.
//!
//! # Perché il flusso ha un nome
//!
//! Un Hub reinstallato riparte dal numero uno. Un client che aveva visto il 500
//! chiederebbe «dopo il 500», riceverebbe **niente**, e leggerebbe quel niente
//! come «non è successo nulla» — che è il modo peggiore di sbagliare, perché
//! sembra normale.
//!
//! Per questo la sequenza porta un **identificativo di flusso**, casuale, nato
//! con l'archivio dell'Hub: [`HubEventStreamId`]. Un client che torna presenta
//! *anche* quello, e se non coincide il verdetto non è «nulla di nuovo», è
//! **«questa non è la storia che stavi seguendo»**.
//!
//! # Che cosa un evento non contiene
//!
//! **Nessun contenuto monitorato**: non testi di messaggi, non allegati, non
//! corpi. Un evento dice che qualcosa è successo e su che cosa; ciò che i client
//! vedranno del materiale acquisito è di TEAM-LIVE-01, con le sue decisioni.
//! Nessun segreto: mai gettoni, mai impronte di gettoni.

use crate::error::{DomainError, DomainResult};
use crate::text::{HubEventDetail, HubEventSubject};
use crate::time::Timestamp;

/// Byte dell'identificativo di flusso: 128 bit.
pub const HUB_STREAM_ID_BYTES: usize = 16;

/// Quanti eventi una sola lettura può restituire.
///
/// Scelto da noi, non misurato: un recupero lungo si fa a pezzi, e un pezzo
/// deve stare comodamente dentro un frame del protocollo (ADR-0084).
pub const MAX_EVENTS_PER_READ: usize = 500;

/// Che cosa è successo.
///
/// **Elenco chiuso.** Un evento nuovo si aggiunge qui, e la sua forma è una
/// decisione: un registro che accettasse qualunque etichetta diventerebbe un
/// archivio di stringhe che nessuno sa interpretare.
///
/// Oggi ci sono i fatti che l'Hub sa già produrre — l'ingresso, il ritiro e il
/// cambio di ruolo di un dispositivo. Gli eventi del lavoro condiviso
/// arriveranno con le milestone che li generano.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEventKind {
    /// Un dispositivo è stato ammesso.
    DeviceEnrolled,
    /// Un dispositivo è stato ritirato.
    DeviceRevoked,
    /// Il ruolo di un dispositivo è cambiato.
    DeviceRoleChanged,
    /// Una revisione condivisa è stata registrata (TEAM-REVIEW-01, ADR-0094).
    ///
    /// Porta **quale contenuto** e **quale stato**, mai il testo: chi sta per
    /// aprire lo stesso elemento vede che qualcuno lo ha già deciso.
    ReviewRecorded,
    /// Un monitoraggio è stato avviato sull'Hub (TEAM-LIVE-01, ADR-0093).
    MonitoringStarted,
    /// Un monitoraggio dell'Hub si è concluso.
    MonitoringStopped,
    /// L'Hub ha acquisito contenuti da una fonte, in una tornata.
    ///
    /// Porta **quanti**, mai che cosa: il testo di un messaggio non entra in un
    /// evento, perché un flusso che lo portasse sarebbe la copia dell'archivio
    /// dell'Hub costruita un pezzo alla volta (freeze §7.10, ADR-0093).
    ContentAcquired,
    /// Un avviso è scattato sull'Hub.
    ///
    /// Porta il livello e il nome della regola, che vengono dai dizionari
    /// **dell'ufficio** e non dalla rete.
    AlertRaised,
    /// Un contenuto è passato a qualcuno, o è tornato di nessuno
    /// (TEAM-ASSIGN-01, ADR-0098, decisione 5).
    ///
    /// Porta **quale contenuto** e **a chi**, mai il testo: chi sta per
    /// prendere in carico lo stesso contenuto vede che qualcun altro lo ha già
    /// fatto.
    WorkAssigned,
}

impl HubEventKind {
    /// Tutti i tipi, per le prove e per i controlli di completezza.
    pub const ALL: [Self; 9] = [
        Self::DeviceEnrolled,
        Self::DeviceRevoked,
        Self::DeviceRoleChanged,
        Self::ReviewRecorded,
        Self::MonitoringStarted,
        Self::MonitoringStopped,
        Self::ContentAcquired,
        Self::AlertRaised,
        Self::WorkAssigned,
    ];

    /// Forma conservata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceEnrolled => "dispositivo_ammesso",
            Self::DeviceRevoked => "dispositivo_ritirato",
            Self::DeviceRoleChanged => "ruolo_dispositivo_cambiato",
            Self::ReviewRecorded => "revisione_registrata",
            Self::MonitoringStarted => "monitoraggio_avviato",
            Self::MonitoringStopped => "monitoraggio_arrestato",
            Self::ContentAcquired => "contenuti_acquisiti",
            Self::AlertRaised => "avviso_scattato",
            Self::WorkAssigned => "lavoro_assegnato",
        }
    }

    /// Se il tipo appartiene al **live condiviso** (TEAM-LIVE-01, ADR-0093).
    ///
    /// Serve a chi mostra: la schermata del live non elenca l'andirivieni dei
    /// dispositivi, che riguarda chi amministra.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(
            self,
            Self::MonitoringStarted
                | Self::MonitoringStopped
                | Self::ContentAcquired
                | Self::AlertRaised
                | Self::ReviewRecorded
                | Self::WorkAssigned
        )
    }

    /// Riconosce la forma conservata.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidHubEvent`] se il testo non è un tipo conosciuto.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == raw)
            .ok_or(DomainError::InvalidHubEvent {
                reason: "non è un tipo di evento conosciuto",
            })
    }
}

/// L'identificativo del flusso di eventi di un Hub.
///
/// Non è un segreto: si mostra, si conserva sul client insieme all'ultimo
/// numero visto, e serve a riconoscere che la storia è la stessa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubEventStreamId([u8; HUB_STREAM_ID_BYTES]);

impl HubEventStreamId {
    /// Costruisce l'identificativo dai byte casuali forniti.
    ///
    /// Il caso viene dal generatore del sistema, come per ogni altro valore
    /// casuale del prodotto: `lisi-core` non ne possiede uno.
    #[must_use]
    pub const fn from_random_bytes(bytes: [u8; HUB_STREAM_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// La forma esadecimale conservata e trasmessa.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut testo = String::with_capacity(HUB_STREAM_ID_BYTES * 2);
        for byte in self.0 {
            testo.push(cifra(byte >> 4));
            testo.push(cifra(byte & 0x0F));
        }
        testo
    }

    /// Riconosce la forma esadecimale.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidHubEvent`] se non sono trentadue cifre
    /// esadecimali minuscole.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        let raw = raw.as_bytes();
        if raw.len() != HUB_STREAM_ID_BYTES * 2 {
            return Err(DomainError::InvalidHubEvent {
                reason: "l'identificativo del flusso non ha trentadue cifre",
            });
        }
        let mut bytes = [0_u8; HUB_STREAM_ID_BYTES];
        for (indice, coppia) in raw.chunks_exact(2).enumerate() {
            let (Some(alto), Some(basso)) = (valore(coppia[0]), valore(coppia[1])) else {
                return Err(DomainError::InvalidHubEvent {
                    reason: "l'identificativo del flusso contiene caratteri non ammessi",
                });
            };
            bytes[indice] = (alto << 4) | basso;
        }
        Ok(Self(bytes))
    }
}

const fn cifra(valore: u8) -> char {
    match valore {
        0..=9 => (b'0' + valore) as char,
        _ => (b'a' + valore - 10) as char,
    }
}

const fn valore(carattere: u8) -> Option<u8> {
    match carattere {
        b'0'..=b'9' => Some(carattere - b'0'),
        b'a'..=b'f' => Some(carattere - b'a' + 10),
        _ => None,
    }
}

/// Un evento da scrivere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewHubEvent {
    /// Che cosa è successo.
    pub kind: HubEventKind,
    /// Di che cosa parla: l'identificativo del dispositivo, o l'entità
    /// interessata.
    pub subject: HubEventSubject,
    /// Un dettaglio corto, senza segreti e senza contenuto monitorato.
    pub detail: Option<HubEventDetail>,
}

/// Un evento conservato, con il numero che l'Hub gli ha dato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubEvent {
    /// Il numero progressivo, senza salti.
    pub sequence: u64,
    /// Che cosa è successo.
    pub kind: HubEventKind,
    /// Di che cosa parla.
    pub subject: HubEventSubject,
    /// Il dettaglio, se c'è.
    pub detail: Option<HubEventDetail>,
    /// Quando l'Hub lo ha scritto. **Si mostra, non si ordina.**
    pub recorded_at: Timestamp,
}

/// Ciò che un client dichiara tornando: quale storia stava seguendo, e fin dove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventCursor {
    /// Il flusso che il client crede di seguire.
    pub stream: HubEventStreamId,
    /// L'ultimo numero che il client dice di aver accettato.
    pub last_sequence: u64,
}

/// Che cosa fare di ciò che un client dichiara.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeVerdict {
    /// Si riprende da qui: il client riceverà gli eventi **dopo** questo numero.
    Resume {
        /// L'ultimo numero che il client ha già.
        after: u64,
    },
    /// Il client seguiva un'altra storia: un Hub reinstallato, un archivio
    /// ripristinato, o un altro Hub. **Non è «nulla di nuovo».**
    StreamChanged,
    /// Il client dichiara un numero che questo Hub non ha mai emesso.
    AheadOfHub,
}

/// Decide come riprendere.
///
/// `latest` è l'ultimo numero emesso dall'Hub; zero se non è mai successo nulla.
#[must_use]
pub const fn resume_from(
    cursor: EventCursor,
    stream: HubEventStreamId,
    latest: u64,
) -> ResumeVerdict {
    // Il confronto del flusso viene PRIMA di ogni altro: un numero letto nella
    // storia sbagliata non significa niente.
    if !uguali(&cursor.stream.0, &stream.0) {
        return ResumeVerdict::StreamChanged;
    }
    if cursor.last_sequence > latest {
        return ResumeVerdict::AheadOfHub;
    }
    ResumeVerdict::Resume {
        after: cursor.last_sequence,
    }
}

const fn uguali(primo: &[u8; HUB_STREAM_ID_BYTES], secondo: &[u8; HUB_STREAM_ID_BYTES]) -> bool {
    let mut indice = 0;
    let mut differenze = 0_u8;
    while indice < HUB_STREAM_ID_BYTES {
        differenze |= primo[indice] ^ secondo[indice];
        indice += 1;
    }
    differenze == 0
}

#[cfg(test)]
mod tests {
    use super::{
        EventCursor, HUB_STREAM_ID_BYTES, HubEventKind, HubEventStreamId, ResumeVerdict,
        resume_from,
    };

    fn flusso(seme: u8) -> HubEventStreamId {
        HubEventStreamId::from_random_bytes([seme; HUB_STREAM_ID_BYTES])
    }

    #[test]
    fn every_kind_round_trips_and_unknown_text_is_refused() {
        for kind in HubEventKind::ALL {
            assert_eq!(HubEventKind::parse(kind.as_str()), Ok(kind));
        }
        assert!(HubEventKind::parse("qualcosa_di_nuovo").is_err());
        assert!(HubEventKind::parse("").is_err());
    }

    #[test]
    fn the_stream_id_round_trips_and_refuses_malformed_text() {
        let originale = flusso(0xAB);
        assert_eq!(originale.to_hex().len(), 32);
        assert_eq!(HubEventStreamId::parse(&originale.to_hex()), Ok(originale));
        assert!(HubEventStreamId::parse("abcd").is_err());
        assert!(HubEventStreamId::parse(&"z".repeat(32)).is_err());
        assert!(
            HubEventStreamId::parse(&originale.to_hex().to_uppercase()).is_err(),
            "la forma conservata è una sola"
        );
    }

    #[test]
    fn a_client_of_the_same_stream_resumes_where_it_left() {
        let stream = flusso(1);
        assert_eq!(
            resume_from(
                EventCursor {
                    stream,
                    last_sequence: 39
                },
                stream,
                41
            ),
            ResumeVerdict::Resume { after: 39 }
        );
        // Chi è già allineato riprende da dove sta, e riceverà il prossimo.
        assert_eq!(
            resume_from(
                EventCursor {
                    stream,
                    last_sequence: 41
                },
                stream,
                41
            ),
            ResumeVerdict::Resume { after: 41 }
        );
        // Un client nuovo, che non ha mai visto niente.
        assert_eq!(
            resume_from(
                EventCursor {
                    stream,
                    last_sequence: 0
                },
                stream,
                0
            ),
            ResumeVerdict::Resume { after: 0 }
        );
    }

    #[test]
    fn a_reinstalled_hub_is_not_silence() {
        // Il caso che il nome del flusso esiste per impedire: l'Hub riparte da
        // zero, il client aveva visto 500. Senza il flusso, «dopo il 500» non
        // restituirebbe nulla e sembrerebbe che non sia successo niente.
        let vecchio = flusso(1);
        let nuovo = flusso(2);
        assert_eq!(
            resume_from(
                EventCursor {
                    stream: vecchio,
                    last_sequence: 500
                },
                nuovo,
                3
            ),
            ResumeVerdict::StreamChanged
        );
    }

    #[test]
    fn a_number_this_hub_never_issued_is_said_as_such() {
        let stream = flusso(7);
        assert_eq!(
            resume_from(
                EventCursor {
                    stream,
                    last_sequence: 12
                },
                stream,
                11
            ),
            ResumeVerdict::AheadOfHub
        );
    }
}

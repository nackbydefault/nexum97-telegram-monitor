//! I comandi che modificano, e ciò che li rende ripetibili senza danno
//! (HUB-CMD-01, ADR-0089).
//!
//! # Le tre garanzie, e da dove vengono
//!
//! 1. **Ripeterlo non raddoppia** (ADR-0042, decisione 8). Una rete d'ufficio
//!    perde pacchetti: un client che non riceve risposta **deve** poter
//!    ripetere. L'identificativo lo decide il client, l'Hub lo ricorda, e un
//!    comando già visto **restituisce l'esito di allora** invece di rieseguire.
//! 2. **L'identificativo è unico per dispositivo**, non globalmente. Il proof of
//!    concept lo ha misurato (ADR-0044, misura 2): con identificativi scelti
//!    liberamente, due client che ne scelgono uno uguale si vedono restituire
//!    l'esito dell'altro, e il proprio comando **non viene eseguito**. La chiave
//!    è quindi la coppia *(dispositivo, identificativo)*.
//! 3. **Chi scrive su una versione superata riceve un conflitto** (ADR-0042,
//!    decisione 9) — e il conflitto dice **contro che cosa** si ha perso
//!    (ADR-0044, misura 3): il valore corrente e chi lo ha scritto. Un
//!    conflitto che dicesse soltanto «hai perso» costringerebbe a rileggere per
//!    capire.
//!
//! # Mai «vince chi scrive per ultimo»
//!
//! Dove si perderebbe una decisione investigativa, l'ultimo arrivato **non
//! vince**: si ferma e mostra la differenza. Il giudizio umano su un contenuto è
//! la cosa meno adatta a una sovrascrittura silenziosa.

use crate::error::{DomainError, DomainResult};
use crate::model::identity::DeviceId;
use crate::text::{HubEventDetail, HubEventSubject};

/// Cifre di un identificativo di comando.
///
/// Corto abbastanza da stare in un messaggio, lungo abbastanza da non
/// collidere per caso dentro **un solo dispositivo**: sono i casi di quel
/// dispositivo a doversi distinguere, non quelli del mondo.
pub const COMMAND_ID_MIN_LEN: usize = 8;

/// Il massimo, perché un identificativo non diventi un campo libero.
pub const COMMAND_ID_MAX_LEN: usize = 64;

/// La chiave con cui l'Hub riconosce un comando già visto.
///
/// **Dispositivo più identificativo**: vedere la garanzia 2 del modulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandKey {
    /// Il dispositivo autenticato che ha mandato il comando.
    pub device: DeviceId,
    /// L'identificativo scelto dal client.
    pub command_id: CommandId,
}

/// L'identificativo che il client sceglie per un comando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandId(String);

impl CommandId {
    /// Riconosce un identificativo ricevuto.
    ///
    /// Ammette lettere minuscole, cifre e trattino: è un identificativo, non un
    /// testo, e ciò che arriva dalla rete non decide la forma di una chiave.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidCommandId`] se è troppo corto, troppo lungo o
    /// contiene altro.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        if raw.len() < COMMAND_ID_MIN_LEN || raw.len() > COMMAND_ID_MAX_LEN {
            return Err(DomainError::InvalidCommandId {
                reason: "non ha una lunghezza ammessa",
            });
        }
        if !raw
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DomainError::InvalidCommandId {
                reason: "contiene caratteri che un identificativo non ha",
            });
        }
        Ok(Self(String::from(raw)))
    }

    /// La forma conservata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Com'è finito un comando.
///
/// Si conserva, perché è ciò che una ripetizione riceve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// Eseguito.
    Done {
        /// Che cosa è cambiato, in breve. Mai contenuto monitorato.
        detail: Option<HubEventDetail>,
    },
    /// Rifiutato, con la ragione che il client deve mostrare.
    Refused {
        /// Perché.
        reason: HubEventDetail,
    },
}

/// Che cosa l'Hub risponde a un comando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandVerdict {
    /// È stato eseguito adesso.
    Applied(CommandOutcome),
    /// Era già stato visto: **questo è l'esito di allora**, e non si è
    /// rieseguito nulla.
    Replay(CommandOutcome),
    /// Scriveva su una versione superata.
    Conflict(Conflict),
}

/// Contro che cosa si ha perso.
///
/// Non basta «hai perso»: chi lo riceve deve poter parlare con chi ha scritto,
/// e per farlo deve sapere **che cosa** c'è adesso e **chi** ce l'ha messo
/// (ADR-0044, misura 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// La versione che l'entità ha adesso.
    pub current_version: u64,
    /// La versione su cui il comando pretendeva di scrivere.
    pub expected_version: u64,
    /// L'entità in questione.
    pub subject: HubEventSubject,
    /// Il valore corrente, in breve: il giudizio, lo stato, la decisione.
    pub current_value: Option<HubEventDetail>,
    /// Chi lo ha scritto: il dispositivo, che è ciò che l'Hub autentica
    /// (ADR-0085). **Non una persona**, finché una persona non si autentica.
    pub written_by: Option<DeviceId>,
}

impl Conflict {
    /// La frase per l'operatore: dice che cosa c'è adesso, e non propone di
    /// sovrascriverlo.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let valore = self.current_value.as_ref().map_or_else(
            || String::from("un valore diverso"),
            |valore| format!("«{}»", valore.as_str()),
        );
        let chi = self.written_by.as_ref().map_or_else(
            || String::from("un'altra postazione"),
            |device| format!("la postazione {device}"),
        );
        format!(
            "Nel frattempo {chi} ha scritto {valore} su «{}» (versione {}, non {}). \
             La modifica non è stata applicata, e nulla è stato sovrascritto.",
            self.subject.as_str(),
            self.current_version,
            self.expected_version
        )
    }
}

/// Verifica la concorrenza ottimistica.
///
/// # Errori
///
/// Restituisce il [`Conflict`] se la versione corrente non è quella attesa.
/// **Non esiste un modo di chiedere «scrivi comunque»**: sarebbe il «vince chi
/// scrive per ultimo» che ADR-0042 decisione 9 vieta.
pub fn check_version(
    expected_version: u64,
    current_version: u64,
    subject: &HubEventSubject,
    current_value: Option<&HubEventDetail>,
    written_by: Option<&DeviceId>,
) -> Result<(), Conflict> {
    if expected_version == current_version {
        return Ok(());
    }
    Err(Conflict {
        current_version,
        expected_version,
        subject: subject.clone(),
        current_value: current_value.cloned(),
        written_by: written_by.cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        COMMAND_ID_MAX_LEN, COMMAND_ID_MIN_LEN, CommandId, CommandOutcome, CommandVerdict,
        check_version,
    };
    use crate::model::identity::{DEVICE_ID_BYTES, DeviceId};
    use crate::text::{HubEventDetail, HubEventSubject};

    fn soggetto() -> HubEventSubject {
        let Ok(valore) = HubEventSubject::try_new("revisione del contenuto 42") else {
            panic!("soggetto di prova");
        };
        valore
    }

    fn dettaglio(testo: &str) -> HubEventDetail {
        let Ok(valore) = HubEventDetail::try_new(testo) else {
            panic!("dettaglio di prova");
        };
        valore
    }

    #[test]
    fn a_command_id_is_an_identifier_not_a_free_field() {
        for buono in ["abc-12345", "0123456789", &"a".repeat(COMMAND_ID_MAX_LEN)] {
            assert!(CommandId::parse(buono).is_ok(), "{buono}");
        }
        for cattivo in [
            "",
            &"a".repeat(COMMAND_ID_MIN_LEN - 1),
            &"a".repeat(COMMAND_ID_MAX_LEN + 1),
            "ABC-12345",
            "con spazio",
            "punto.e.virgola",
        ] {
            assert!(CommandId::parse(cattivo).is_err(), "{cattivo:?}");
        }
    }

    #[test]
    fn the_same_version_writes_and_a_stale_one_conflicts() {
        assert!(check_version(7, 7, &soggetto(), None, None).is_ok());

        let Err(conflitto) = check_version(
            7,
            9,
            &soggetto(),
            Some(&dettaglio("non rilevante")),
            Some(&DeviceId::from_random_bytes(&[2; DEVICE_ID_BYTES])),
        ) else {
            panic!("una versione superata deve dare un conflitto");
        };
        assert_eq!(conflitto.current_version, 9);
        assert_eq!(conflitto.expected_version, 7);
    }

    #[test]
    fn the_conflict_says_against_what_you_lost_and_does_not_offer_to_overwrite() {
        let device = DeviceId::from_random_bytes(&[3; DEVICE_ID_BYTES]);
        let Err(conflitto) = check_version(
            1,
            2,
            &soggetto(),
            Some(&dettaglio("già rivisto: non rilevante")),
            Some(&device),
        ) else {
            panic!("conflitto");
        };
        let frase = conflitto.operator_message();
        assert!(frase.contains("già rivisto: non rilevante"));
        assert!(frase.contains(device.as_str()));
        assert!(frase.contains("nulla è stato sovrascritto"));
        let minuscolo = frase.to_lowercase();
        assert!(!minuscolo.contains("sovrascrivi"));
        assert!(!minuscolo.contains("comunque"));
    }

    #[test]
    fn a_conflict_without_details_still_says_what_it_can() {
        let Err(conflitto) = check_version(1, 4, &soggetto(), None, None) else {
            panic!("conflitto");
        };
        let frase = conflitto.operator_message();
        assert!(frase.contains("un'altra postazione"));
        assert!(frase.contains("versione 4"));
    }

    #[test]
    fn a_replay_carries_the_outcome_of_then() {
        let esito = CommandOutcome::Done {
            detail: Some(dettaglio("monitoraggio avviato")),
        };
        let ripetizione = CommandVerdict::Replay(esito.clone());
        assert_eq!(ripetizione, CommandVerdict::Replay(esito));
    }
}

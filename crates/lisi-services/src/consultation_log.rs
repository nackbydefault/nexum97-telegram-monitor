//! Il registro delle consultazioni (AUDIT-VIEW-01, ADR-0193, DEC-480).
//!
//! # Spento di fabbrica
//!
//! Lo accende l'amministratore, scegliendo per quanti giorni si conserva; lo
//! spegne, e allora le righe si tolgono tutte. Accendere, cambiare e spegnere
//! sono azioni, e stanno nell'audit; le consultazioni no (ADR-0051,
//! decisione 5).
//!
//! # Che cosa registra
//!
//! Chi ha aperto la conversazione di un contenuto o la scheda di un soggetto,
//! e quando. Nessun testo, nessun motivo; la stessa apertura ripetuta entro
//! [`SAME_OPENING_MINUTES`] minuti non fa una riga nuova.

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, Timestamp};
use lisi_storage::Database;
pub use lisi_storage::repository::consultation::StoredConsultation;

use crate::error::{ServiceError, ServiceResult};

/// Entro quanti minuti la stessa apertura non fa una riga nuova.
pub const SAME_OPENING_MINUTES: i64 = 10;
/// La conservazione più breve, in giorni.
pub const MIN_RETENTION_DAYS: u32 = 30;
/// La conservazione più lunga, in giorni.
pub const MAX_RETENTION_DAYS: u32 = 365;
/// Quante consultazioni l'amministratore legge al più.
pub const SHOWN: usize = 200;
/// L'azione d'audit della scelta.
pub const CHOICE_AUDIT_ACTION: &str = "registro_consultazioni_scelto";

const MINUTO: i64 = 60_000;
const GIORNO: i64 = 86_400_000;

/// Che cosa si è aperto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consulted {
    /// La conversazione di un contenuto.
    Content(i64),
    /// La scheda di un soggetto.
    Subject(i64),
}

impl Consulted {
    const fn kind(self) -> &'static str {
        match self {
            Self::Content(_) => "contenuto",
            Self::Subject(_) => "soggetto",
        }
    }

    const fn id(self) -> i64 {
        match self {
            Self::Content(id) | Self::Subject(id) => id,
        }
    }
}

/// Una riga del registro, come la legge l'amministratore.
#[must_use]
pub fn as_sentence(riga: &StoredConsultation) -> String {
    let che_cosa = if riga.kind == "soggetto" {
        format!("la scheda del soggetto n. {}", riga.entity_id)
    } else {
        format!("la conversazione del contenuto n. {}", riga.entity_id)
    };
    format!(
        "{}: {} ha aperto {che_cosa}.",
        riga.viewed_at.to_readable_local(),
        riga.actor
    )
}

/// Il servizio del registro.
#[derive(Debug)]
pub struct ConsultationLogService {
    database: Database,
}

impl ConsultationLogService {
    /// Il servizio, attorno all'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// La conservazione in giorni; `None` se il registro è spento.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn retention(&self) -> ServiceResult<Option<u32>> {
        Ok(self.database.consultation_retention()?)
    }

    /// Che cosa vale per chiunque, in una frase: un operatore sa quando le sue
    /// aperture si registrano (ADR-0193, decisione 6).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn status_sentence(&self) -> ServiceResult<String> {
        Ok(match self.retention()? {
            Some(giorni) => format!(
                "Il registro delle consultazioni è acceso. Si conserva per {giorni} giorni chi \
                 apre la conversazione di un contenuto o la scheda di un soggetto, e quando. Lo \
                 legge soltanto l'amministratore."
            ),
            None => String::from(
                "Il registro delle consultazioni è spento: le aperture non si registrano.",
            ),
        })
    }

    /// Accende, cambia o spegne il registro. Soltanto l'amministratore.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// [`ServiceError::ConsultationLogRefused`] per una conservazione fuori
    /// dai limiti; un errore se la scrittura non riesce.
    pub fn choose(
        &mut self,
        retention_days: Option<u32>,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<String> {
        if !mode.allows(RestrictedAction::ChooseConsultationLog) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseConsultationLog,
            });
        }
        if let Some(giorni) = retention_days
            && !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&giorni)
        {
            return Err(ServiceError::ConsultationLogRefused {
                reason: format!(
                    "la conservazione va da {MIN_RETENTION_DAYS} a {MAX_RETENTION_DAYS} giorni"
                ),
            });
        }
        let dettaglio = retention_days.map_or_else(
            || String::from("spento"),
            |giorni| format!("acceso, {giorni} giorni"),
        );
        let audit = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(CHOICE_AUDIT_ACTION)?,
            entity: AuditEntity::try_new("postazione")?,
            entity_id: None,
            actor_mode: Some(mode),
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        };
        let tolte = self
            .database
            .save_consultation_retention(retention_days, actor, &audit)?;
        let potate = self.prune(now)?;
        Ok(match retention_days {
            Some(giorni) => format!(
                "Registro delle consultazioni acceso, con una conservazione di {giorni} giorni.{}",
                if potate > 0 {
                    format!(" Tolte le righe più vecchie: {potate}.")
                } else {
                    String::new()
                }
            ),
            None => format!("Registro delle consultazioni spento. Righe tolte: {tolte}."),
        })
    }

    /// Toglie le righe più vecchie della conservazione; restituisce quante.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn prune(&self, now: Timestamp) -> ServiceResult<usize> {
        let Some(giorni) = self.retention()? else {
            return Ok(0);
        };
        let limite = now
            .as_millis()
            .saturating_sub(i64::from(giorni).saturating_mul(GIORNO));
        Ok(self
            .database
            .prune_consultations(Timestamp::from_millis(limite))?)
    }

    /// Registra un'apertura, se il registro è acceso e se la stessa non è
    /// già stata registrata da poco. Restituisce se ha scritto una riga.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o la scrittura non riescono.
    pub fn record(
        &self,
        consulted: Consulted,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<bool> {
        if self.retention()?.is_none() {
            return Ok(false);
        }
        let ultima =
            self.database
                .last_consultation_of(actor.as_str(), consulted.kind(), consulted.id())?;
        if ultima.is_some_and(|istante| {
            now.as_millis().saturating_sub(istante.as_millis()) < SAME_OPENING_MINUTES * MINUTO
        }) {
            return Ok(false);
        }
        self.database.insert_consultation(&StoredConsultation {
            actor: actor.as_str().to_owned(),
            kind: consulted.kind().to_owned(),
            entity_id: consulted.id(),
            viewed_at: now,
        })?;
        Ok(true)
    }

    /// Le consultazioni, le più recenti prima. Soltanto l'amministratore.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// un errore se la lettura non riesce.
    pub fn entries(&self, mode: OperatingMode) -> ServiceResult<Vec<StoredConsultation>> {
        if !mode.allows(RestrictedAction::ChooseConsultationLog) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseConsultationLog,
            });
        }
        Ok(self.database.consultations(SHOWN)?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, Timestamp};

    use super::{ConsultationLogService, Consulted, as_sentence};
    use crate::error::ServiceError;

    const MINUTO: i64 = 60_000;
    const GIORNO: i64 = 86_400_000;

    fn servizio() -> ConsultationLogService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        ConsultationLogService::new(database)
    }

    fn chi(nome: &str) -> Actor {
        let Ok(attore) = Actor::try_new(nome) else {
            panic!("attore valido");
        };
        attore
    }

    fn al(millis: i64) -> Timestamp {
        Timestamp::from_millis(1_762_300_000_000 + millis)
    }

    #[test]
    fn spento_non_registra_e_l_operatore_non_lo_accende_ne_lo_legge() {
        let mut servizio = servizio();
        assert_eq!(
            servizio
                .record(Consulted::Content(1), &chi("operatore.uno"), al(0))
                .ok(),
            Some(false)
        );
        assert!(matches!(
            servizio.choose(
                Some(90),
                OperatingMode::Operator,
                &chi("operatore.uno"),
                al(0)
            ),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
        assert!(matches!(
            servizio.entries(OperatingMode::Operator),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
        assert!(matches!(
            servizio.choose(Some(7), OperatingMode::Administrator, &chi("a"), al(0)),
            Err(ServiceError::ConsultationLogRefused { .. })
        ));
        assert!(
            servizio
                .status_sentence()
                .is_ok_and(|frase| frase.contains("spento"))
        );
    }

    #[test]
    fn acceso_registra_senza_doppioni_e_rispetta_la_conservazione() {
        let mut servizio = servizio();
        let Ok(_) = servizio.choose(
            Some(30),
            OperatingMode::Administrator,
            &chi("amministratore"),
            al(0),
        ) else {
            panic!("il registro si deve accendere");
        };
        let operatore = chi("operatore.uno");
        assert_eq!(
            servizio
                .record(Consulted::Content(5), &operatore, al(0))
                .ok(),
            Some(true)
        );
        // La stessa apertura entro dieci minuti non fa una riga nuova.
        assert_eq!(
            servizio
                .record(Consulted::Content(5), &operatore, al(5 * MINUTO))
                .ok(),
            Some(false)
        );
        assert_eq!(
            servizio
                .record(Consulted::Subject(5), &operatore, al(5 * MINUTO))
                .ok(),
            Some(true),
            "la scheda di un soggetto è un'altra cosa"
        );
        assert_eq!(
            servizio
                .record(Consulted::Content(5), &operatore, al(11 * MINUTO))
                .ok(),
            Some(true)
        );
        let Ok(righe) = servizio.entries(OperatingMode::Administrator) else {
            panic!("il registro si deve leggere");
        };
        assert_eq!(righe.len(), 3);
        assert!(as_sentence(&righe[1]).contains("la scheda del soggetto n. 5"));

        // Oltre la conservazione, le righe si tolgono.
        assert_eq!(servizio.prune(al(31 * GIORNO)).ok(), Some(3));
        assert!(
            servizio
                .status_sentence()
                .is_ok_and(|frase| frase.contains("30 giorni"))
        );
    }

    #[test]
    fn spegnere_toglie_tutte_le_righe() {
        let mut servizio = servizio();
        let Ok(_) = servizio.choose(
            Some(90),
            OperatingMode::Administrator,
            &chi("amministratore"),
            al(0),
        ) else {
            panic!("il registro si deve accendere");
        };
        let _ = servizio.record(Consulted::Content(1), &chi("operatore.uno"), al(0));
        let _ = servizio.record(Consulted::Content(2), &chi("operatore.due"), al(0));
        let Ok(frase) = servizio.choose(
            None,
            OperatingMode::Administrator,
            &chi("amministratore"),
            al(1),
        ) else {
            panic!("il registro si deve spegnere");
        };
        assert!(frase.contains("Righe tolte: 2"), "{frase}");
        assert_eq!(
            servizio
                .entries(OperatingMode::Administrator)
                .map(|v| v.len())
                .ok(),
            Some(0)
        );
    }
}

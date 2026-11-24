//! Sessioni di monitoraggio.
//!
//! Una sessione è l'unità di lavoro dell'operatore: ha una durata, un insieme di
//! fonti selezionate e un ciclo di vita ordinato. Le fonti selezionate fanno
//! parte della sessione fin dalla creazione, perché nessun contenuto può essere
//! collegato a una fonte che non era stata selezionata.

use crate::error::{DomainError, DomainResult};
use crate::id::{SessionId, SourceId};
use crate::text::{Actor, DisplayName};
use crate::time::Timestamp;

string_enum!(
    /// Modalità con cui è stata scelta la durata della sessione.
    SessionDurationMode {
        /// Durata scelta fra quelle predefinite.
        Preset => "preset",
        /// Durata indicata dall'operatore.
        Custom => "custom",
        /// Nessuna durata: la sessione termina su comando esplicito.
        Manual => "manual",
    }
);

string_enum!(
    /// Stato della sessione nel suo ciclo di vita.
    SessionState {
        /// Creata e non ancora avviata.
        Planned => "planned",
        /// In acquisizione.
        Running => "running",
        /// Sospesa e riprendibile.
        Paused => "paused",
        /// Terminata perché la durata pianificata è trascorsa.
        Completed => "completed",
        /// Terminata su comando dell'operatore.
        Stopped => "stopped",
    }
);

impl SessionState {
    /// Se la transizione verso `next` è ammessa.
    ///
    /// L'arresto è ordinato: da uno stato terminale non si riparte, e una
    /// sessione non può passare direttamente da pianificata a conclusa senza
    /// essere stata avviata. Il vincolo è qui e non nell'interfaccia, così che
    /// ogni percorso che modifica lo stato debba attraversarlo.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Running | Self::Stopped)
                | (
                    Self::Running,
                    Self::Paused | Self::Completed | Self::Stopped
                )
                | (
                    Self::Paused,
                    Self::Running | Self::Completed | Self::Stopped
                )
        )
    }

    /// Se lo stato è terminale.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Completed | Self::Stopped)
    }

    /// Descrizione mostrata all'operatore.
    ///
    /// Sta qui e non nell'interfaccia perché la stessa parola deve comparire
    /// nella schermata e nel rapporto esportato: la forma conservata
    /// (`planned`, `stopped`) è un identificatore, e mostrarla a chi legge un
    /// rapporto vorrebbe dire fargli tradurre il nostro schema.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Planned => "Pianificata",
            Self::Running => "In corso",
            // Era «Sospesa»: accanto a «Sospendi avvisi» si leggeva come una
            // pausa, che non esiste (OPERATOR-SIM-01, OS-05). L'acquisizione
            // continua, e l'etichetta lo dice.
            Self::Paused => "In corso, avvisi sospesi",
            Self::Completed => "Conclusa per durata trascorsa",
            Self::Stopped => "Arrestata dall'operatore",
        }
    }
}

/// Durata pianificata della sessione.
///
/// La modalità e i secondi pianificati sono conservati separatamente nel
/// database ma sono un unico valore nel dominio: una durata `Manual` con dei
/// secondi pianificati, o una `Preset` senza, sarebbero stati incoerenti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDuration {
    /// Durata predefinita, in secondi.
    Preset {
        /// Secondi pianificati, maggiori di zero.
        seconds: i64,
    },
    /// Durata indicata dall'operatore, in secondi.
    Custom {
        /// Secondi pianificati, maggiori di zero.
        seconds: i64,
    },
    /// Nessuna durata pianificata.
    Manual,
}

impl SessionDuration {
    /// Modalità corrispondente.
    #[must_use]
    pub const fn mode(self) -> SessionDurationMode {
        match self {
            Self::Preset { .. } => SessionDurationMode::Preset,
            Self::Custom { .. } => SessionDurationMode::Custom,
            Self::Manual => SessionDurationMode::Manual,
        }
    }

    /// Secondi pianificati, assenti nella modalità manuale.
    #[must_use]
    pub const fn planned_seconds(self) -> Option<i64> {
        match self {
            Self::Preset { seconds } | Self::Custom { seconds } => Some(seconds),
            Self::Manual => None,
        }
    }

    /// Ricompone la durata dalle due colonne conservate nel database.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InconsistentPlannedDuration`] se la modalità e
    /// i secondi pianificati non sono coerenti, compreso il caso di una durata
    /// nulla o negativa.
    pub fn try_from_parts(
        mode: SessionDurationMode,
        planned_seconds: Option<i64>,
    ) -> DomainResult<Self> {
        match (mode, planned_seconds) {
            (SessionDurationMode::Preset, Some(seconds)) if seconds > 0 => {
                Ok(Self::Preset { seconds })
            }
            (SessionDurationMode::Custom, Some(seconds)) if seconds > 0 => {
                Ok(Self::Custom { seconds })
            }
            (SessionDurationMode::Manual, None) => Ok(Self::Manual),
            (mode, _) => Err(DomainError::InconsistentPlannedDuration {
                mode: mode.as_str(),
            }),
        }
    }

    /// La durata a parole, la stessa nella procedura e nella scheda
    /// (ADR-0150): «1 ora», «2 ore e 15 minuti»; la personalizzata lo dice.
    #[must_use]
    pub fn in_words(self) -> String {
        match self {
            Self::Preset { seconds } => duration_in_words(seconds),
            Self::Custom { seconds } => format!("{} (personalizzata)", duration_in_words(seconds)),
            Self::Manual => String::from("Fino all'arresto manuale"),
        }
    }
}

/// La durata personalizzata più breve: un minuto (ADR-0150).
pub const CUSTOM_MIN_SECONDS: i64 = 60;

/// La durata personalizzata più lunga: sette giorni (ADR-0150). Oltre, un
/// monitoraggio non è più a tempo: è un arresto manuale che nessuno ricorda di
/// aver chiesto, e «Fino all'arresto» lo dice.
pub const CUSTOM_MAX_SECONDS: i64 = 7 * 24 * 3_600;

/// Una durata in secondi, a parole: ore e minuti, al singolare quando è uno.
///
/// I secondi residui non si dicono: le durate si scelgono in minuti, e una
/// durata non multipla del minuto viene solo dalle prove.
#[must_use]
pub fn duration_in_words(seconds: i64) -> String {
    let minuti_totali = seconds.max(0) / 60;
    let ore = minuti_totali / 60;
    let minuti = minuti_totali % 60;

    let parola = |quanti: i64, uno: &str, molti: &str| {
        if quanti == 1 {
            format!("1 {uno}")
        } else {
            format!("{quanti} {molti}")
        }
    };
    match (ore, minuti) {
        (0, minuti) => parola(minuti, "minuto", "minuti"),
        (ore, 0) => parola(ore, "ora", "ore"),
        (ore, minuti) => format!(
            "{} e {}",
            parola(ore, "ora", "ore"),
            parola(minuti, "minuto", "minuti")
        ),
    }
}

/// Sessione che si intende creare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSession {
    /// Nome leggibile della sessione.
    pub label: DisplayName,
    /// Operatore che crea la sessione.
    pub started_by: Actor,
    /// Durata pianificata.
    pub duration: SessionDuration,
    /// Fonti selezionate per la sessione.
    ///
    /// L'elenco è parte della creazione e non un passo successivo: una sessione
    /// senza fonti selezionate non potrebbe acquisire nulla, e la selezione è il
    /// presupposto del vincolo che lega i contenuti alle sole fonti scelte.
    pub source_ids: Vec<SourceId>,
}

/// Sessione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Identificatore assegnato dalla persistenza.
    pub id: SessionId,
    /// Nome leggibile della sessione.
    pub label: DisplayName,
    /// Operatore che ha creato la sessione.
    pub started_by: Actor,
    /// Durata pianificata.
    pub duration: SessionDuration,
    /// Stato corrente.
    pub state: SessionState,
    /// Istante di creazione.
    pub created_at: Timestamp,
    /// Istante del primo avvio, assente finché la sessione non è stata avviata.
    pub started_at: Option<Timestamp>,
    /// Istante di conclusione, assente finché la sessione non è terminata.
    pub ended_at: Option<Timestamp>,
}

impl Session {
    /// L'istante in cui la durata pianificata scade, se ne ha una.
    ///
    /// Si ricava da due colonne già conservate — l'avvio e i secondi
    /// pianificati — e non da un orologio di processo: un riavvio, una
    /// sospensione della postazione o un timer dell'interfaccia fermo non lo
    /// spostano (INSTALLED-APP-E2E-01, E2E01-01). Una sessione mai avviata o
    /// senza durata non scade.
    #[must_use]
    pub const fn planned_end(&self) -> Option<Timestamp> {
        match (self.started_at, self.duration.planned_seconds()) {
            (Some(started_at), Some(seconds)) => Some(started_at.plus_seconds(seconds)),
            _ => None,
        }
    }

    /// Se la durata pianificata è trascorsa all'istante indicato e la sessione
    /// sta ancora acquisendo.
    ///
    /// La scadenza è **inclusa**: all'istante esatto della fine il monitoraggio
    /// è già concluso, e nulla di ciò che arriva in quell'istante gli appartiene.
    #[must_use]
    pub const fn is_due(&self, now: Timestamp) -> bool {
        if !matches!(self.state, SessionState::Running | SessionState::Paused) {
            return false;
        }
        match self.planned_end() {
            Some(end) => now.as_millis() >= end.as_millis(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{Session, SessionDuration, SessionDurationMode, SessionState};
    use crate::error::DomainError;
    use crate::id::SessionId;
    use crate::text::{Actor, DisplayName};
    use crate::time::Timestamp;

    /// **La durata si dice bene** (ADR-0150): «1 ora» e non «1 ore»; ore e
    /// minuti insieme; la personalizzata lo dichiara.
    #[test]
    fn la_durata_si_dice_al_singolare_e_al_plurale() {
        use super::duration_in_words;

        assert_eq!(duration_in_words(60), "1 minuto");
        assert_eq!(duration_in_words(1_800), "30 minuti");
        assert_eq!(duration_in_words(3_600), "1 ora");
        assert_eq!(duration_in_words(7_200), "2 ore");
        assert_eq!(duration_in_words(5_400), "1 ora e 30 minuti");
        assert_eq!(duration_in_words(7_260), "2 ore e 1 minuto");
        assert_eq!(duration_in_words(86_400), "24 ore");
        assert_eq!(
            SessionDuration::Custom { seconds: 8_100 }.in_words(),
            "2 ore e 15 minuti (personalizzata)"
        );
        assert_eq!(
            SessionDuration::Preset { seconds: 3_600 }.in_words(),
            "1 ora"
        );
        assert_eq!(
            SessionDuration::Manual.in_words(),
            "Fino all'arresto manuale"
        );
        assert_eq!(super::CUSTOM_MAX_SECONDS, 604_800);
    }

    fn sessione(state: SessionState, duration: SessionDuration, avvio: Option<i64>) -> Session {
        let (Ok(label), Ok(actor)) = (DisplayName::try_new("Prova"), Actor::try_new("operatore"))
        else {
            panic!("i valori di prova devono essere validi");
        };
        Session {
            id: SessionId::new(1),
            label,
            started_by: actor,
            duration,
            state,
            created_at: Timestamp::from_millis(0),
            started_at: avvio.map(Timestamp::from_millis),
            ended_at: None,
        }
    }

    /// **La fine si ricava dall'avvio e dai secondi conservati** (E2E01-01): un
    /// monitoraggio di 30 minuti avviato alle 22:22:27 scade alle 22:52:27, e
    /// non quando l'interfaccia se ne accorge.
    #[test]
    fn la_fine_pianificata_e_avvio_piu_durata() {
        let trenta_minuti = sessione(
            SessionState::Running,
            SessionDuration::Preset { seconds: 1_800 },
            Some(1_000),
        );
        assert_eq!(
            trenta_minuti.planned_end(),
            Some(Timestamp::from_millis(1_000 + 1_800_000))
        );
        let manuale = sessione(SessionState::Running, SessionDuration::Manual, Some(1_000));
        assert_eq!(manuale.planned_end(), None);
        let mai_avviata = sessione(
            SessionState::Planned,
            SessionDuration::Preset { seconds: 60 },
            None,
        );
        assert_eq!(mai_avviata.planned_end(), None);
    }

    /// **All'istante esatto della scadenza il monitoraggio è già concluso**, un
    /// millisecondo prima no; con gli avvisi sospesi scade lo stesso, perché
    /// l'acquisizione continua (ADR-0017); da concluso non scade di nuovo.
    #[test]
    fn la_scadenza_e_inclusa_e_vale_anche_con_gli_avvisi_sospesi() {
        let durata = SessionDuration::Preset { seconds: 60 };
        let in_corso = sessione(SessionState::Running, durata, Some(0));
        assert!(!in_corso.is_due(Timestamp::from_millis(59_999)));
        assert!(in_corso.is_due(Timestamp::from_millis(60_000)));
        assert!(in_corso.is_due(Timestamp::from_millis(3_300_000)));

        let sospesi = sessione(SessionState::Paused, durata, Some(0));
        assert!(sospesi.is_due(Timestamp::from_millis(60_000)));

        for finale in [SessionState::Completed, SessionState::Stopped] {
            assert!(!sessione(finale, durata, Some(0)).is_due(Timestamp::from_millis(99_999)));
        }
        let manuale = sessione(SessionState::Running, SessionDuration::Manual, Some(0));
        assert!(!manuale.is_due(Timestamp::from_millis(i64::MAX)));
    }

    /// **Con gli avvisi sospesi il monitoraggio è in corso, e l'etichetta lo
    /// dice** (OPERATOR-UX-REMEDIATION-01, OS-05): «Sospesa» si leggeva come una
    /// pausa dell'acquisizione, che il prodotto non ha.
    #[test]
    fn sospendere_gli_avvisi_non_si_legge_come_una_pausa() {
        let etichetta = SessionState::Paused.label();
        assert!(etichetta.starts_with("In corso"), "{etichetta}");
        assert!(etichetta.contains("avvisi sospesi"), "{etichetta}");
    }

    #[test]
    fn every_state_has_a_distinct_readable_label() {
        // La forma conservata e' un identificatore: mostrarla a chi legge un
        // rapporto vorrebbe dire fargli tradurre il nostro schema.
        let labels: Vec<&str> = SessionState::all().iter().map(|s| s.label()).collect();
        for label in &labels {
            assert!(!label.is_empty());
            assert_eq!(labels.iter().filter(|other| *other == label).count(), 1);
            assert!(
                !label.chars().all(char::is_lowercase),
                "l'etichetta non deve essere la forma conservata: {label}"
            );
        }
    }

    #[test]
    fn every_state_survives_a_round_trip_through_its_stored_form() {
        for state in SessionState::all() {
            assert_eq!(SessionState::from_str(state.as_str()), Ok(*state));
        }
    }

    #[test]
    fn every_duration_mode_survives_a_round_trip_through_its_stored_form() {
        for mode in SessionDurationMode::all() {
            assert_eq!(SessionDurationMode::from_str(mode.as_str()), Ok(*mode));
        }
    }

    #[test]
    fn the_ordered_lifecycle_is_allowed() {
        assert!(SessionState::Planned.can_transition_to(SessionState::Running));
        assert!(SessionState::Running.can_transition_to(SessionState::Paused));
        assert!(SessionState::Paused.can_transition_to(SessionState::Running));
        assert!(SessionState::Running.can_transition_to(SessionState::Completed));
        assert!(SessionState::Running.can_transition_to(SessionState::Stopped));
        assert!(SessionState::Paused.can_transition_to(SessionState::Stopped));
    }

    #[test]
    fn a_session_cannot_be_completed_without_having_run() {
        assert!(!SessionState::Planned.can_transition_to(SessionState::Completed));
        assert!(!SessionState::Planned.can_transition_to(SessionState::Paused));
    }

    #[test]
    fn no_transition_leaves_a_final_state() {
        for terminal in [SessionState::Completed, SessionState::Stopped] {
            assert!(terminal.is_final());
            for next in SessionState::all() {
                assert!(
                    !terminal.can_transition_to(*next),
                    "da {terminal} non deve essere possibile passare a {next}"
                );
            }
        }
    }

    #[test]
    fn a_state_cannot_transition_to_itself() {
        for state in SessionState::all() {
            assert!(!state.can_transition_to(*state));
        }
    }

    #[test]
    fn a_planned_duration_is_recomposed_from_its_stored_columns() {
        assert_eq!(
            SessionDuration::try_from_parts(SessionDurationMode::Preset, Some(3_600)),
            Ok(SessionDuration::Preset { seconds: 3_600 })
        );
        assert_eq!(
            SessionDuration::try_from_parts(SessionDurationMode::Custom, Some(90)),
            Ok(SessionDuration::Custom { seconds: 90 })
        );
        assert_eq!(
            SessionDuration::try_from_parts(SessionDurationMode::Manual, None),
            Ok(SessionDuration::Manual)
        );
    }

    #[test]
    fn a_manual_duration_with_planned_seconds_is_rejected() {
        assert!(matches!(
            SessionDuration::try_from_parts(SessionDurationMode::Manual, Some(60)),
            Err(DomainError::InconsistentPlannedDuration { .. })
        ));
    }

    #[test]
    fn a_timed_duration_without_planned_seconds_is_rejected() {
        for mode in [SessionDurationMode::Preset, SessionDurationMode::Custom] {
            assert!(matches!(
                SessionDuration::try_from_parts(mode, None),
                Err(DomainError::InconsistentPlannedDuration { .. })
            ));
        }
    }

    #[test]
    fn a_non_positive_planned_duration_is_rejected() {
        for seconds in [0, -1] {
            assert!(matches!(
                SessionDuration::try_from_parts(SessionDurationMode::Custom, Some(seconds)),
                Err(DomainError::InconsistentPlannedDuration { .. })
            ));
        }
    }

    #[test]
    fn a_duration_survives_a_round_trip_through_its_stored_columns() {
        for duration in [
            SessionDuration::Preset { seconds: 1_800 },
            SessionDuration::Custom { seconds: 45 },
            SessionDuration::Manual,
        ] {
            assert_eq!(
                SessionDuration::try_from_parts(duration.mode(), duration.planned_seconds()),
                Ok(duration)
            );
        }
    }
}

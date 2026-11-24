//! Periodi non coperti prioritari (PR-06, ADR-0122).
//!
//! # La frase che governa il modulo
//!
//! **Un periodo non coperto prioritario non dice che nel periodo la fonte abbia
//! pubblicato qualcosa.** Il ritmo passato di una fonte non dice che cosa abbia
//! fatto mentre nessuno guardava; soltanto il recupero, leggendo la cronologia,
//! può dirlo (PR-07). Qui si **ordina**, e non si afferma.
//!
//! # Il criterio, «Priorità dei periodi non coperti»
//!
//! 1. il **ritmo osservato**: la durata dei tratti coperti della fonte negli
//!    ultimi [`OBSERVATION_DAYS`] giorni, divisa per i messaggi di quella fonte
//!    arrivati in quei tratti;
//! 2. sotto [`MIN_ARRIVALS`] messaggi il ritmo **non è osservabile**, e la fonte
//!    non riceve priorità;
//! 3. **alta** un periodo lungo almeno [`HIGH_FACTOR`] volte l'intervallo medio,
//!    **media** almeno l'intervallo medio, **bassa** altrimenti;
//! 4. i periodi sono i tratti non coperti e non determinabili della finestra,
//!    esclusi quelli prima della configurazione e quello ancora in corso;
//! 5. l'ordine: priorità, rapporto fra durata e ritmo, il più vecchio, la fonte.
//!
//! La versione del criterio sta nel registro delle regole di PR-02, con
//! l'impronta del codice che la decide.
//!
//! # Nessuna stima
//!
//! Nessuna funzione di questo modulo moltiplica il ritmo per la durata. Il
//! numero che ne uscirebbe — «circa N messaggi» — sarebbe preciso e falso.

use std::collections::BTreeMap;

use lisi_core::model::NewAuditEntry;
use lisi_core::model::acquisition::InboxEventKind;
use lisi_core::model::coverage::{Coverage, CoverageState, NotCoveredReason};
use lisi_core::model::explanation::RuleVersion;
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SourceId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::gap_decision::NewGapDecision;

use crate::coverage::duration_in_words;
use crate::error::ServiceResult;

/// La finestra in cui si osserva il ritmo e si cercano i periodi, in giorni.
pub const OBSERVATION_DAYS: i64 = 30;

/// Quanti messaggi arrivati in tratti coperti servono perché il ritmo sia
/// osservabile.
pub const MIN_ARRIVALS: usize = 3;

/// Un periodo lungo almeno tante volte l'intervallo medio ha priorità alta.
pub const HIGH_FACTOR: i64 = 3;

const GIORNO: i64 = 24 * 60 * 60 * 1_000;

/// Che cosa la priorità non significa. Accompagna ogni periodo, ovunque
/// compaia.
pub const NOT_MEANING: &str = "La priorità è tecnica: non dice che nel periodo la fonte abbia \
                               pubblicato qualcosa.";

/// Come si nomina un periodo prioritario: la forma vincolata dal piano.
pub const NAME: &str = "Periodo non coperto prioritario in base al ritmo storico della fonte";

/// La priorità tecnica di un periodo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GapPriority {
    /// Più breve dell'intervallo medio.
    Low,
    /// Almeno l'intervallo medio.
    Medium,
    /// Almeno [`HIGH_FACTOR`] volte l'intervallo medio.
    High,
}

impl GapPriority {
    /// La parola che l'operatore legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "bassa",
            Self::Medium => "media",
            Self::High => "alta",
        }
    }

    /// Il nome stabile, per l'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.label()
    }
}

/// Il ritmo osservato di una fonte nei suoi tratti coperti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedRhythm {
    /// Quanto è durata, in tutto, la copertura della fonte.
    pub covered_ms: i64,
    /// Quanti messaggi della fonte sono arrivati nei tratti coperti.
    pub arrivals: usize,
}

impl ObservedRhythm {
    /// L'intervallo medio fra due messaggi arrivati, se il ritmo è osservabile.
    #[must_use]
    pub fn mean_interval_ms(self) -> Option<i64> {
        if self.arrivals < MIN_ARRIVALS || self.covered_ms <= 0 {
            return None;
        }
        let arrivi = i64::try_from(self.arrivals).ok()?;
        Some((self.covered_ms / arrivi).max(1))
    }
}

/// Un periodo non coperto, con la sua priorità tecnica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityGap {
    /// La fonte.
    pub source_id: SourceId,
    /// Il suo nome.
    pub source_name: String,
    /// Da quando.
    pub from: Timestamp,
    /// Fino a quando.
    pub to: Timestamp,
    /// Lo stato del tratto, con il suo perché (PR-05).
    pub state: CoverageState,
    /// La priorità tecnica.
    pub priority: GapPriority,
    /// L'intervallo medio osservato della fonte.
    pub mean_interval_ms: i64,
}

impl PriorityGap {
    /// La durata del periodo.
    #[must_use]
    pub fn duration_ms(&self) -> i64 {
        self.to.as_millis() - self.from.as_millis()
    }

    /// La frase del periodo, nella forma vincolata, con che cosa non significa.
    #[must_use]
    pub fn sentence(&self) -> String {
        format!(
            "{NAME}: dal {} al {}, priorità {}. {} {NOT_MEANING}",
            self.from.to_readable_local(),
            self.to.to_readable_local(),
            self.priority.label(),
            criterion_sentence(self.mean_interval_ms)
        )
    }
}

/// Il criterio, detto con i numeri che applica.
///
/// Si compone dalle **stesse** costanti della classificazione: non può dire
/// una cosa e applicarne un'altra.
#[must_use]
pub fn criterion_sentence(mean_interval_ms: i64) -> String {
    format!(
        "Nei periodi coperti di questa fonte è arrivato in media un messaggio ogni {}. Un periodo \
         lungo almeno {} ha priorità alta, almeno {} media.",
        duration_in_words(mean_interval_ms),
        duration_in_words(mean_interval_ms.saturating_mul(HIGH_FACTOR)),
        duration_in_words(mean_interval_ms)
    )
}

/// La priorità di un periodo, dalla sua durata e dal ritmo della sua fonte.
#[must_use]
pub const fn priority_of(duration_ms: i64, mean_interval_ms: i64) -> GapPriority {
    if duration_ms >= mean_interval_ms.saturating_mul(HIGH_FACTOR) {
        GapPriority::High
    } else if duration_ms >= mean_interval_ms {
        GapPriority::Medium
    } else {
        GapPriority::Low
    }
}

/// Il ritmo osservato: i messaggi arrivati nei tratti **coperti**.
#[must_use]
pub fn observed_rhythm(copertura: &Coverage, arrivi: &[Timestamp]) -> ObservedRhythm {
    let coperti: Vec<_> = copertura
        .intervals()
        .iter()
        .filter(|tratto| tratto.state == CoverageState::Covered)
        .collect();
    ObservedRhythm {
        covered_ms: coperti
            .iter()
            .map(|tratto| tratto.to.as_millis() - tratto.from.as_millis())
            .sum(),
        arrivals: arrivi
            .iter()
            .filter(|arrivo| {
                coperti
                    .iter()
                    .any(|tratto| tratto.from <= **arrivo && **arrivo < tratto.to)
            })
            .count(),
    }
}

/// L'esito per una fonte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceGaps {
    /// Il ritmo è osservabile: i periodi, con la loro priorità.
    Prioritized(Vec<PriorityGap>),
    /// Il ritmo non è osservabile: nessuna priorità, e quanti periodi ci sono.
    RhythmNotObservable {
        /// La fonte.
        source_id: SourceId,
        /// Il suo nome.
        source_name: String,
        /// Quanti periodi non coperti ha, senza priorità.
        gaps: usize,
    },
}

/// I periodi di una fonte, con la loro priorità (funzione pura).
///
/// `until` è l'istante della fotografia: il tratto che arriva fin lì è ancora
/// in corso, e non si valuta.
#[must_use]
pub fn assess_source(
    source_id: SourceId,
    source_name: &str,
    copertura: &Coverage,
    arrivi: &[Timestamp],
    until: Timestamp,
) -> SourceGaps {
    let periodi: Vec<_> = copertura
        .gaps()
        .filter(|tratto| {
            tratto.state != CoverageState::NotCovered(NotCoveredReason::NotYetConfigured)
                && tratto.to < until
        })
        .collect();

    let Some(medio) = observed_rhythm(copertura, arrivi).mean_interval_ms() else {
        return SourceGaps::RhythmNotObservable {
            source_id,
            source_name: String::from(source_name),
            gaps: periodi.len(),
        };
    };

    SourceGaps::Prioritized(
        periodi
            .into_iter()
            .map(|tratto| PriorityGap {
                source_id,
                source_name: String::from(source_name),
                from: tratto.from,
                to: tratto.to,
                state: tratto.state,
                priority: priority_of(tratto.to.as_millis() - tratto.from.as_millis(), medio),
                mean_interval_ms: medio,
            })
            .collect(),
    )
}

/// L'ordine dei periodi: priorità, rapporto fra durata e ritmo, il più vecchio,
/// la fonte.
pub fn order(periodi: &mut [PriorityGap]) {
    periodi.sort_by(|uno, altro| {
        altro
            .priority
            .cmp(&uno.priority)
            // Il rapporto senza divisioni: a/b > c/d se a·d > c·b.
            .then_with(|| {
                (i128::from(altro.duration_ms()) * i128::from(uno.mean_interval_ms))
                    .cmp(&(i128::from(uno.duration_ms()) * i128::from(altro.mean_interval_ms)))
            })
            .then_with(|| uno.from.cmp(&altro.from))
            .then_with(|| uno.source_id.get().cmp(&altro.source_id.get()))
    });
}

/// Tutti i periodi prioritari della finestra, e le fonti senza ritmo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapAssessment {
    /// I periodi di priorità alta e media, in ordine, non ancora decisi.
    pub listed: Vec<PriorityGap>,
    /// Quanti periodi di priorità bassa non sono elencati.
    pub low: usize,
    /// Le fonti il cui ritmo non è osservabile, con quanti periodi hanno.
    pub not_observable: Vec<(String, usize)>,
}

/// L'inizio della finestra.
#[must_use]
pub const fn window_start(until: Timestamp) -> Timestamp {
    Timestamp::from_millis(until.as_millis() - OBSERVATION_DAYS * GIORNO)
}

/// Compone i periodi prioritari dall'archivio, alla fotografia `until`.
///
/// Legge soltanto. Un periodo su cui una persona ha già deciso non compare.
///
/// # Errori
///
/// Restituisce un errore se una lettura non riesce.
pub fn assess(database: &Database, until: Timestamp) -> ServiceResult<GapAssessment> {
    let dal = window_start(until);
    let coperture = crate::coverage::for_sources(database, dal, until)?;
    let arrivi = arrivals_by_source(database, dal, until)?;
    let decisi = database.gap_decisions()?;

    let mut listed = Vec::new();
    let mut low = 0;
    let mut not_observable = Vec::new();
    for fonte in coperture {
        let vuoto = Vec::new();
        let suoi = arrivi.get(&fonte.source_id.get()).unwrap_or(&vuoto);
        match assess_source(fonte.source_id, &fonte.name, &fonte.coverage, suoi, until) {
            SourceGaps::Prioritized(periodi) => {
                for periodo in periodi {
                    let deciso = decisi.iter().any(|decisione| {
                        decisione.source_id == periodo.source_id
                            && decisione.gap_from == periodo.from
                            && decisione.gap_to == periodo.to
                    });
                    if deciso {
                        continue;
                    }
                    if periodo.priority == GapPriority::Low {
                        low += 1;
                    } else {
                        listed.push(periodo);
                    }
                }
            }
            SourceGaps::RhythmNotObservable {
                source_name, gaps, ..
            } => {
                if gaps > 0 {
                    not_observable.push((source_name, gaps));
                }
            }
        }
    }
    order(&mut listed);
    Ok(GapAssessment {
        listed,
        low,
        not_observable,
    })
}

/// I messaggi **nuovi** arrivati da ciascuna fonte nella finestra.
///
/// Soltanto i nuovi: una modifica o una cancellazione arrivano dopo un
/// messaggio che c'era già, e contarle raddoppierebbe il ritmo.
fn arrivals_by_source(
    database: &Database,
    from: Timestamp,
    until: Timestamp,
) -> ServiceResult<BTreeMap<i64, Vec<Timestamp>>> {
    let mut arrivi: BTreeMap<i64, Vec<Timestamp>> = BTreeMap::new();
    for sessione in database.sessions()? {
        let Some(avvio) = sessione.started_at else {
            continue;
        };
        if avvio >= until || sessione.ended_at.is_some_and(|fine| fine <= from) {
            continue;
        }
        for fatto in database.session_reception_facts(sessione.id)? {
            // UN MESSAGGIO RECUPERATO NON FA RITMO (versione 2, ADR-0123): prova
            // che in quell'istante si era collegati, non che sia arrivato dal vivo.
            if fatto.kind != InboxEventKind::NewMessage
                || fatto.recovered
                || fatto.received_at < from
                || fatto.received_at >= until
            {
                continue;
            }
            if let Some(fonte) = fatto.source_id {
                arrivi
                    .entry(fonte.get())
                    .or_default()
                    .push(fatto.received_at);
            }
        }
    }
    Ok(arrivi)
}

/// Che cosa una persona decide su un periodo prioritario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapDecision {
    /// Il periodo passa alla valutazione di un recupero (PR-07).
    EvaluateRecovery,
    /// Il periodo resta un limite dichiarato: non si guardava.
    DeclaredNotCovered,
}

impl GapDecision {
    /// Il nome stabile, per l'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvaluateRecovery => "da_valutare_per_recupero",
            Self::DeclaredNotCovered => "dichiarato_non_coperto",
        }
    }

    /// Il nome che l'operatore legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EvaluateRecovery => "Da valutare per un recupero",
            Self::DeclaredNotCovered => "Dichiarato non coperto",
        }
    }
}

/// L'azione d'audit di una decisione su un periodo.
pub const GAP_DECISION_AUDIT_ACTION: &str = "periodo_non_coperto_deciso";

/// Registra la decisione di una persona su un periodo, con il motivo.
///
/// La decisione e la riga d'audit si scrivono insieme. **Nessuna richiesta a
/// Telegram parte da qui**: «da valutare per un recupero» consegna il periodo a
/// una persona, e la richiesta la fa lei (PR-07).
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce.
pub fn record_decision(
    database: &mut Database,
    periodo: &PriorityGap,
    decisione: GapDecision,
    motivo: &OperationalReason,
    attore: &Actor,
    now: Timestamp,
) -> ServiceResult<()> {
    let versione = match crate::rule_versions::current_version(
        lisi_core::model::explanation::Explained::CoverageGap,
    ) {
        RuleVersion::Known(versione) => versione,
        // Irraggiungibile: la versione del criterio è registrata. Se non lo
        // fosse, lo zero lo rifiuta l'archivio invece di scrivere una versione
        // inventata.
        RuleVersion::NotRecorded | RuleVersion::NotTransmitted => 0,
    };
    let audit = NewAuditEntry {
        actor: attore.clone(),
        action: AuditAction::try_new(GAP_DECISION_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("periodo_non_coperto")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "{}: fonte {}, dal {} al {}, priorità {} (criterio v{versione})",
            decisione.label(),
            periodo.source_id.get(),
            periodo.from.to_readable_utc(),
            periodo.to.to_readable_utc(),
            periodo.priority.label()
        ))?),
        recorded_at: now,
    };
    database.insert_gap_decision(
        &NewGapDecision {
            source_id: periodo.source_id,
            gap_from: periodo.from,
            gap_to: periodo.to,
            priority: String::from(periodo.priority.as_str()),
            criterion_version: versione,
            decision: String::from(decisione.as_str()),
            reason: String::from(motivo.as_str()),
            decided_by: String::from(attore.as_str()),
            decided_at: now,
        },
        &audit,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use lisi_core::model::coverage::{
        Coverage, CoverageInterval, CoverageState, NotCoveredReason, UndeterminedReason,
    };
    use lisi_core::{SourceId, Timestamp};

    use super::{
        GapPriority, HIGH_FACTOR, MIN_ARRIVALS, NAME, NOT_MEANING, PriorityGap, SourceGaps,
        assess_source, criterion_sentence, order, priority_of,
    };

    const THIS_MODULE: &str = include_str!("gap.rs");
    const ORA: i64 = 3_600_000;

    fn t(ore: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + ore * ORA)
    }

    fn tratto(da: i64, a: i64, stato: CoverageState) -> CoverageInterval {
        CoverageInterval {
            from: t(da),
            to: t(a),
            state: stato,
        }
    }

    const NON_SI_SA: CoverageState =
        CoverageState::Undetermined(UndeterminedReason::ProgramStopped);
    const FERMO: CoverageState = CoverageState::NotCovered(NotCoveredReason::NoMonitoring);

    /// Dieci ore coperte, poi un vuoto di sei ore, poi due coperte, poi un
    /// vuoto di un'ora, poi la coda ancora in corso.
    fn copertura() -> Coverage {
        let Some(copertura) = Coverage::build(vec![
            tratto(
                -2,
                0,
                CoverageState::NotCovered(NotCoveredReason::NotYetConfigured),
            ),
            tratto(0, 10, CoverageState::Covered),
            tratto(10, 16, NON_SI_SA),
            tratto(16, 18, CoverageState::Covered),
            tratto(18, 19, FERMO),
            tratto(19, 20, CoverageState::Covered),
            tratto(
                20,
                24,
                CoverageState::Undetermined(UndeterminedReason::AfterLastFact),
            ),
        ]) else {
            panic!("tratti contigui");
        };
        copertura
    }

    /// Un arrivo ogni ora nei tratti coperti: 13 arrivi in 13 ore.
    fn ogni_ora() -> Vec<Timestamp> {
        (0..10).chain(16..18).chain(19..20).map(t).collect()
    }

    fn periodi(esito: SourceGaps) -> Vec<PriorityGap> {
        let SourceGaps::Prioritized(periodi) = esito else {
            panic!("il ritmo doveva essere osservabile");
        };
        periodi
    }

    /// **Il criterio usa il ritmo della fonte**: sei ore su un ritmo di un'ora
    /// sono priorità alta, un'ora è media; la coda in corso e il tratto prima
    /// della configurazione non si valutano.
    #[test]
    fn la_priorita_viene_dal_ritmo_della_fonte() {
        let trovati = periodi(assess_source(
            SourceId::new(1),
            "Canale",
            &copertura(),
            &ogni_ora(),
            t(24),
        ));
        assert_eq!(trovati.len(), 2, "{trovati:?}");
        assert_eq!(trovati[0].priority, GapPriority::High);
        assert_eq!(trovati[0].mean_interval_ms, ORA);
        assert_eq!(trovati[1].priority, GapPriority::Medium);
        assert!(trovati.iter().all(|periodo| periodo.to < t(24)));
    }

    /// **Nessuna soglia uguale per tutte le fonti** (controllo negativo 2): la
    /// stessa durata ha priorità diverse con ritmi diversi.
    #[test]
    fn la_stessa_durata_pesa_diversamente_su_fonti_diverse() {
        assert_eq!(priority_of(6 * ORA, ORA), GapPriority::High);
        assert_eq!(priority_of(6 * ORA, 4 * ORA), GapPriority::Medium);
        assert_eq!(priority_of(6 * ORA, 10 * ORA), GapPriority::Low);
    }

    /// **Senza ritmo osservabile, nessuna priorità** (controllo negativo 4).
    #[test]
    fn senza_ritmo_nessuna_priorita() {
        let pochi: Vec<Timestamp> = (0..MIN_ARRIVALS - 1)
            .map(|ora| t(i64::try_from(ora).unwrap_or(0)))
            .collect();
        let esito = assess_source(SourceId::new(1), "Canale", &copertura(), &pochi, t(24));
        assert!(
            matches!(esito, SourceGaps::RhythmNotObservable { gaps: 2, .. }),
            "{esito:?}"
        );
        // Gli arrivi FUORI dai tratti coperti non fanno ritmo.
        let fuori: Vec<Timestamp> = (11..15).map(t).collect();
        assert!(matches!(
            assess_source(SourceId::new(1), "Canale", &copertura(), &fuori, t(24)),
            SourceGaps::RhythmNotObservable { .. }
        ));
    }

    /// **Il criterio mostrato è quello applicato** (controllo negativo 3).
    #[test]
    fn il_criterio_mostrato_e_quello_applicato() {
        let frase = criterion_sentence(ORA);
        assert!(frase.contains("un messaggio ogni 1 ora"), "{frase}");
        assert!(
            frase.contains(&format!("almeno {} ore ha priorità alta", HIGH_FACTOR)),
            "{frase}"
        );
        assert_eq!(priority_of(HIGH_FACTOR * ORA, ORA), GapPriority::High);
        assert_eq!(priority_of(HIGH_FACTOR * ORA - 1, ORA), GapPriority::Medium);
    }

    /// **Il linguaggio è vincolato, e nessuna frase stima messaggi**
    /// (controlli negativi 5 e 6).
    #[test]
    fn il_linguaggio_non_afferma_ne_stima() {
        let trovati = periodi(assess_source(
            SourceId::new(1),
            "Canale",
            &copertura(),
            &ogni_ora(),
            t(24),
        ));
        let mut frasi: Vec<String> = trovati.iter().map(PriorityGap::sentence).collect();
        frasi.push(String::from(NOT_MEANING));
        frasi.push(String::from(NAME));
        let produzione = THIS_MODULE
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(THIS_MODULE, |(codice, _)| codice);
        frasi.push(produzione.to_lowercase());
        for frase in &frasi {
            let minuscola = frase.to_lowercase();
            for vietata in [
                "dati mancanti",
                "messaggi mancanti",
                "sicuramente",
                "avrebbe dovuto",
            ] {
                assert!(!minuscola.contains(vietata), "«{vietata}» in: {frase}");
            }
        }
        for frase in trovati.iter().map(PriorityGap::sentence) {
            assert!(frase.starts_with(NAME), "{frase}");
            assert!(frase.contains(NOT_MEANING), "{frase}");
            let parole: Vec<&str> = frase.split_whitespace().collect();
            for coppia in parole.windows(2) {
                assert!(
                    !(coppia[0].chars().all(|c| c.is_ascii_digit())
                        && coppia[1].starts_with("messagg")),
                    "una frase stima un numero di messaggi: {frase}"
                );
            }
        }
    }

    /// **Stessi fatti, stesso ordine**, e l'ordine mette prima la priorità.
    #[test]
    fn l_ordine_e_deterministico() {
        let mut uno = periodi(assess_source(
            SourceId::new(1),
            "Canale",
            &copertura(),
            &ogni_ora(),
            t(24),
        ));
        let mut due = uno.clone();
        due.reverse();
        order(&mut uno);
        order(&mut due);
        assert_eq!(uno, due);
        assert_eq!(uno[0].priority, GapPriority::High);
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        assert!(
            !produzione.contains("now("),
            "il criterio non legge l'orologio"
        );
    }

    /// **La priorità non entra in nessuna analisi** (controllo negativo 7).
    #[test]
    fn la_priorita_non_entra_nelle_analisi() {
        for (nome, sorgente) in [
            ("trend.rs", include_str!("trend.rs")),
            ("similarity.rs", include_str!("similarity.rs")),
            ("spike/mod.rs", include_str!("spike/mod.rs")),
            ("analysis.rs", include_str!("analysis.rs")),
            ("source_health.rs", include_str!("source_health.rs")),
            ("person.rs", include_str!("person.rs")),
            ("person_dossier.rs", include_str!("person_dossier.rs")),
            ("person_timeline.rs", include_str!("person_timeline.rs")),
            ("assessment.rs", include_str!("assessment.rs")),
        ] {
            for vietato in ["crate::gap", "gap::", "PriorityGap", "GapPriority"] {
                assert!(
                    !sorgente.contains(vietato),
                    "{nome} nomina «{vietato}»: la priorità è tecnica, e non entra nelle analisi"
                );
            }
        }
    }

    /// **Dall'archivio alla coda, e fuori dalla coda con una decisione**:
    /// comporre non scrive; decidere scrive la decisione e la sua traccia, e il
    /// periodo deciso non torna.
    #[test]
    fn un_periodo_deciso_esce_dalla_coda() {
        use lisi_core::model::acquisition::{IdempotencyKey, InboxEventKind, NewInboxEntry};
        use lisi_core::model::reason::OperationalReason;
        use lisi_core::model::{NewSession, NewSource, SessionDuration, SessionState, SourceKind};
        use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let (Ok(attore), Ok(identificativo), Ok(nome)) = (
            Actor::try_new("operatore.prova"),
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: attore.clone(),
                active: true,
            },
            t(-2),
        ) else {
            panic!("la fonte deve registrarsi");
        };
        for (inizio, fine, ore) in [(0, 10, 0..9), (20, 22, 20..22)] {
            let Ok(etichetta) = DisplayName::try_new(&format!("Monitoraggio delle {inizio}"))
            else {
                panic!("etichetta valida");
            };
            let Ok(sessione) = database.insert_session(
                &NewSession {
                    label: etichetta,
                    started_by: attore.clone(),
                    duration: SessionDuration::Preset { seconds: 36_000 },
                    source_ids: vec![fonte],
                },
                t(inizio),
            ) else {
                panic!("la sessione deve crearsi");
            };
            let (Ok(()), Ok(())) = (
                database.update_session_state(sessione, SessionState::Running, t(inizio)),
                Ok::<(), ()>(()),
            ) else {
                panic!("la sessione deve avviarsi");
            };
            for ora in ore {
                let chiave = IdempotencyKey::derive(
                    sessione,
                    Some(fonte),
                    InboxEventKind::NewMessage,
                    Some(&ora.to_string()),
                    None,
                );
                let Ok(_) = database.enqueue_inbox(&NewInboxEntry {
                    session_id: sessione,
                    source_id: Some(fonte),
                    event_kind: InboxEventKind::NewMessage,
                    remote_event_id: None,
                    idempotency_key: chiave,
                    remote_timestamp: None,
                    received_at: t(ora),
                    payload_json: None,
                    format_version: 1,
                }) else {
                    panic!("l'evento deve accodarsi");
                };
            }
            let Ok(()) = database.update_session_state(sessione, SessionState::Stopped, t(fine))
            else {
                panic!("la sessione deve concludersi");
            };
        }

        let prima = database.total_changes();
        let Ok(esito) = super::assess(&database, t(30)) else {
            panic!("i periodi devono comporsi");
        };
        assert_eq!(
            database.total_changes(),
            prima,
            "comporre la coda non scrive"
        );
        // Quattro: prima del primo monitoraggio, la coda del primo, fra i due, la
        // coda del secondo. Quello che arriva fino alla fotografia non si valuta.
        assert_eq!(esito.listed.len(), 4, "{:?}", esito.listed);
        assert_eq!(esito.listed[0].priority, GapPriority::High);
        assert_eq!(esito.listed[0].from, t(10));

        let Ok(motivo) = OperationalReason::try_new("La fonte va seguita anche di notte.") else {
            panic!("motivo valido");
        };
        let Ok(()) = super::record_decision(
            &mut database,
            &esito.listed[0],
            super::GapDecision::EvaluateRecovery,
            &motivo,
            &attore,
            t(31),
        ) else {
            panic!("la decisione deve registrarsi");
        };
        let Ok(dopo) = super::assess(&database, t(32)) else {
            panic!("i periodi devono comporsi");
        };
        assert_eq!(dopo.listed.len(), 3);
        assert!(dopo.listed.iter().all(|periodo| periodo.from != t(10)));
    }
}

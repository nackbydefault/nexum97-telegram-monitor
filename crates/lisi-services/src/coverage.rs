//! Che cosa stavamo guardando, ricavato dai fatti (PR-05, ADR-0121).
//!
//! # Una derivazione pura
//!
//! [`monitoring_coverage`], [`source_in_monitoring`] e [`source_coverage`]
//! ricevono i fatti e l'**istante della fotografia**, e restituiscono i tratti.
//! Non leggono l'archivio e non leggono l'orologio: stessi fatti, stesso
//! istante, stessa copertura. [`CoverageService`] raccoglie i fatti e li passa.
//!
//! # Le regole, in una riga ciascuna (ADR-0121, decisione 2)
//!
//! 1. fra due fatti consecutivi senza rotture registrate: coperto;
//! 2. un tratto che finisce con un ritorno in linea: non determinabile;
//! 3. dalla perdita del collegamento al ritorno: non determinabile;
//! 4. da un errore permanente al ritorno: non determinabile;
//! 5. dall'avvio al primo fatto: coperto, salvo che il primo fatto sia un
//!    ritorno in linea; senza fatti, tutto non determinabile;
//! 6. dall'ultimo fatto alla fine: non determinabile;
//! 7. una fonte trovata non accessibile: non determinabile fra le due prove di
//!    accessibilità che la circondano;
//! 8. fuori da ogni monitoraggio: non coperto; prima della configurazione: non
//!    coperto, «non ancora configurata»;
//! 9. più monitoraggi: coperto se uno copriva, altrimenti non determinabile se
//!    uno non sa, altrimenti non coperto.
//!
//! # Un contenuto non crea copertura
//!
//! Un evento **ricevuto** prova che in quell'istante il programma era vivo e
//! collegato: è un fatto su di noi. L'istante in cui un messaggio fu
//! **pubblicato** è un fatto su di loro, e qui non entra.

use std::collections::BTreeSet;

use lisi_core::model::acquisition::InboxEventKind;
use lisi_core::model::coverage::{
    Coverage, CoverageInterval, CoverageState, NotCoveredReason, UndeterminedReason,
};
use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_storage::Database;

use crate::error::ServiceResult;
use lisi_core::model::source_health::HealthCheckOutcome;

/// Un fatto del monitoraggio, com'è arrivato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleFact {
    /// Un evento ricevuto da Telegram: il programma era vivo e collegato.
    Received {
        /// Quando.
        at: Timestamp,
        /// Da quale fonte, quando è di una fonte.
        source: Option<SourceId>,
    },
    /// Il collegamento è tornato in linea.
    ConnectionRestored(Timestamp),
    /// Il collegamento si è perso.
    ConnectionLost(Timestamp),
    /// Il connettore si è fermato per un errore permanente.
    ConnectorFailed(Timestamp),
}

impl LifecycleFact {
    /// Quando.
    #[must_use]
    pub const fn at(self) -> Timestamp {
        match self {
            Self::Received { at, .. }
            | Self::ConnectionRestored(at)
            | Self::ConnectionLost(at)
            | Self::ConnectorFailed(at) => at,
        }
    }

    /// Il fatto che un evento dell'archivio porta, se ne porta uno.
    ///
    /// Un errore transitorio **non** è una prova di collegamento: si ignora.
    #[must_use]
    pub const fn from_event(
        kind: InboxEventKind,
        at: Timestamp,
        source: Option<SourceId>,
    ) -> Option<Self> {
        match kind {
            InboxEventKind::NewMessage
            | InboxEventKind::EditedMessage
            | InboxEventKind::DeletedMessage => Some(Self::Received { at, source }),
            InboxEventKind::ConnectionEstablished | InboxEventKind::Reconnected => {
                Some(Self::ConnectionRestored(at))
            }
            InboxEventKind::ConnectionLost => Some(Self::ConnectionLost(at)),
            InboxEventKind::PermanentError => Some(Self::ConnectorFailed(at)),
            InboxEventKind::SourceAvailable
            | InboxEventKind::SourceUnavailable
            | InboxEventKind::TemporaryError
            | InboxEventKind::OrderedShutdown
            | InboxEventKind::Checkpoint
            | InboxEventKind::UnsupportedEvent => None,
        }
    }
}

/// I fatti di un monitoraggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringFacts {
    /// Quando è stato avviato.
    pub started_at: Timestamp,
    /// Quando si è concluso, se si è concluso.
    pub ended_at: Option<Timestamp>,
    /// I fatti, in qualunque ordine: la derivazione li ordina.
    pub facts: Vec<LifecycleFact>,
    /// L'interruzione registrata, se c'è: dall'ultimo fatto noto al riavvio.
    pub interruption: Option<(Timestamp, Timestamp)>,
    /// Le pause dell'acquisizione: da quando, e fino a quando se è stata
    /// ripresa (PAUSE-01, ADR-0172).
    pub pauses: Vec<(Timestamp, Option<Timestamp>)>,
}

/// La copertura di un monitoraggio: il programma e il collegamento.
///
/// `until` è l'istante della fotografia: la fine di un monitoraggio in corso.
#[must_use]
pub fn monitoring_coverage(monitoraggio: &MonitoringFacts, until: Timestamp) -> Coverage {
    let inizio = monitoraggio.started_at;
    let fine = monitoraggio.ended_at.map_or(until, |fine| fine.min(until));
    if fine <= inizio {
        return vuota();
    }

    let mut fatti: Vec<LifecycleFact> = monitoraggio
        .facts
        .iter()
        .copied()
        .filter(|fatto| fatto.at() >= inizio && fatto.at() <= fine)
        .collect();
    // L'ordine di arrivo; a parità d'istante, l'ordine in cui sono stati letti.
    fatti.sort_by_key(|fatto| fatto.at());

    let mut tratti = Vec::with_capacity(fatti.len() + 1);
    let mut cursore = inizio;
    // Lo stato dopo l'ultimo fatto: `None` vuol dire collegato.
    let mut dopo: Option<UndeterminedReason> = None;
    let mut primo = true;

    for fatto in &fatti {
        let stato = match fatto {
            LifecycleFact::ConnectionRestored(_) => CoverageState::Undetermined(if primo {
                UndeterminedReason::NoFactYet
            } else {
                dopo.unwrap_or(UndeterminedReason::ConnectionRestored)
            }),
            LifecycleFact::Received { .. }
            | LifecycleFact::ConnectionLost(_)
            | LifecycleFact::ConnectorFailed(_) => {
                dopo.map_or(CoverageState::Covered, CoverageState::Undetermined)
            }
        };
        tratti.push(CoverageInterval {
            from: cursore,
            to: fatto.at(),
            state: stato,
        });
        dopo = match fatto {
            LifecycleFact::Received { .. } | LifecycleFact::ConnectionRestored(_) => None,
            LifecycleFact::ConnectionLost(_) => Some(UndeterminedReason::ConnectionLost),
            LifecycleFact::ConnectorFailed(_) => Some(UndeterminedReason::ConnectorFailed),
        };
        cursore = fatto.at();
        primo = false;
    }

    tratti.push(CoverageInterval {
        from: cursore,
        to: fine,
        state: CoverageState::Undetermined(if primo {
            UndeterminedReason::NoFactYet
        } else {
            dopo.unwrap_or(UndeterminedReason::AfterLastFact)
        }),
    });

    let mut copertura = costruisci(tratti);
    // L'INTERRUZIONE REGISTRATA è un fatto: fra l'ultimo fatto noto e il
    // riavvio il programma si è fermato, in un istante che non si sa. Vale
    // sopra qualunque altra lettura di quel tratto.
    if let Some((da, a)) = monitoraggio.interruption {
        copertura = sovrapponi(
            &copertura,
            da,
            a,
            CoverageState::Undetermined(UndeterminedReason::ProgramStopped),
            Sovrapposizione::Sempre,
        );
    }
    // LA PAUSA È UN BUCO DICHIARATO (ADR-0172): si sa che non si guardava, e
    // perché. Vale sopra qualunque altra lettura di quel tratto; una pausa
    // ancora aperta arriva fino alla fine della fotografia.
    for (da, a) in &monitoraggio.pauses {
        copertura = sovrapponi(
            &copertura,
            (*da).max(inizio),
            a.unwrap_or(fine).min(fine),
            CoverageState::NotCovered(NotCoveredReason::Paused),
            Sovrapposizione::Sempre,
        );
    }
    copertura
}

/// Una verifica di accessibilità di una fonte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessCheck {
    /// Quando.
    pub at: Timestamp,
    /// Se la fonte era accessibile. `None` per una verifica non riuscita, che
    /// non dice nulla.
    pub accessible: Option<bool>,
}

/// La copertura di una fonte **dentro** un monitoraggio (regola 7).
///
/// Sopra la copertura del monitoraggio, una verifica che trova la fonte non
/// accessibile rende non determinabile il tratto fra la prova di accessibilità
/// precedente — una verifica riuscita o un messaggio di quella fonte — e la
/// successiva. Tocca soltanto ciò che era coperto: un motivo già più preciso
/// resta.
#[must_use]
pub fn source_in_monitoring(
    monitoraggio: &Coverage,
    fonte: SourceId,
    fatti: &[LifecycleFact],
    verifiche: &[AccessCheck],
) -> Coverage {
    let (Some(inizio), Some(fine)) = (monitoraggio.start(), monitoraggio.end()) else {
        return monitoraggio.clone();
    };

    let mut prove: Vec<Timestamp> = fatti
        .iter()
        .filter_map(|fatto| match fatto {
            LifecycleFact::Received { at, source } if *source == Some(fonte) => Some(*at),
            _ => None,
        })
        .chain(
            verifiche
                .iter()
                .filter(|verifica| verifica.accessible == Some(true))
                .map(|verifica| verifica.at),
        )
        .collect();
    prove.sort();

    let mut copertura = monitoraggio.clone();
    for verifica in verifiche {
        if verifica.accessible != Some(false) || verifica.at < inizio || verifica.at > fine {
            continue;
        }
        let da = prove
            .iter()
            .rev()
            .find(|prova| **prova < verifica.at)
            .copied()
            .unwrap_or(inizio)
            .max(inizio);
        let a = prove
            .iter()
            .find(|prova| **prova > verifica.at)
            .copied()
            .unwrap_or(fine)
            .min(fine);
        copertura = sovrapponi(
            &copertura,
            da,
            a,
            CoverageState::Undetermined(UndeterminedReason::SourceNotAccessible),
            Sovrapposizione::SoloCoperto,
        );
    }
    copertura
}

/// La copertura di una fonte su una finestra, attraverso tutti i monitoraggi
/// che l'hanno seguita (regole 8 e 9).
///
/// `configured_at` è l'istante in cui la fonte è stata configurata; `from` e
/// `until` sono la finestra.
#[must_use]
pub fn source_coverage(
    configured_at: Timestamp,
    monitoraggi: &[Coverage],
    from: Timestamp,
    until: Timestamp,
) -> Coverage {
    if until <= from {
        return vuota();
    }
    let configurata = configured_at.max(from).min(until);
    let base = costruisci(vec![
        CoverageInterval {
            from,
            to: configurata,
            state: CoverageState::NotCovered(NotCoveredReason::NotYetConfigured),
        },
        CoverageInterval {
            from: configurata,
            to: until,
            state: CoverageState::NotCovered(NotCoveredReason::NoMonitoring),
        },
    ]);

    // I confini di tutti i tratti, dentro la finestra.
    let mut confini: BTreeSet<Timestamp> = BTreeSet::new();
    confini.insert(from);
    confini.insert(until);
    for copertura in std::iter::once(&base).chain(monitoraggi.iter()) {
        for tratto in copertura.intervals() {
            for istante in [tratto.from, tratto.to] {
                if istante > from && istante < until {
                    confini.insert(istante);
                }
            }
        }
    }

    let confini: Vec<Timestamp> = confini.into_iter().collect();
    let tratti = confini
        .windows(2)
        .map(|coppia| {
            let (da, a) = (coppia[0], coppia[1]);
            let mut stato = stato_in(&base, da)
                .unwrap_or(CoverageState::NotCovered(NotCoveredReason::NoMonitoring));
            for copertura in monitoraggi {
                if let Some(altro) = stato_in(copertura, da) {
                    stato = migliore(stato, altro);
                }
            }
            CoverageInterval {
                from: da,
                to: a,
                state: stato,
            }
        })
        .collect();
    costruisci(tratti)
}

/// Il più informativo fra due stati dello stesso istante (regola 9).
///
/// Coperto vince; poi non determinabile; poi non coperto. A parità, il primo:
/// la derivazione resta la stessa a ogni lettura.
const fn migliore(uno: CoverageState, altro: CoverageState) -> CoverageState {
    const fn peso(stato: CoverageState) -> u8 {
        match stato {
            CoverageState::Covered => 2,
            CoverageState::Undetermined(_) => 1,
            CoverageState::NotCovered(_) => 0,
        }
    }
    if peso(altro) > peso(uno) { altro } else { uno }
}

/// Lo stato in un istante, se la copertura lo comprende.
fn stato_in(copertura: &Coverage, istante: Timestamp) -> Option<CoverageState> {
    copertura
        .intervals()
        .iter()
        .find(|tratto| tratto.from <= istante && istante < tratto.to)
        .map(|tratto| tratto.state)
}

/// Che cosa una sovrapposizione può cambiare.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sovrapposizione {
    /// Tutto il tratto, qualunque stato avesse.
    Sempre,
    /// Soltanto ciò che era coperto.
    SoloCoperto,
}

/// Mette `stato` sul tratto `[da, a)`, spezzando i tratti che lo toccano.
fn sovrapponi(
    copertura: &Coverage,
    da: Timestamp,
    a: Timestamp,
    stato: CoverageState,
    modo: Sovrapposizione,
) -> Coverage {
    if a <= da {
        return copertura.clone();
    }
    let mut tratti = Vec::with_capacity(copertura.intervals().len() + 2);
    for tratto in copertura.intervals() {
        let dentro_da = tratto.from.max(da);
        let dentro_a = tratto.to.min(a);
        let cambia = dentro_da < dentro_a
            && (modo == Sovrapposizione::Sempre || tratto.state == CoverageState::Covered);
        if !cambia {
            tratti.push(*tratto);
            continue;
        }
        tratti.push(CoverageInterval {
            from: tratto.from,
            to: dentro_da,
            state: tratto.state,
        });
        tratti.push(CoverageInterval {
            from: dentro_da,
            to: dentro_a,
            state: stato,
        });
        tratti.push(CoverageInterval {
            from: dentro_a,
            to: tratto.to,
            state: tratto.state,
        });
    }
    costruisci(tratti)
}

/// Una copertura senza tratti.
const fn vuota() -> Coverage {
    Coverage::empty()
}

/// Costruisce una copertura da tratti che questo modulo ha reso contigui.
///
/// # Invariante
///
/// Ogni chiamante produce tratti in ordine e contigui: `Coverage::build` li
/// rifiuterebbe solo se una regola di questo modulo fosse sbagliata. In quel
/// caso non si mostra una copertura inventata: si mostra **un solo tratto non
/// determinabile** — mai uno coperto.
fn costruisci(tratti: Vec<CoverageInterval>) -> Coverage {
    let (inizio, fine) = (
        tratti.first().map(|tratto| tratto.from),
        tratti.last().map(|tratto| tratto.to),
    );
    Coverage::build(tratti).unwrap_or_else(|| {
        tracing::error!("copertura non contigua: si dichiara non determinabile");
        match (inizio, fine) {
            (Some(da), Some(a)) => Coverage::single(
                da,
                a,
                CoverageState::Undetermined(UndeterminedReason::NoFactYet),
            ),
            _ => Coverage::empty(),
        }
    })
}

/// La copertura di un monitoraggio e delle sue fonti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringCoverage {
    /// Il programma e il collegamento, sulla finestra del monitoraggio.
    pub overall: Coverage,
    /// Ciascuna fonte del monitoraggio, con il suo nome.
    pub sources: Vec<(SourceId, String, Coverage)>,
}

/// La copertura di una fonte su una finestra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCoverage {
    /// La fonte.
    pub source_id: SourceId,
    /// Il suo nome, come l'operatore la conosce.
    pub name: String,
    /// I tratti.
    pub coverage: Coverage,
}

/// Quante verifiche di salute per fonte si leggono, al più.
///
/// Una verifica si fa a mano o all'avvio: centinaia sono anni di lavoro. Il
/// tetto rende la lettura limitata anche su un archivio che ne avesse di più.
pub const MAX_CHECKS_PER_SOURCE: u32 = 500;

// ------------------------------------------------- raccolta dei fatti
//
// Le funzioni qui sotto leggono i fatti dall'archivio che ricevono e li passano
// alla derivazione. Nessuna scrive: la copertura è una lettura, e si fa
// sull'archivio del servizio che la mostra, senza aprirne un altro.
/// I fatti di un monitoraggio, se è stato avviato.
fn fatti(database: &Database, session_id: SessionId) -> ServiceResult<Option<MonitoringFacts>> {
    let sessione = database.session(session_id)?;
    let Some(started_at) = sessione.started_at else {
        return Ok(None);
    };
    let facts = database
        .session_reception_facts(session_id)?
        .into_iter()
        .filter_map(|fatto| {
            LifecycleFact::from_event(fatto.kind, fatto.received_at, fatto.source_id)
        })
        .collect();
    Ok(Some(MonitoringFacts {
        started_at,
        ended_at: sessione.ended_at,
        facts,
        interruption: database.interruption_span(session_id)?,
        pauses: database
            .acquisition_pauses(session_id)?
            .into_iter()
            .map(|pausa| (pausa.paused_at, pausa.resumed_at))
            .collect(),
    }))
}

/// Le verifiche di accessibilità di una fonte.
fn verifiche(database: &Database, source_id: SourceId) -> ServiceResult<Vec<AccessCheck>> {
    Ok(database
        .source_health_checks(source_id, MAX_CHECKS_PER_SOURCE)?
        .into_iter()
        .map(|verifica| AccessCheck {
            at: verifica.observed_at,
            accessible: accessibilita(verifica.outcome),
        })
        .collect())
}

/// La copertura di un monitoraggio e delle sue fonti, alla fotografia
/// `until`.
///
/// # Errori
///
/// Restituisce un errore se una lettura non riesce.
pub fn for_monitoring(
    database: &Database,
    session_id: SessionId,
    until: Timestamp,
) -> ServiceResult<MonitoringCoverage> {
    let Some(fatti) = fatti(database, session_id)? else {
        return Ok(MonitoringCoverage {
            overall: Coverage::empty(),
            sources: Vec::new(),
        });
    };
    let overall = monitoring_coverage(&fatti, until);
    let nomi = nomi(database)?;
    let mut sources = Vec::new();
    for source_id in database.session_source_ids(session_id)? {
        let copertura = source_in_monitoring(
            &overall,
            source_id,
            &fatti.facts,
            &verifiche(database, source_id)?,
        );
        let nome = nomi.iter().find(|(id, _, _)| *id == source_id).map_or_else(
            || format!("fonte {}", source_id.get()),
            |(_, nome, _)| nome.clone(),
        );
        sources.push((source_id, nome, copertura));
    }
    Ok(MonitoringCoverage { overall, sources })
}

/// La copertura di ogni fonte configurata sulla finestra `[from, until)`.
///
/// # Errori
///
/// Restituisce un errore se una lettura non riesce.
pub fn for_sources(
    database: &Database,
    from: Timestamp,
    until: Timestamp,
) -> ServiceResult<Vec<SourceCoverage>> {
    // I monitoraggi che toccano la finestra, con i fatti letti una volta.
    let mut monitoraggi: Vec<(Vec<SourceId>, MonitoringFacts, Coverage)> = Vec::new();
    for sessione in database.sessions()? {
        let Some(avvio) = sessione.started_at else {
            continue;
        };
        if avvio >= until || sessione.ended_at.is_some_and(|fine| fine <= from) {
            continue;
        }
        let Some(fatti) = fatti(database, sessione.id)? else {
            continue;
        };
        let copertura = monitoring_coverage(&fatti, until);
        monitoraggi.push((database.session_source_ids(sessione.id)?, fatti, copertura));
    }

    let mut risultato = Vec::new();
    for (source_id, name, configured_at) in nomi(database)? {
        let verifiche = verifiche(database, source_id)?;
        let parti: Vec<Coverage> = monitoraggi
            .iter()
            .filter(|(fonti, _, _)| fonti.contains(&source_id))
            .map(|(_, fatti, copertura)| {
                source_in_monitoring(copertura, source_id, &fatti.facts, &verifiche)
            })
            .collect();
        risultato.push(SourceCoverage {
            source_id,
            name,
            coverage: source_coverage(configured_at, &parti, from, until),
        });
    }
    Ok(risultato)
}

/// Le fonti configurate: identificativo, nome e istante di configurazione.
fn nomi(database: &Database) -> ServiceResult<Vec<(SourceId, String, Timestamp)>> {
    Ok(database
        .sources()?
        .into_iter()
        .map(|fonte| {
            (
                fonte.id,
                String::from(fonte.display_name.as_str()),
                fonte.created_at,
            )
        })
        .collect())
}

/// Che cosa una verifica dice dell'accessibilità della fonte.
///
/// Una verifica **non riuscita** non dice nulla: né che la fonte ci fosse, né
/// che mancasse (SRC-HEALTH).
const fn accessibilita(esito: HealthCheckOutcome) -> Option<bool> {
    match esito {
        HealthCheckOutcome::Reachable => Some(true),
        HealthCheckOutcome::HistoryUnreadable | HealthCheckOutcome::NotAccessible => Some(false),
        HealthCheckOutcome::CheckFailed => None,
    }
}

// ------------------------------------------------------------- a parole
//
// UNA VOCE SOLA: le frasi della copertura sono le stesse sullo schermo e nei
// documenti, e si compongono qui. Due composizioni divergono alla prima
// correzione, e l'atto direbbe una cosa diversa dalla schermata.

/// Quanti tratti si dicono a parole, al più: gli altri si contano.
pub const MAX_GAPS_IN_WORDS: usize = 5;

/// La copertura di una fonte, come entra in un documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageLine {
    /// Il nome della fonte, come l'operatore la conosce.
    pub source: String,
    /// I tratti.
    pub coverage: Coverage,
}

/// Una durata, in parole: giorni, ore, minuti.
#[must_use]
pub fn duration_in_words(millis: i64) -> String {
    let minuti = millis.max(0) / 60_000;
    let (giorni, ore, minuti) = (minuti / 1_440, (minuti % 1_440) / 60, minuti % 60);
    let mut parti = Vec::new();
    for (quanti, uno, tanti) in [
        (giorni, "giorno", "giorni"),
        (ore, "ora", "ore"),
        (minuti, "minuto", "minuti"),
    ] {
        match quanti {
            0 => {}
            1 => parti.push(format!("1 {uno}")),
            _ => parti.push(format!("{quanti} {tanti}")),
        }
    }
    if parti.is_empty() {
        return String::from("meno di un minuto");
    }
    parti.join(", ")
}

/// I tratti non coperti o non determinabili, a parole, con il perché: la
/// forma dei **documenti**, in UTC.
#[must_use]
pub fn gaps_in_words(copertura: &Coverage) -> String {
    gaps_in_words_with(copertura, Timestamp::to_readable_utc)
}

/// La stessa frase **per lo schermo**: l'ora dell'orologio della postazione,
/// con l'UTC accanto (ADR-0136). Gli estremi sono gli stessi dei documenti, e
/// l'UTC tra parentesi è lo stesso numero che la relazione riporta.
#[must_use]
pub fn gaps_in_words_on_screen(copertura: &Coverage) -> String {
    gaps_in_words_with(copertura, Timestamp::to_readable_local)
}

fn gaps_in_words_with(copertura: &Coverage, scrivi: fn(Timestamp) -> String) -> String {
    if copertura.intervals().is_empty() {
        return String::from("Nessun periodo da mostrare.");
    }
    let vuoti: Vec<String> = copertura
        .gaps()
        .map(|tratto| {
            let stato = tratto.state.label();
            let mut lettere = stato.chars();
            let stato: String = lettere.next().map_or_else(String::new, |prima| {
                prima.to_uppercase().chain(lettere).collect()
            });
            // UN TRATTO SOTTO IL SECONDO NON SI SCRIVE «DAL X AL X»
            // (INSTALLED-APP-E2E-01, E2E01-20): gli estremi si scrivono al
            // secondo, e un periodo di pochi millisecondi si leggeva come un
            // periodo di zero secondi. Resta, perché è vero, e dice la sua misura.
            if tratto
                .to
                .as_millis()
                .saturating_sub(tratto.from.as_millis())
                < 1_000
            {
                return format!(
                    "{stato} per meno di un secondo, il {}: {}.",
                    scrivi(tratto.from),
                    tratto.state.reason()
                );
            }
            format!(
                "{stato} dal {} al {}: {}.",
                scrivi(tratto.from),
                scrivi(tratto.to),
                tratto.state.reason()
            )
        })
        .collect();
    if vuoti.is_empty() {
        return String::from("Coperta per tutto il periodo.");
    }
    let mut frase = vuoti
        .iter()
        .take(MAX_GAPS_IN_WORDS)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    if vuoti.len() > MAX_GAPS_IN_WORDS {
        frase.push_str(&format!(
            " E altri {} tratti non coperti o non determinabili.",
            vuoti.len() - MAX_GAPS_IN_WORDS
        ));
    }
    frase
}

/// Quanto di ciascuno stato, sulla finestra: soltanto gli stati presenti.
#[must_use]
pub fn totals_in_words(copertura: &Coverage) -> String {
    if copertura.intervals().is_empty() {
        return String::from("Nessuna finestra da misurare.");
    }
    let (coperto, non_coperto, non_si_sa) = copertura.totals();
    let mut parti = Vec::new();
    for (quanto, stato) in [
        (coperto, "coperto"),
        (non_si_sa, "non determinabile"),
        (non_coperto, "non coperto"),
    ] {
        if quanto > 0 {
            parti.push(format!("{stato} per {}", duration_in_words(quanto)));
        }
    }
    let mut frase = parti.join(", ");
    if let Some(prima) = frase.get(..1).map(str::to_uppercase) {
        frase.replace_range(..1, &prima);
    }
    frase.push('.');
    frase
}

/// Gli intervalli **recuperati dopo** di una fonte, dentro `[from, until)`
/// (PR-08, ADR-0124): quelli delle operazioni di recupero che hanno un
/// intervallo, ristretti alla finestra, in ordine e fusi dove si toccano.
///
/// # Non sono copertura
///
/// Nessuno guardava: la copertura resta a tre stati, e questi intervalli si
/// disegnano come uno strato a parte. Farli diventare «coperti» direbbe che si
/// ascoltava dove si è soltanto letto dopo.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn recovered_spans(
    database: &Database,
    source_id: SourceId,
    from: Timestamp,
    until: Timestamp,
) -> ServiceResult<Vec<(Timestamp, Timestamp)>> {
    let mut tratti: Vec<(Timestamp, Timestamp)> = database
        .source_recovery_operations(source_id)?
        .into_iter()
        .filter_map(|operazione| operazione.interval)
        .map(|(da, a)| (da.max(from), a.min(until)))
        .filter(|(da, a)| da < a)
        .collect();
    tratti.sort();
    let mut fusi: Vec<(Timestamp, Timestamp)> = Vec::with_capacity(tratti.len());
    for (da, a) in tratti {
        match fusi.last_mut() {
            Some(ultimo) if da <= ultimo.1 => ultimo.1 = ultimo.1.max(a),
            _ => fusi.push((da, a)),
        }
    }
    Ok(fusi)
}

/// Gli intervalli recuperati dopo, a parole. Vuota quando non ce ne sono.
/// Forma dei documenti, in UTC.
#[must_use]
pub fn recovered_in_words(tratti: &[(Timestamp, Timestamp)]) -> String {
    recovered_in_words_with(tratti, Timestamp::to_readable_utc)
}

/// La stessa frase per lo schermo, in ora locale con l'UTC accanto (ADR-0136).
#[must_use]
pub fn recovered_in_words_on_screen(tratti: &[(Timestamp, Timestamp)]) -> String {
    recovered_in_words_with(tratti, Timestamp::to_readable_local)
}

fn recovered_in_words_with(
    tratti: &[(Timestamp, Timestamp)],
    scrivi: fn(Timestamp) -> String,
) -> String {
    tratti
        .iter()
        .map(|(da, a)| {
            format!(
                "Recuperato dopo dal {} al {}: letto nella cronologia, non guardato allora.",
                scrivi(*da),
                scrivi(*a)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use lisi_core::model::coverage::{
        Coverage, CoverageState, NotCoveredReason, UndeterminedReason,
    };
    use lisi_core::{SourceId, Timestamp};

    use super::{
        AccessCheck, LifecycleFact, MonitoringFacts, monitoring_coverage, source_coverage,
        source_in_monitoring,
    };

    /// Il sorgente del modulo, per la guardia sull'orologio.
    const THIS_MODULE: &str = include_str!("coverage.rs");

    /// **Un tratto sotto il secondo non si scrive «dal X al X»** (E2E01-20):
    /// si dice la sua misura, e il tratto resta.
    #[test]
    fn un_tratto_sotto_il_secondo_si_dice_come_tale() {
        let inizio = Timestamp::from_millis(1_790_294_400_000);
        let breve = Timestamp::from_millis(1_790_294_400_300);
        let fine = Timestamp::from_millis(1_790_298_000_000);
        let Some(copertura) = Coverage::build(vec![
            lisi_core::model::coverage::CoverageInterval {
                from: inizio,
                to: breve,
                state: CoverageState::NotCovered(NotCoveredReason::NotYetConfigured),
            },
            lisi_core::model::coverage::CoverageInterval {
                from: breve,
                to: fine,
                state: CoverageState::Covered,
            },
        ]) else {
            panic!("tratti contigui");
        };
        let frase = super::gaps_in_words(&copertura);
        assert!(frase.contains("per meno di un secondo, il"), "{frase}");
        assert!(
            !frase.contains(&format!(
                "dal {} al {}",
                inizio.to_readable_utc(),
                breve.to_readable_utc()
            )),
            "{frase}"
        );
    }

    const ORA: i64 = 3_600_000;

    fn t(ore: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + ore * ORA)
    }

    fn ricevuto(ore: i64) -> LifecycleFact {
        LifecycleFact::Received {
            at: t(ore),
            source: Some(SourceId::new(1)),
        }
    }

    fn monitoraggio(fatti: Vec<LifecycleFact>, fine: Option<i64>) -> MonitoringFacts {
        MonitoringFacts {
            started_at: t(0),
            ended_at: fine.map(t),
            facts: fatti,
            interruption: None,
            pauses: Vec::new(),
        }
    }

    /// Lo stato in un'ora data.
    fn stato(copertura: &Coverage, ore: i64) -> Option<CoverageState> {
        copertura
            .intervals()
            .iter()
            .find(|tratto| tratto.from <= t(ore) && t(ore) < tratto.to)
            .map(|tratto| tratto.state)
    }

    fn contigua(copertura: &Coverage) {
        for coppia in copertura.intervals().windows(2) {
            assert_eq!(coppia[0].to, coppia[1].from, "tratti non contigui");
        }
    }

    /// **Fra due fatti senza rotture, coperto; dopo l'ultimo, non
    /// determinabile** (regole 1, 5, 6).
    #[test]
    fn fra_i_fatti_si_guardava_dopo_l_ultimo_non_si_sa() {
        let copertura = monitoring_coverage(
            &monitoraggio(vec![ricevuto(2), ricevuto(5)], Some(8)),
            t(10),
        );
        contigua(&copertura);
        assert_eq!(copertura.start(), Some(t(0)));
        assert_eq!(copertura.end(), Some(t(8)));
        assert_eq!(stato(&copertura, 1), Some(CoverageState::Covered));
        assert_eq!(stato(&copertura, 4), Some(CoverageState::Covered));
        assert_eq!(
            stato(&copertura, 6),
            Some(CoverageState::Undetermined(
                UndeterminedReason::AfterLastFact
            )),
            "dopo l'ultimo fatto non si sa: colmarlo sarebbe una stima"
        );
    }

    /// **Il periodo di pausa è «non coperto», con il suo motivo, anche fra due
    /// fatti; una pausa aperta arriva alla fine** (PAUSE-01, ADR-0172,
    /// criterio 4; prova negativa: la pausa tolta dalla copertura → rossa).
    #[test]
    fn la_pausa_e_un_buco_dichiarato() {
        let pausa = CoverageState::NotCovered(NotCoveredReason::Paused);
        let copertura = monitoring_coverage(
            &MonitoringFacts {
                pauses: vec![(t(2), Some(t(4))), (t(6), None)],
                ..monitoraggio(vec![ricevuto(1), ricevuto(5), ricevuto(7)], Some(8))
            },
            t(10),
        );
        contigua(&copertura);
        assert_eq!(stato(&copertura, 1), Some(CoverageState::Covered));
        assert_eq!(
            stato(&copertura, 3),
            Some(pausa),
            "fra due fatti, ma in pausa"
        );
        assert_eq!(stato(&copertura, 4), Some(CoverageState::Covered));
        assert_eq!(stato(&copertura, 7), Some(pausa), "la pausa aperta");
        assert_eq!(copertura.end(), Some(t(8)), "non oltre la fine");
        assert_eq!(
            pausa.reason(),
            "l'acquisizione era in pausa per decisione dell'operatore"
        );
    }

    /// **Un ritorno in linea dice che subito prima il collegamento non c'era**
    /// (regola 2).
    #[test]
    fn un_ritorno_in_linea_rende_non_determinabile_il_tratto_prima() {
        let copertura = monitoring_coverage(
            &monitoraggio(
                vec![
                    ricevuto(1),
                    LifecycleFact::ConnectionRestored(t(4)),
                    ricevuto(6),
                ],
                Some(7),
            ),
            t(10),
        );
        assert_eq!(stato(&copertura, 0), Some(CoverageState::Covered));
        assert_eq!(
            stato(&copertura, 2),
            Some(CoverageState::Undetermined(
                UndeterminedReason::ConnectionRestored
            ))
        );
        assert_eq!(stato(&copertura, 5), Some(CoverageState::Covered));
    }

    /// **Una perdita del collegamento non è coperta fino al ritorno** (regola
    /// 3).
    #[test]
    fn dalla_perdita_al_ritorno_non_si_sa() {
        let copertura = monitoring_coverage(
            &monitoraggio(
                vec![
                    ricevuto(1),
                    LifecycleFact::ConnectionLost(t(2)),
                    LifecycleFact::ConnectionRestored(t(5)),
                    ricevuto(6),
                ],
                Some(7),
            ),
            t(10),
        );
        assert_eq!(stato(&copertura, 1), Some(CoverageState::Covered));
        assert_eq!(
            stato(&copertura, 3),
            Some(CoverageState::Undetermined(
                UndeterminedReason::ConnectionLost
            ))
        );
        assert_eq!(stato(&copertura, 5), Some(CoverageState::Covered));
    }

    /// **Senza fatti, tutto non determinabile; il primo fatto un ritorno in
    /// linea, l'inizio non determinabile** (regola 5).
    #[test]
    fn senza_fatti_non_si_sa_nulla() {
        let vuoto = monitoring_coverage(&monitoraggio(Vec::new(), Some(5)), t(10));
        assert_eq!(vuoto.intervals().len(), 1);
        assert_eq!(
            stato(&vuoto, 2),
            Some(CoverageState::Undetermined(UndeterminedReason::NoFactYet))
        );

        let copertura = monitoring_coverage(
            &monitoraggio(
                vec![LifecycleFact::ConnectionRestored(t(3)), ricevuto(4)],
                Some(5),
            ),
            t(10),
        );
        assert_eq!(
            stato(&copertura, 1),
            Some(CoverageState::Undetermined(UndeterminedReason::NoFactYet))
        );
        assert_eq!(stato(&copertura, 3), Some(CoverageState::Covered));
    }

    /// **Un'interruzione registrata è un vuoto, non una copertura**, anche se
    /// i fatti intorno direbbero altro.
    #[test]
    fn un_arresto_anomalo_produce_un_vuoto() {
        let mut fatti = monitoraggio(
            vec![
                ricevuto(1),
                ricevuto(2),
                LifecycleFact::ConnectionRestored(t(6)),
                ricevuto(7),
            ],
            Some(8),
        );
        fatti.interruption = Some((t(2), t(5)));
        let copertura = monitoring_coverage(&fatti, t(10));
        for ora in [2, 3, 4] {
            assert_eq!(
                stato(&copertura, ora),
                Some(CoverageState::Undetermined(
                    UndeterminedReason::ProgramStopped
                )),
                "ora {ora}"
            );
        }
        assert_ne!(stato(&copertura, 5), Some(CoverageState::Covered));
        contigua(&copertura);
    }

    /// **Una fonte trovata non accessibile non è coperta fra le prove che la
    /// circondano** (regola 7).
    #[test]
    fn una_fonte_non_accessibile_non_si_dice_coperta() {
        let fatti = vec![ricevuto(1), ricevuto(2), ricevuto(6), ricevuto(7)];
        let generale = monitoring_coverage(&monitoraggio(fatti.clone(), Some(8)), t(10));
        let verifiche = [AccessCheck {
            at: t(4),
            accessible: Some(false),
        }];
        let fonte = source_in_monitoring(&generale, SourceId::new(1), &fatti, &verifiche);
        assert_eq!(stato(&fonte, 1), Some(CoverageState::Covered));
        for ora in [2, 3, 4, 5] {
            assert_eq!(
                stato(&fonte, ora),
                Some(CoverageState::Undetermined(
                    UndeterminedReason::SourceNotAccessible
                )),
                "ora {ora}"
            );
        }
        assert_eq!(stato(&fonte, 6), Some(CoverageState::Covered));

        // Una verifica NON RIUSCITA non dice nulla.
        let fallita = [AccessCheck {
            at: t(4),
            accessible: None,
        }];
        assert_eq!(
            source_in_monitoring(&generale, SourceId::new(1), &fatti, &fallita),
            generale
        );
    }

    /// **Fuori da ogni monitoraggio, non coperto; prima della configurazione,
    /// «non ancora configurata»; più monitoraggi, il più informativo** (regole
    /// 8 e 9). Controllo negativo 1: un periodo in cui il monitoraggio era
    /// fermo non si dice coperto.
    #[test]
    fn fuori_dai_monitoraggi_non_si_guardava() {
        let primo = monitoring_coverage(
            &monitoraggio(vec![ricevuto(3), ricevuto(4)], Some(5)),
            t(24),
        );
        let copertura = source_coverage(t(-10), &[primo], t(-24), t(24));
        contigua(&copertura);
        assert_eq!(
            stato(&copertura, -20),
            Some(CoverageState::NotCovered(
                NotCoveredReason::NotYetConfigured
            ))
        );
        assert_eq!(
            stato(&copertura, -5),
            Some(CoverageState::NotCovered(NotCoveredReason::NoMonitoring))
        );
        assert_eq!(stato(&copertura, 3), Some(CoverageState::Covered));
        assert_eq!(
            stato(&copertura, 12),
            Some(CoverageState::NotCovered(NotCoveredReason::NoMonitoring)),
            "a monitoraggio fermo non si guardava"
        );

        let secondo = monitoring_coverage(
            &MonitoringFacts {
                started_at: t(4),
                ended_at: Some(t(6)),
                facts: vec![ricevuto(5)],
                interruption: None,
                pauses: Vec::new(),
            },
            t(24),
        );
        let primo = monitoring_coverage(
            &monitoraggio(vec![ricevuto(3), ricevuto(4)], Some(5)),
            t(24),
        );
        let insieme = source_coverage(t(-10), &[primo, secondo], t(-24), t(24));
        assert_eq!(
            stato(&insieme, 4),
            Some(CoverageState::Covered),
            "il secondo monitoraggio copriva l'ora in cui il primo non sapeva"
        );
    }

    /// **La derivazione è pura**: stessi fatti, stesso istante, stessa
    /// copertura; e il modulo non legge l'orologio (controllo negativo 4).
    #[test]
    fn la_derivazione_e_pura() {
        let fatti = monitoraggio(
            vec![
                ricevuto(1),
                LifecycleFact::ConnectionLost(t(2)),
                ricevuto(3),
            ],
            None,
        );
        assert_eq!(
            monitoring_coverage(&fatti, t(6)),
            monitoring_coverage(&fatti, t(6))
        );
        // Un monitoraggio in corso finisce alla fotografia, non all'orologio.
        assert_eq!(monitoring_coverage(&fatti, t(6)).end(), Some(t(6)));

        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for vietato in ["now(", "SystemTime", "Instant::"] {
            assert!(
                !produzione.contains(vietato),
                "«{vietato}» nella derivazione"
            );
        }
    }

    /// **Un contenuto recuperato non crea copertura**: la derivazione non
    /// conosce l'istante di pubblicazione, soltanto quello di arrivo.
    #[test]
    fn la_derivazione_non_conosce_la_pubblicazione() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for vietato in ["published_at", "remote_timestamp", "AcquisitionOrigin"] {
            assert!(
                !produzione.contains(vietato),
                "«{vietato}»: la copertura viene da ciò che è arrivato, non da ciò che è stato pubblicato"
            );
        }
    }

    /// **Dall'archivio vero alla copertura**: le letture nuove portano i fatti
    /// giusti, e consultare la copertura non scrive nulla.
    #[test]
    fn dall_archivio_alla_copertura_senza_scrivere() {
        use lisi_core::model::acquisition::{IdempotencyKey, InboxEventKind, NewInboxEntry};
        use lisi_core::model::interruption::{GapStart, Interruption};
        use lisi_core::model::{NewSession, NewSource, SessionDuration, SessionState, SourceKind};
        use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let (Ok(attore), Ok(identificativo), Ok(nome), Ok(etichetta)) = (
            Actor::try_new("operatore.prova"),
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Monitoraggio di prova"),
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
        let Ok(sessione) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: attore,
                duration: SessionDuration::Preset { seconds: 36_000 },
                source_ids: vec![fonte],
            },
            t(0),
        ) else {
            panic!("la sessione deve crearsi");
        };
        let Ok(()) = database.update_session_state(sessione, SessionState::Running, t(0)) else {
            panic!("la sessione deve avviarsi");
        };
        for (ora, genere, di_fonte) in [
            (1, InboxEventKind::NewMessage, true),
            (2, InboxEventKind::NewMessage, true),
            (6, InboxEventKind::ConnectionEstablished, false),
            (7, InboxEventKind::NewMessage, true),
        ] {
            let origine = if di_fonte { Some(fonte) } else { None };
            let chiave =
                IdempotencyKey::derive(sessione, origine, genere, None, Some(&ora.to_string()));
            let Ok(_) = database.enqueue_inbox(&NewInboxEntry {
                session_id: sessione,
                source_id: origine,
                event_kind: genere,
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
        let Ok(_) = database.record_interruption(
            sessione,
            &Interruption::new(t(5), GapStart::LastContent(t(2))),
        ) else {
            panic!("l'interruzione deve registrarsi");
        };

        let prima = database.total_changes();
        let Ok(copertura) = super::for_monitoring(&database, sessione, t(9)) else {
            panic!("la copertura deve comporsi");
        };
        let Ok(fonti) = super::for_sources(&database, t(-24), t(9)) else {
            panic!("la copertura delle fonti deve comporsi");
        };
        assert_eq!(
            database.total_changes(),
            prima,
            "consultare la copertura non scrive"
        );

        assert_eq!(stato(&copertura.overall, 1), Some(CoverageState::Covered));
        assert_eq!(
            stato(&copertura.overall, 3),
            Some(CoverageState::Undetermined(
                UndeterminedReason::ProgramStopped
            ))
        );
        assert_eq!(stato(&copertura.overall, 6), Some(CoverageState::Covered));
        assert_eq!(copertura.sources.len(), 1);
        assert_eq!(copertura.sources[0].1, "Canale di prova");

        assert_eq!(fonti.len(), 1);
        assert_eq!(
            stato(&fonti[0].coverage, -1),
            Some(CoverageState::NotCovered(NotCoveredReason::NoMonitoring))
        );
        assert_eq!(
            stato(&fonti[0].coverage, -10),
            Some(CoverageState::NotCovered(
                NotCoveredReason::NotYetConfigured
            ))
        );
        assert_eq!(stato(&fonti[0].coverage, 1), Some(CoverageState::Covered));
    }

    /// Un generatore deterministico (congruenziale lineare): le prove di
    /// proprietà devono ripetersi uguali, e il caso che fallisce si ritrova.
    struct Sequenza(u64);

    impl Sequenza {
        fn prossimo(&mut self, limite: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % limite.max(1)
        }
    }

    /// **Prova di proprietà (PR-15): la copertura di un monitoraggio è una
    /// partizione della sua finestra, e un periodo fermo non è mai coperto.**
    ///
    /// Su cinquecento sequenze di fatti generate: i tratti sono contigui, non
    /// vuoti, cominciano all'avvio e finiscono alla fine; nessun tratto coperto
    /// cade fra un collegamento perso e il suo ritorno, dentro l'interruzione
    /// registrata, o dopo l'ultimo fatto; a parità di fatti la copertura è la
    /// stessa.
    #[test]
    fn la_copertura_e_una_partizione_e_un_periodo_fermo_non_e_coperto() {
        let mut caso = Sequenza(20_261_001);
        for numero in 0..500 {
            let quanti = caso.prossimo(12);
            let mut fatti = Vec::new();
            for _ in 0..quanti {
                let ora = i64::try_from(caso.prossimo(48)).unwrap_or_default();
                fatti.push(match caso.prossimo(4) {
                    0 => LifecycleFact::ConnectionLost(t(ora)),
                    1 => LifecycleFact::ConnectionRestored(t(ora)),
                    2 => LifecycleFact::ConnectorFailed(t(ora)),
                    _ => ricevuto(ora),
                });
            }
            let fine = (caso.prossimo(3) == 0)
                .then(|| i64::try_from(caso.prossimo(48)).unwrap_or_default() + 1);
            let interruzione = (caso.prossimo(3) == 0).then(|| {
                let da = i64::try_from(caso.prossimo(40)).unwrap_or_default();
                (
                    t(da),
                    t(da + 1 + i64::try_from(caso.prossimo(6)).unwrap_or_default()),
                )
            });
            let fatti_del_caso = MonitoringFacts {
                interruption: interruzione,
                ..monitoraggio(fatti.clone(), fine)
            };
            let until = t(48);
            let copertura = monitoring_coverage(&fatti_del_caso, until);
            assert_eq!(
                copertura,
                monitoring_coverage(&fatti_del_caso, until),
                "caso {numero}: la stessa copertura a parità di fatti"
            );

            let fine_finestra = fine.map_or(until, |ore| t(ore).min(until));
            let tratti = copertura.intervals();
            assert!(
                !tratti.is_empty(),
                "caso {numero}: una finestra non vuota ha tratti"
            );
            assert_eq!(tratti[0].from, t(0), "caso {numero}: comincia all'avvio");
            assert_eq!(
                tratti[tratti.len() - 1].to,
                fine_finestra,
                "caso {numero}: finisce alla fine"
            );
            for coppia in tratti.windows(2) {
                assert_eq!(
                    coppia[0].to, coppia[1].from,
                    "caso {numero}: tratti contigui"
                );
            }
            for tratto in tratti {
                assert!(tratto.from < tratto.to, "caso {numero}: un tratto vuoto");
            }

            // I periodi fermi: dal collegamento perso (o da un guasto) al fatto
            // successivo, l'interruzione registrata, e il dopo dell'ultimo fatto.
            // Il fatto successivo, non il solo ritorno: un messaggio ricevuto
            // prova che il programma è di nuovo vivo e collegato (ADR-0121,
            // regola 1), e la prima stesura di questa prova lo aveva dimenticato.
            let mut ordinati: Vec<LifecycleFact> = fatti
                .iter()
                .copied()
                .filter(|fatto| fatto.at() >= t(0) && fatto.at() <= fine_finestra)
                .collect();
            ordinati.sort_by_key(|fatto| fatto.at());
            let mut fermi: Vec<(Timestamp, Timestamp)> = Vec::new();
            for (posizione, fatto) in ordinati.iter().enumerate() {
                if matches!(
                    fatto,
                    LifecycleFact::ConnectionLost(_) | LifecycleFact::ConnectorFailed(_)
                ) {
                    let ritorno = ordinati[posizione + 1..]
                        .first()
                        .map_or(fine_finestra, |dopo| dopo.at());
                    fermi.push((fatto.at(), ritorno));
                }
            }
            if let Some(ultimo) = ordinati.last() {
                fermi.push((ultimo.at(), fine_finestra));
            } else {
                fermi.push((t(0), fine_finestra));
            }
            if let Some((da, a)) = interruzione {
                fermi.push((da, a));
            }
            for tratto in tratti
                .iter()
                .filter(|tratto| tratto.state == CoverageState::Covered)
            {
                // Un periodo di durata zero — la perdita e il fatto successivo
                // nello stesso istante — non ha un dentro da coprire.
                for (da, a) in fermi.iter().filter(|(da, a)| da < a) {
                    assert!(
                        tratto.to <= *da || tratto.from >= *a,
                        "caso {numero}: un tratto coperto ({:?}–{:?}) cade in un periodo \
                         fermo ({da:?}–{a:?})",
                        tratto.from,
                        tratto.to
                    );
                }
            }
        }
    }
}

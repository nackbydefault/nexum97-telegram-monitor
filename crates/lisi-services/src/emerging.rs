//! Legge dall'archivio le occorrenze di un periodo e le fa confrontare.
//!
//! # Perché questo modulo esiste separato da [`crate::trend`]
//!
//! Perché `trend` **non conosce l'archivio**, e non deve: è la garanzia che il
//! confronto non possa scrivere nulla, ed è la stessa forma di LAB-01, del
//! replay e del riscontro sui dizionari. Qualcuno però deve pur leggere, e
//! quel qualcuno è questo modulo — che legge e nient'altro: non conta, non
//! confronta, non decide che cosa emerga.
//!
//! È la separazione fra `diagnostics`, che compone, e `live_diagnostics`, che
//! misura.
//!
//! # Perché si rifiuta invece di troncare
//!
//! Un elenco troncato mostra meno righe; un **conteggio** troncato mostra
//! numeri falsi. Se il periodo contiene più osservazioni del limite, il
//! confronto non si esegue e lo dichiara.

use lisi_core::Timestamp;
use lisi_storage::Database;

use crate::error::ServiceResult;
use crate::spike::{BucketedWindow, SpikeGap, SpikeOutcome, SpikeReport, detect};
use crate::trend::{
    ComparisonWindows, Observation, ObservationKind, TrendGap, TrendOutcome, TrendReport, analyse,
};

/// Quante occorrenze al massimo entrano in un confronto.
///
/// # Perché un limite, e perché questo
///
/// Perché la lettura è sincrona e tiene ferma l'interfaccia: su un archivio
/// molto grande la finestra resterebbe bloccata senza dire nulla.
///
/// **Duecentomila** non è una misura: è la soglia oltre la quale si preferisce
/// dire «non l'ho fatto» invece di farlo male. Due settimane di monitoraggio
/// d'ufficio restano ampiamente al di sotto; un archivio che la supera ha
/// bisogno di un'analisi che lavori a lotti, e questa non lo è.
pub const MAX_OBSERVATIONS: u32 = 200_000;

/// Traduce il genere conservato dall'archivio.
///
/// `None` per un genere che questa versione non conosce: una riga incompresa si
/// scarta invece di finire in un mucchio generico, dove gonfierebbe il conteggio
/// di qualcosa che non è.
fn genere(raw: &str) -> Option<ObservationKind> {
    ObservationKind::all()
        .into_iter()
        .find(|kind| kind.as_str() == raw)
}

/// Confronta il periodo recente con quello precedente, della stessa durata.
///
/// # Che cosa legge
///
/// Le occorrenze pubblicate nell'intero arco delle due finestre, in una
/// lettura sola, e il primo istante di pubblicazione dell'archivio — che è ciò
/// che impedisce di confrontare con un periodo in cui NEXUM non guardava.
///
/// # Non scrive nulla
///
/// Chiedersi che cosa stia comparendo non è un atto di cui qualcuno risponda.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn compose(
    database: &Database,
    windows: ComparisonWindows,
    limit: u32,
) -> ServiceResult<TrendReport> {
    let righe =
        database.observations_between(windows.baseline_start(), windows.recent_end(), limit)?;

    if righe.len() > limit as usize {
        return Ok(TrendReport {
            windows,
            outcome: TrendOutcome::NotComparable(TrendGap::TooManyObservations { limit }),
        });
    }

    Ok(analyse(
        &in_osservazioni(righe),
        windows,
        database.earliest_publication()?,
    ))
}

/// Durata di ciascun intervallo della rilevazione degli aumenti: **un giorno**.
///
/// Un giorno è l'unità in cui un operatore ricorda che cosa è successo, ed è
/// abbastanza lunga perché il conteggio di una voce non sia quasi sempre zero.
pub const SPIKE_BUCKET_MS: i64 = 24 * 60 * 60 * 1_000;

/// Quanti intervalli: **quattordici**, di cui tredici di confronto.
///
/// Tredici supera il minimo che il metodo pretende, e quattordici giorni sono
/// **esattamente** l'arco delle due finestre di TREND-01: le due analisi si
/// leggono così in una volta sola, e una prova impone che gli archi coincidano.
pub const SPIKE_BUCKET_COUNT: usize = 14;

/// Le due analisi temporali, sullo stesso arco e sulla stessa lettura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergingAnalysis {
    /// Che cosa compare più che nel periodo di confronto (TREND-01).
    pub trend: TrendReport,
    /// Che cosa supera la soglia dichiarata (SPIKE-01).
    pub spikes: SpikeReport,
}

/// Le due analisi predefinite, che finiscono adesso.
///
/// # Perché una lettura sola
///
/// Perché i due archi **coincidono**: quattordici giorni. Leggere due volte le
/// stesse righe raddoppierebbe il costo e aprirebbe la possibilità che le due
/// analisi vedano insiemi diversi, se qualcosa venisse acquisito nel frattempo
/// — e due risposte alla stessa domanda che non si accordano sono peggio di una
/// sola.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn compose_now(database: &Database, now: Timestamp) -> ServiceResult<Option<EmergingAnalysis>> {
    let (Some(windows), Some(window)) = (
        ComparisonWindows::ending_at(now, crate::trend::DEFAULT_WINDOW_MS),
        BucketedWindow::ending_at(now, SPIKE_BUCKET_MS, SPIKE_BUCKET_COUNT),
    ) else {
        // Non accade con le costanti predefinite. Se qualcuno le cambiasse in
        // valori impossibili, la risposta corretta è «non disponibile» e non un
        // panico: una schermata che si chiude non è più onesta di una che
        // dichiara di non avere il dato.
        return Ok(None);
    };

    // I due archi coincidono, e una prova lo impone; il minimo e il massimo
    // sono qui perche' una divergenza futura restringa la lettura di nessuna
    // delle due invece di lasciarne una scoperta in silenzio.
    let arco_from = windows.baseline_start().min(window.start());
    let arco_to = windows.recent_end().max(window.end());

    let righe = database.observations_between(arco_from, arco_to, MAX_OBSERVATIONS)?;

    if righe.len() > MAX_OBSERVATIONS as usize {
        return Ok(Some(EmergingAnalysis {
            trend: TrendReport {
                windows,
                outcome: TrendOutcome::NotComparable(TrendGap::TooManyObservations {
                    limit: MAX_OBSERVATIONS,
                }),
            },
            spikes: SpikeReport {
                window,
                outcome: SpikeOutcome::NotMeasurable(SpikeGap::TooManyObservations {
                    limit: MAX_OBSERVATIONS,
                }),
            },
        }));
    }

    let osservazioni = in_osservazioni(righe);
    let archivio = database.earliest_publication()?;

    Ok(Some(EmergingAnalysis {
        trend: analyse(&osservazioni, windows, archivio),
        spikes: detect(&osservazioni, window, archivio),
    }))
}

/// Traduce le righe lette in osservazioni.
fn in_osservazioni(
    righe: Vec<lisi_storage::repository::trend::ObservationRow>,
) -> Vec<Observation> {
    righe
        .into_iter()
        .filter_map(|riga| {
            Some(Observation {
                kind: genere(&riga.kind)?,
                key: riga.key,
                at: riga.at,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::{MatchRange, NewMatch};
    use lisi_core::text::{MatchedText, RuleCategory, RuleId};
    use lisi_storage::Database;

    use super::{MAX_OBSERVATIONS, SPIKE_BUCKET_COUNT, SPIKE_BUCKET_MS, compose, compose_now};
    use crate::spike::{BucketedWindow, MINIMUM_BASELINE_BUCKETS};
    use crate::trend::{ComparisonWindows, DEFAULT_WINDOW_MS, TrendGap, TrendOutcome};

    const GIORNO: i64 = 24 * 60 * 60 * 1_000;
    const ORA_ZERO: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn finestre() -> ComparisonWindows {
        let Some(finestre) = ComparisonWindows::ending_at(istante(ORA_ZERO), DEFAULT_WINDOW_MS)
        else {
            panic!("le finestre di prova devono potersi costruire");
        };
        finestre
    }

    /// Un archivio con una fonte, una sessione e i contenuti indicati.
    ///
    /// Ogni coppia è `(giorni_fa, termine)`.
    fn archivio(contenuti: &[(i64, &str)]) -> Database {
        use lisi_core::model::{AcquisitionOrigin, NewContent, NewSession, NewSource, SourceKind};
        use lisi_core::text::{Actor, ContentBody, DisplayName, RemoteMessageId};

        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(title), Ok(label), Ok(attore)) = (
            lisi_core::text::SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: attore.clone(),
                active: true,
            },
            istante(ORA_ZERO),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: attore,
                duration: lisi_core::model::SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            istante(ORA_ZERO),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        for (indice, (giorni_fa, termine)) in contenuti.iter().enumerate() {
            let quando = istante(ORA_ZERO - giorni_fa * GIORNO);
            let (Ok(remote), Ok(body)) = (
                RemoteMessageId::try_new(&format!("m{indice}")),
                ContentBody::try_new("corpo di prova"),
            ) else {
                panic!("i valori del contenuto devono essere validi");
            };
            let (Ok(livello), Ok(rule_id), Ok(rule_category), Ok(matched_text), Ok(range)) = (
                lisi_core::model::AnalysisLevel::try_new(0),
                RuleId::try_new(termine),
                RuleCategory::try_new("prova"),
                MatchedText::try_new(termine),
                MatchRange::try_new(0, termine.len()),
            ) else {
                panic!("i valori del riscontro devono essere validi");
            };

            let Ok(inserimento) = database.insert_content(&NewContent {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body,
                url: None,
                published_at: quando,
                acquired_at: quando,
                origin: AcquisitionOrigin::Observed,
                analysis_level: livello,
            }) else {
                panic!("il contenuto deve potersi registrare");
            };
            let Ok(_) = database.insert_match(
                &NewMatch {
                    content_id: inserimento.content_id(),
                    rule_id,
                    rule_category,
                    matched_text,
                    range,
                    level: livello,
                },
                quando,
            ) else {
                panic!("il riscontro deve potersi registrare");
            };
        }

        database
    }

    /// Su un archivio vuoto non si dice che non stia emergendo nulla.
    #[test]
    fn su_un_archivio_vuoto_il_confronto_dichiara_di_non_avere_nulla() {
        let database = archivio(&[]);

        let Ok(esito) = compose(&database, finestre(), MAX_OBSERVATIONS) else {
            panic!("la lettura deve riuscire");
        };

        assert!(matches!(
            esito.outcome,
            TrendOutcome::NotComparable(TrendGap::EmptyArchive)
        ));
        assert_eq!(esito.emerging_count(), None);
    }

    /// **Un archivio più giovane del periodo di confronto non si confronta.**
    ///
    /// È il caso di ogni ufficio che abbia appena cominciato, ed è la trappola
    /// che questa milestone esiste per non cadere.
    #[test]
    fn un_archivio_appena_cominciato_non_fa_emergere_tutto() {
        // Tutti i contenuti sono di ieri e l'altro ieri: l'archivio comincia
        // dentro il periodo recente.
        let database = archivio(&[(1, "assalto"), (1, "assalto"), (2, "assalto")]);

        let Ok(esito) = compose(&database, finestre(), MAX_OBSERVATIONS) else {
            panic!("la lettura deve riuscire");
        };

        assert!(
            matches!(
                esito.outcome,
                TrendOutcome::NotComparable(TrendGap::BaselinePrecedesArchive { .. })
            ),
            "{:?}",
            esito.outcome
        );
    }

    /// Con entrambe le finestre coperte, il confronto si esegue e conta.
    #[test]
    fn con_entrambe_le_finestre_coperte_il_confronto_conta() {
        let database = archivio(&[
            // L'archivio deve coprire l'INIZIO del periodo di confronto: se
            // cominciasse dopo, la linea di partenza sarebbe piu' corta della
            // finestra recente e ogni cosa sembrerebbe cresciuta.
            (14, "vecchio"),
            // Periodo di confronto: da 7 a 14 giorni fa.
            (13, "assalto"),
            (12, "corteo"),
            // Periodo recente: da 0 a 7 giorni fa.
            (6, "assalto"),
            (5, "assalto"),
            (4, "assalto"),
            (3, "assalto"),
        ]);

        let Ok(esito) = compose(&database, finestre(), MAX_OBSERVATIONS) else {
            panic!("la lettura deve riuscire");
        };

        let TrendOutcome::Compared { findings, .. } = &esito.outcome else {
            panic!("il confronto doveva eseguirsi: {:?}", esito.outcome);
        };

        let assalto = findings.iter().find(|voce| voce.key == "assalto");
        let Some(assalto) = assalto else {
            panic!("«assalto» doveva comparire: {findings:?}");
        };
        assert_eq!(assalto.recent, 4);
        assert_eq!(assalto.baseline, 1);
    }

    /// **Oltre il limite non si conta una parte: si rifiuta.**
    #[test]
    fn oltre_il_limite_il_confronto_si_rifiuta() {
        let database = archivio(&[(14, "z"), (13, "a"), (12, "b"), (6, "c"), (5, "d")]);

        // Cinque contenuti producono dieci occorrenze: termine e volume.
        let Ok(esito) = compose(&database, finestre(), 3) else {
            panic!("la lettura deve riuscire");
        };

        assert!(matches!(
            esito.outcome,
            TrendOutcome::NotComparable(TrendGap::TooManyObservations { limit: 3 })
        ));
        assert_eq!(
            esito.emerging_count(),
            None,
            "un rifiuto non è zero segnali emergenti"
        );
    }

    /// Il confronto predefinito esiste e porta con sé le proprie finestre.
    #[test]
    fn il_confronto_predefinito_dichiara_le_proprie_finestre() {
        let database = archivio(&[(14, "vecchio"), (13, "assalto"), (6, "assalto")]);

        let Ok(Some(analisi)) = compose_now(&database, istante(ORA_ZERO)) else {
            panic!("le due analisi devono comporsi");
        };

        assert_eq!(analisi.trend.windows.duration_ms(), DEFAULT_WINDOW_MS);
        assert!(analisi.trend.as_sentence().contains("Periodo recente:"));
        assert!(
            analisi
                .spikes
                .as_sentence()
                .contains("Intervallo osservato:")
        );
    }

    /// **I due archi coincidono, e la lettura è una sola.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Le due analisi si leggono insieme perché coprono lo stesso periodo. Se
    /// qualcuno cambiasse `DEFAULT_WINDOW_MS` o `SPIKE_BUCKET_COUNT`, una delle
    /// due riceverebbe meno righe di quante gliene servono — e non se ne
    /// accorgerebbe: conterebbe zero negli intervalli scoperti, che è
    /// esattamente il modo in cui un'assenza di dati si traveste da misura.
    ///
    /// Il minimo e il massimo nella lettura evitano che accada, ma il caso
    /// resterebbe non voluto: questa prova impone che sia deliberato.
    #[test]
    fn le_due_analisi_coprono_lo_stesso_arco() {
        let now = istante(ORA_ZERO);
        let Some(finestre) = ComparisonWindows::ending_at(now, DEFAULT_WINDOW_MS) else {
            panic!("le finestre devono potersi costruire");
        };
        let Some(intervalli) = BucketedWindow::ending_at(now, SPIKE_BUCKET_MS, SPIKE_BUCKET_COUNT)
        else {
            panic!("il periodo deve potersi costruire");
        };

        assert_eq!(
            finestre.baseline_start(),
            intervalli.start(),
            "le due analisi devono cominciare insieme"
        );
        assert_eq!(
            finestre.recent_end(),
            intervalli.end(),
            "le due analisi devono finire insieme"
        );
        assert!(
            intervalli.baseline_buckets() >= MINIMUM_BASELINE_BUCKETS,
            "gli intervalli di confronto devono bastare al metodo"
        );
    }

    /// **Un aumento oltre soglia compare accanto al confronto fra periodi.**
    ///
    /// Le due analisi rispondono a domande diverse sugli stessi fatti, e si
    /// leggono insieme: la prima dice che cosa compare più di prima, la seconda
    /// che cosa supera la soglia dichiarata.
    #[test]
    fn le_due_analisi_rispondono_insieme_sugli_stessi_fatti() {
        // Quindici giorni di archivio; una voce stabile, e una che esplode
        // nell'ultimo giorno.
        let mut contenuti: Vec<(i64, &str)> = vec![(14, "vecchio")];
        for giorno in 1..=13 {
            contenuti.push((giorno, "stabile"));
        }
        for _ in 0..12 {
            contenuti.push((0, "esploso"));
        }
        // «esploso» deve esistere anche prima, altrimenti la mediana e' zero e
        // il caso non distingue nulla.
        for giorno in 1..=13 {
            contenuti.push((giorno, "esploso"));
        }

        let database = archivio(&contenuti);

        let Ok(Some(analisi)) = compose_now(&database, istante(ORA_ZERO)) else {
            panic!("le due analisi devono comporsi");
        };

        assert!(
            analisi.spikes.anomalous_count().is_some(),
            "il metodo doveva applicarsi: {}",
            analisi.spikes.as_sentence()
        );
        assert!(
            analisi.trend.emerging_count().is_some(),
            "il confronto doveva eseguirsi: {}",
            analisi.trend.as_sentence()
        );
    }
}

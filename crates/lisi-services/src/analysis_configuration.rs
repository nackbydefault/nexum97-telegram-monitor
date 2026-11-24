//! Con quali termini l'analisi è stata condotta, come i documenti lo dicono
//! (NEXUM97-REPORT-CONFIG-01, ADR-0156).
//!
//! # Perché una composizione sola
//!
//! Relazione, allegato tecnico, registro e rapporto dicono la stessa cosa: quali
//! versioni di dizionario erano in vigore, quale configurazione risolta, quali
//! parole aggiunte per la sessione. Il collaudo con il profilo reale (DEC-415)
//! li ha trovati muti o sbagliati nello stesso punto, e quattro composizioni
//! della stessa frase sarebbero quattro occasioni di sbagliarla in modo
//! diverso. Qui si legge e si compone; i documenti rendono.
//!
//! # Che cosa l'archivio sa, e da quando
//!
//! - I **termini risolti** esistono per ogni monitoraggio avviato con una
//!   configurazione, e sono immutabili: ciascuno porta le proprie provenienze
//!   (dizionario e versione, o «aggiunta alla sessione»). La loro **impronta**
//!   si ricalcola rileggendoli.
//! - Le **scelte** dei dizionari e le **parole aggiunte** si registrano a parte
//!   soltanto da FR-049 (2026-10-04). Per i monitoraggi di prima le loro tabelle
//!   sono vuote, e un elenco vuoto **non** vuol dire «nessuna»: vuol dire «non
//!   registrate». Quello che manca si ricava dai termini risolti, e la frase lo
//!   dichiara.
//!
//! # Perché non si copia nella fotografia della relazione
//!
//! Perché dopo l'avvio non cambia: i termini risolti sono immutabili per
//! trigger, l'archivio rifiuta scelte e parole dopo la risoluzione, e una
//! sessione con termini risolti non si cancella. Una copia per pacchetto
//! sarebbe una seconda verità da tenere allineata (ADR-0156).

use std::collections::{BTreeMap, BTreeSet};

use lisi_core::model::dictionary::{MatchMode, ResolvedDictionaryConfiguration};
use lisi_core::model::report::ReportSnapshot;
use lisi_core::text::counted;
use lisi_core::{DictionaryVersionId, SessionId};
use lisi_storage::{Database, StorageError};

use crate::error::ServiceResult;
use crate::report_narrative::Block;

/// La guida della frase sulle versioni di dizionario.
pub const DICTIONARIES_LEAD: &str = "Versioni di dizionario in vigore:";
/// La guida della frase sulla configurazione risolta e la sua impronta.
///
/// In superficie la configurazione risolta è «l'elenco dei termini della
/// sessione»: la parola tecnica resta nei commenti e negli ADR (PR-01).
pub const RESOLUTION_LEAD: &str = "Termini della sessione:";
/// La guida della frase sulla provenienza dei termini risolti.
pub const PROVENANCE_LEAD: &str = "Da dove vengono i termini:";
/// La guida della frase sulle parole aggiunte per la sessione.
pub const CUSTOM_TERMS_LEAD: &str = "Parole aggiunte per la sessione:";

/// Da dove è nota una versione scelta all'avvio.
pub const DICTIONARY_RECORDED: &str = "scelta registrata all'avvio";
/// Da dove è nota una versione ricavata dalle provenienze.
pub const DICTIONARY_FROM_RESOLVED_TERMS: &str = "da dove vengono i termini della sessione";
/// Da dove è nota una parola registrata all'avvio.
pub const CUSTOM_TERM_RECORDED: &str = "registrata all'avvio";
/// Da dove è nota una parola ricavata dai termini risolti.
pub const CUSTOM_TERM_FROM_RESOLVED_TERMS: &str =
    "dall'elenco dei termini della sessione, con il suo livello";

/// Una versione di dizionario, come i documenti la nominano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredDictionary {
    /// Nome del dizionario.
    pub name: String,
    /// Numero di versione.
    pub version: u32,
    /// Quanti termini contiene la versione.
    pub terms: usize,
}

impl ConfiguredDictionary {
    /// «Incendi v3».
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} v{}", self.name, self.version)
    }
}

/// Le versioni di dizionario in vigore, e da dove il documento le sa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dictionaries {
    /// Le scelte registrate all'avvio.
    Recorded(Vec<ConfiguredDictionary>),
    /// Le scelte non sono state registrate: le versioni sono quelle da cui
    /// provengono i termini risolti (BUG-REP-1).
    FromResolvedTerms(Vec<ConfiguredDictionary>),
    /// Nessuna scelta registrata, e la configurazione risolta, integra, non ha
    /// alcun termine che venga da un dizionario.
    NoneInConfiguration,
    /// Nessuna scelta registrata e nessuna configurazione risolta integra: il
    /// documento non lo può sapere.
    Undeterminable,
}

/// Quanti termini risolti vengono da una provenienza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceCount {
    /// «Incendi v3», o «aggiunta alla sessione».
    pub label: String,
    /// Quanti termini distinti ne provengono.
    pub terms: usize,
}

/// La configurazione risolta conservata per la sessione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Conservata, e i termini riletti danno la stessa impronta registrata.
    Intact {
        /// Impronta SHA-256, in forma completa.
        digest: String,
        /// Termini distinti.
        terms: usize,
        /// Da dove vengono, dizionari prima e parole della sessione dopo.
        provenances: Vec<ProvenanceCount>,
    },
    /// Nessuna configurazione risolta registrata.
    NotRecorded,
    /// Registrata, ma i termini conservati non corrispondono più all'impronta o
    /// non si leggono.
    NotIntact {
        /// L'impronta registrata all'avvio.
        recorded_digest: String,
    },
}

/// Una parola aggiunta per la sessione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomTerm {
    /// Il testo, come è stato scritto.
    pub text: String,
    /// Il livello: quello scelto, o quello risolto quando la parola si ricava
    /// dai termini risolti.
    pub level: i8,
    /// La modalità di riscontro.
    pub match_mode: MatchMode,
    /// I dizionari in cui la stessa parola compare, quando si ricava dai
    /// termini risolti: il livello risolto è il più alto fra tutti.
    pub also_in: Vec<String>,
}

/// Le parole aggiunte per la sessione, e da dove il documento le sa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomTerms {
    /// Registrate all'avvio, con il livello scelto.
    Recorded(Vec<CustomTerm>),
    /// Non registrate a parte: sono i termini risolti attribuiti alla sessione.
    FromResolvedTerms(Vec<CustomTerm>),
    /// Nessuna: la configurazione risolta, integra, non ne contiene.
    NoneAdded,
    /// Né registrate né ricavabili da una configurazione risolta integra.
    Undeterminable,
}

/// Una frase dei documenti: la guida e il corpo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// «Versioni di dizionario in vigore:».
    pub lead: &'static str,
    /// Il resto della frase, con il punto finale.
    pub body: String,
}

/// Con quali termini l'analisi è stata condotta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisConfiguration {
    /// Le versioni di dizionario.
    pub dictionaries: Dictionaries,
    /// La configurazione risolta e la sua impronta.
    pub resolution: Resolution,
    /// Le parole aggiunte per la sessione.
    pub custom_terms: CustomTerms,
}

impl AnalysisConfiguration {
    /// Una configurazione di cui l'archivio non sa nulla.
    ///
    /// Esiste per le prove dei generatori che non riguardano la configurazione:
    /// è il caso in cui il documento dice «non determinabili», mai «nessuna».
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            dictionaries: Dictionaries::Undeterminable,
            resolution: Resolution::NotRecorded,
            custom_terms: CustomTerms::Undeterminable,
        }
    }

    /// Le frasi, nell'ordine in cui ogni documento le scrive.
    #[must_use]
    pub fn statements(&self) -> Vec<Statement> {
        let mut statements = vec![
            Statement {
                lead: DICTIONARIES_LEAD,
                body: self.dictionaries_body(),
            },
            Statement {
                lead: RESOLUTION_LEAD,
                body: self.resolution_body(),
            },
        ];
        if let Resolution::Intact { provenances, .. } = &self.resolution {
            statements.push(Statement {
                lead: PROVENANCE_LEAD,
                body: provenance_body(provenances),
            });
        }
        statements.push(Statement {
            lead: CUSTOM_TERMS_LEAD,
            body: self.custom_terms_body(),
        });
        statements
    }

    /// Le frasi come righe guidate della relazione e dell'allegato.
    pub fn push_blocks(&self, blocks: &mut Vec<Block>) {
        for statement in self.statements() {
            blocks.push(Block::Lead {
                lead: String::from(statement.lead),
                body: statement.body,
            });
        }
    }

    /// Le versioni come righe del registro, con da dove sono note.
    #[must_use]
    pub fn dictionary_rows(&self) -> Vec<(&ConfiguredDictionary, &'static str)> {
        match &self.dictionaries {
            Dictionaries::Recorded(rows) => {
                rows.iter().map(|row| (row, DICTIONARY_RECORDED)).collect()
            }
            Dictionaries::FromResolvedTerms(rows) => rows
                .iter()
                .map(|row| (row, DICTIONARY_FROM_RESOLVED_TERMS))
                .collect(),
            Dictionaries::NoneInConfiguration | Dictionaries::Undeterminable => Vec::new(),
        }
    }

    /// Le parole come righe del registro, con da dove sono note.
    #[must_use]
    pub fn custom_term_rows(&self) -> Vec<(&CustomTerm, &'static str)> {
        match &self.custom_terms {
            CustomTerms::Recorded(rows) => {
                rows.iter().map(|row| (row, CUSTOM_TERM_RECORDED)).collect()
            }
            CustomTerms::FromResolvedTerms(rows) => rows
                .iter()
                .map(|row| (row, CUSTOM_TERM_FROM_RESOLVED_TERMS))
                .collect(),
            CustomTerms::NoneAdded | CustomTerms::Undeterminable => Vec::new(),
        }
    }

    fn dictionaries_body(&self) -> String {
        match &self.dictionaries {
            Dictionaries::Recorded(rows) if rows.is_empty() => String::from(
                "non leggibili: le versioni registrate all'avvio non si trovano più \
                 nell'archivio.",
            ),
            Dictionaries::Recorded(rows) => format!("{}.", labels(rows)),
            Dictionaries::FromResolvedTerms(rows) if rows.is_empty() => String::from(
                "non leggibili: le scelte dei dizionari non sono state registrate. Le versioni \
                 da cui vengono i termini della sessione non si trovano più nell'archivio.",
            ),
            Dictionaries::FromResolvedTerms(rows) => format!(
                "{}. Le scelte dei dizionari non sono state registrate dalla versione del \
                 programma che ha avviato il monitoraggio. Queste sono le versioni da cui \
                 vengono i termini della sessione: un dizionario scelto senza termini non vi \
                 compare.",
                labels(rows)
            ),
            Dictionaries::NoneInConfiguration => {
                String::from("nessuna: nessun termine della sessione viene da un dizionario.")
            }
            Dictionaries::Undeterminable => String::from(
                "non determinabili: le scelte dei dizionari non sono state registrate, e un \
                 elenco integro dei termini della sessione non è disponibile.",
            ),
        }
    }

    fn resolution_body(&self) -> String {
        match &self.resolution {
            Resolution::Intact { digest, terms, .. } => format!(
                "{}; impronta {digest}. L'impronta è ricalcolata dai termini \
                 conservati ed è uguale a quella registrata all'avvio. Riconosce l'elenco: non \
                 è una firma.",
                counted(*terms, "termine diverso", "termini diversi")
            ),
            Resolution::NotRecorded => String::from(
                "non conservati: l'archivio non registra con quali termini l'analisi è stata \
                 condotta.",
            ),
            Resolution::NotIntact { recorded_digest } => format!(
                "l'impronta registrata all'avvio è {recorded_digest}, ma i termini conservati \
                 non vi corrispondono più o non si leggono. Il documento non li riporta come \
                 termini dell'analisi."
            ),
        }
    }

    fn custom_terms_body(&self) -> String {
        match &self.custom_terms {
            CustomTerms::Recorded(rows) => format!("{}.", custom_term_list(rows)),
            CustomTerms::FromResolvedTerms(rows) => format!(
                "{}. Le parole aggiunte non sono state registrate a parte dalla versione del \
                 programma che ha avviato il monitoraggio. Vengono dall'elenco dei termini \
                 della sessione, con il livello dell'elenco: il più alto fra le fonti.",
                custom_term_list(rows)
            ),
            CustomTerms::NoneAdded => String::from("nessuna."),
            CustomTerms::Undeterminable => String::from(
                "non determinabili: le parole aggiunte non sono state registrate a parte, e un \
                 elenco integro dei termini della sessione non è disponibile.",
            ),
        }
    }
}

fn labels(rows: &[ConfiguredDictionary]) -> String {
    rows.iter()
        .map(ConfiguredDictionary::label)
        .collect::<Vec<_>>()
        .join(", ")
}

fn provenance_body(provenances: &[ProvenanceCount]) -> String {
    if provenances.is_empty() {
        return String::from("nessun termine.");
    }
    format!(
        "{}. Un termine che viene da più fonti si conta in ciascuna.",
        provenances
            .iter()
            .map(|provenance| format!(
                "{}: {}",
                provenance.label,
                counted(provenance.terms, "termine", "termini")
            ))
            .collect::<Vec<_>>()
            .join("; ")
    )
}

fn custom_term_list(rows: &[CustomTerm]) -> String {
    rows.iter()
        .map(|term| {
            let mut item = format!(
                "«{}», livello {}, modalità «{}»",
                term.text,
                term.level,
                term.match_mode.label()
            );
            if !term.also_in.is_empty() {
                item.push_str(&format!(", presente anche in {}", term.also_in.join(", ")));
            }
            item
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// La configurazione di una relazione: le versioni dalla sua fotografia.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge. Una configurazione
/// risolta che non corrisponde alla propria impronta **non** è un errore: il
/// documento lo dichiara.
pub fn of_report(
    database: &Database,
    snapshot: &ReportSnapshot,
) -> ServiceResult<AnalysisConfiguration> {
    read(
        database,
        snapshot.session_id,
        &snapshot.dictionary_version_ids,
    )
}

/// La configurazione di una sessione: le versioni dalle scelte registrate.
///
/// Serve al rapporto di esportazione, che non ha una fotografia propria.
///
/// # Errori
///
/// Come [`of_report`].
pub fn of_session(
    database: &Database,
    session_id: SessionId,
) -> ServiceResult<AnalysisConfiguration> {
    let recorded = database.session_dictionary_version_ids(session_id)?;
    read(database, session_id, &recorded)
}

fn read(
    database: &Database,
    session_id: SessionId,
    recorded_versions: &[DictionaryVersionId],
) -> ServiceResult<AnalysisConfiguration> {
    let (resolution, configuration) = resolution_of(database, session_id)?;

    let dictionaries = if !recorded_versions.is_empty() {
        Dictionaries::Recorded(dictionaries_of(database, recorded_versions))
    } else if let Some(configuration) = &configuration {
        let versions: BTreeSet<DictionaryVersionId> = configuration
            .terms
            .iter()
            .flat_map(|term| term.provenances.iter())
            .filter_map(|provenance| provenance.version_id)
            .collect();
        if versions.is_empty() {
            Dictionaries::NoneInConfiguration
        } else {
            let versions: Vec<DictionaryVersionId> = versions.into_iter().collect();
            Dictionaries::FromResolvedTerms(dictionaries_of(database, &versions))
        }
    } else {
        Dictionaries::Undeterminable
    };

    let recorded_terms = database.session_custom_terms(session_id)?;
    let custom_terms = if !recorded_terms.is_empty() {
        CustomTerms::Recorded(
            recorded_terms
                .iter()
                .map(|term| CustomTerm {
                    text: term.text.as_str().to_owned(),
                    level: term.suggested_level.get(),
                    match_mode: term.match_mode,
                    also_in: Vec::new(),
                })
                .collect(),
        )
    } else if let Some(configuration) = &configuration {
        let added: Vec<CustomTerm> = configuration
            .terms
            .iter()
            .filter(|term| {
                term.provenances
                    .iter()
                    .any(|provenance| provenance.version_id.is_none())
            })
            .map(|term| CustomTerm {
                text: term.original.as_str().to_owned(),
                level: term.suggested_level,
                match_mode: term.match_mode,
                also_in: term
                    .provenances
                    .iter()
                    .filter(|provenance| provenance.version_id.is_some())
                    .map(|provenance| provenance.label.clone())
                    .collect(),
            })
            .collect();
        if added.is_empty() {
            CustomTerms::NoneAdded
        } else {
            CustomTerms::FromResolvedTerms(added)
        }
    } else {
        CustomTerms::Undeterminable
    };

    Ok(AnalysisConfiguration {
        dictionaries,
        resolution,
        custom_terms,
    })
}

/// La configurazione risolta, e il suo stato.
///
/// Un'impronta che non corrisponde, o un termine che non si legge, diventano
/// una frase del documento; ogni altro errore dell'archivio resta un errore, e
/// la generazione si ferma: un archivio che non si legge non diventa una
/// dichiarazione.
fn resolution_of(
    database: &Database,
    session_id: SessionId,
) -> ServiceResult<(Resolution, Option<ResolvedDictionaryConfiguration>)> {
    match database.session_resolved_configuration(session_id) {
        Ok(Some(configuration)) => Ok((intact(&configuration), Some(configuration))),
        Ok(None) => Ok((Resolution::NotRecorded, None)),
        Err(error) if is_not_intact(&error) => {
            let resolution = database
                .session_recorded_dictionary_digest(session_id)?
                .map_or(Resolution::NotRecorded, |recorded_digest| {
                    Resolution::NotIntact { recorded_digest }
                });
            Ok((resolution, None))
        }
        Err(error) => Err(error.into()),
    }
}

/// Se l'errore dice che la configurazione conservata non è più quella.
const fn is_not_intact(error: &StorageError) -> bool {
    matches!(
        error,
        StorageError::SnapshotDigestMismatch
            | StorageError::CorruptedRow { .. }
            | StorageError::CorruptedValue(_)
    )
}

fn intact(configuration: &ResolvedDictionaryConfiguration) -> Resolution {
    // Dizionari prima, in ordine di nome; le parole della sessione per ultime.
    // La versione nella chiave tiene distinti due dizionari omonimi.
    let mut counts: BTreeMap<(bool, String, Option<i64>), usize> = BTreeMap::new();
    for term in &configuration.terms {
        for provenance in &term.provenances {
            let key = (
                provenance.version_id.is_none(),
                provenance.label.clone(),
                provenance.version_id.map(DictionaryVersionId::get),
            );
            *counts.entry(key).or_default() += 1;
        }
    }

    Resolution::Intact {
        digest: configuration.digest.as_str().to_owned(),
        terms: configuration.unique_count,
        provenances: counts
            .into_iter()
            .map(|((_, label, _), terms)| ProvenanceCount { label, terms })
            .collect(),
    }
}

/// Nome, numero e termini di ogni versione indicata.
///
/// Una versione che non si legge più resta fuori, con un avviso nel diario:
/// è il comportamento che il registro aveva già (le versioni pubblicate non si
/// cancellano, e il caso non dovrebbe presentarsi).
fn dictionaries_of(
    database: &Database,
    version_ids: &[DictionaryVersionId],
) -> Vec<ConfiguredDictionary> {
    let mut dictionaries = Vec::new();
    for version_id in version_ids {
        let Ok(version) = database.dictionary_version(*version_id) else {
            tracing::warn!(
                versione = version_id.get(),
                "versione di dizionario non più leggibile: non entra nei documenti"
            );
            continue;
        };
        let name = database.dictionary(version.dictionary_id).map_or_else(
            |_| String::from("Dizionario non più disponibile"),
            |dictionary| dictionary.name.as_str().to_owned(),
        );
        let terms = database
            .dictionary_terms(*version_id)
            .map(|terms| terms.len())
            .unwrap_or_default();
        dictionaries.push(ConfiguredDictionary {
            name,
            version: version.number,
            terms,
        });
    }
    dictionaries
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::MatchMode;
    use lisi_storage::StorageError;

    use super::{
        AnalysisConfiguration, ConfiguredDictionary, CustomTerm, CustomTerms, Dictionaries,
        ProvenanceCount, Resolution, is_not_intact,
    };

    fn incendi() -> ConfiguredDictionary {
        ConfiguredDictionary {
            name: String::from("Incendi"),
            version: 3,
            terms: 120,
        }
    }

    fn intact(terms: usize) -> Resolution {
        Resolution::Intact {
            digest: "a".repeat(64),
            terms,
            provenances: vec![
                ProvenanceCount {
                    label: String::from("Incendi v3"),
                    terms: terms.saturating_sub(1),
                },
                ProvenanceCount {
                    label: String::from("aggiunta alla sessione"),
                    terms: 1,
                },
            ],
        }
    }

    fn body(configuration: &AnalysisConfiguration, lead: &str) -> String {
        let Some(statement) = configuration
            .statements()
            .into_iter()
            .find(|statement| statement.lead == lead)
        else {
            panic!("manca la frase «{lead}»");
        };
        statement.body
    }

    /// **Le scelte registrate si scrivono come prima**: per nome e numero.
    #[test]
    fn le_scelte_registrate_si_scrivono_per_nome_e_numero() {
        let configurazione = AnalysisConfiguration {
            dictionaries: Dictionaries::Recorded(vec![
                incendi(),
                ConfiguredDictionary {
                    name: String::from("Ordine pubblico"),
                    version: 2,
                    terms: 40,
                },
            ]),
            resolution: intact(160),
            custom_terms: CustomTerms::NoneAdded,
        };
        assert_eq!(
            body(&configurazione, super::DICTIONARIES_LEAD),
            "Incendi v3, Ordine pubblico v2."
        );
        assert_eq!(body(&configurazione, super::CUSTOM_TERMS_LEAD), "nessuna.");
    }

    /// **«Nessuna» solo quando la configurazione integra lo conferma**; senza
    /// configurazione risolta il documento non lo sa, e lo dice.
    #[test]
    fn senza_configurazione_risolta_nulla_si_dice_nessuno() {
        let configurazione = AnalysisConfiguration::unknown();
        let frasi = configurazione.statements();
        for frase in &frasi {
            assert!(
                !frase.body.starts_with("nessun"),
                "«{}» dice «{}» senza saperlo",
                frase.lead,
                frase.body
            );
        }
        assert!(body(&configurazione, super::DICTIONARIES_LEAD).starts_with("non determinabili"));
        assert!(body(&configurazione, super::CUSTOM_TERMS_LEAD).starts_with("non determinabili"));
        assert!(body(&configurazione, super::RESOLUTION_LEAD).starts_with("non conservati"));
        // Senza termini integri non c'è una provenienza da contare.
        assert!(
            !frasi
                .iter()
                .any(|frase| frase.lead == super::PROVENANCE_LEAD)
        );
    }

    /// Con la configurazione integra e nessun termine da un dizionario,
    /// «nessuna» è vero, e si dice perché.
    #[test]
    fn nessuna_versione_quando_la_configurazione_integra_lo_conferma() {
        let configurazione = AnalysisConfiguration {
            dictionaries: Dictionaries::NoneInConfiguration,
            resolution: Resolution::Intact {
                digest: "b".repeat(64),
                terms: 1,
                provenances: vec![ProvenanceCount {
                    label: String::from("aggiunta alla sessione"),
                    terms: 1,
                }],
            },
            custom_terms: CustomTerms::Recorded(vec![CustomTerm {
                text: String::from("cerco"),
                level: 1,
                match_mode: MatchMode::ExactWord,
                also_in: Vec::new(),
            }]),
        };
        assert!(body(&configurazione, super::DICTIONARIES_LEAD).starts_with("nessuna:"));
        assert_eq!(
            body(&configurazione, super::RESOLUTION_LEAD)
                .split(';')
                .next()
                .map(str::to_owned),
            Some(String::from("1 termine diverso"))
        );
        assert_eq!(
            body(&configurazione, super::PROVENANCE_LEAD),
            "aggiunta alla sessione: 1 termine. Un termine che viene da più fonti si conta in \
             ciascuna."
        );
        assert_eq!(
            body(&configurazione, super::CUSTOM_TERMS_LEAD),
            "«cerco», livello 1, modalità «Parola esatta»."
        );
    }

    /// **Un'impronta che non corrisponde si dichiara**, con l'impronta
    /// registrata, e nessun termine di quella configurazione si presenta come
    /// configurazione dell'analisi.
    #[test]
    fn un_impronta_che_non_corrisponde_si_dichiara() {
        let registrata = "c".repeat(64);
        let configurazione = AnalysisConfiguration {
            dictionaries: Dictionaries::Undeterminable,
            resolution: Resolution::NotIntact {
                recorded_digest: registrata.clone(),
            },
            custom_terms: CustomTerms::Undeterminable,
        };
        let frase = body(&configurazione, super::RESOLUTION_LEAD);
        assert!(frase.contains(&registrata));
        assert!(frase.contains("non vi corrispondono più"));
        assert!(
            !configurazione
                .statements()
                .iter()
                .any(|frase| frase.lead == super::PROVENANCE_LEAD)
        );
    }

    /// Solo i difetti di integrità diventano una frase; un errore
    /// dell'archivio resta un errore e ferma la generazione.
    #[test]
    fn solo_un_difetto_di_integrita_diventa_una_frase() {
        assert!(is_not_intact(&StorageError::SnapshotDigestMismatch));
        assert!(is_not_intact(&StorageError::CorruptedRow {
            detail: "prova"
        }));
        assert!(!is_not_intact(&StorageError::NotFound {
            entity: "sessione",
            id: 1,
        }));
        assert!(!is_not_intact(&StorageError::AuditIsAppendOnly));
    }

    /// Una parola ricavata dai termini risolti che compare anche in un
    /// dizionario lo dice: il suo livello è quello risolto.
    #[test]
    fn una_parola_ricavata_dice_dove_altro_compare() {
        let configurazione = AnalysisConfiguration {
            dictionaries: Dictionaries::FromResolvedTerms(vec![incendi()]),
            resolution: intact(121),
            custom_terms: CustomTerms::FromResolvedTerms(vec![CustomTerm {
                text: String::from("rogo"),
                level: 3,
                match_mode: MatchMode::NormalizedWord,
                also_in: vec![String::from("Incendi v3")],
            }]),
        };
        let frase = body(&configurazione, super::CUSTOM_TERMS_LEAD);
        assert!(frase.starts_with(
            "«rogo», livello 3, modalità «Parola come viene cercata», presente anche in \
             Incendi v3."
        ));
        assert!(frase.contains("con il livello dell'elenco"));
        assert_eq!(
            configurazione.dictionary_rows().first().map(|(_, da)| *da),
            Some(super::DICTIONARY_FROM_RESOLVED_TERMS)
        );
        assert_eq!(
            configurazione.custom_term_rows().first().map(|(_, da)| *da),
            Some(super::CUSTOM_TERM_FROM_RESOLVED_TERMS)
        );
    }
}

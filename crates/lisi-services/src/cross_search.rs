//! La ricerca trasversale: **una** domanda su più rami — A nell'archivio, B
//! nelle chat dell'account, C dentro una chat, D nei post pubblici — e un
//! elenco solo, con il perimetro di ciascun ramo (CYBER-SEARCH-03, ADR-0163).
//!
//! # L'unione
//!
//! Un risultato è un messaggio: chat e numero. Lo stesso messaggio trovato da
//! più rami compare una volta, con tutte le provenienze. Un contenuto
//! dell'archivio la cui fonte non ha un numero di chat leggibile resta da solo.
//!
//! # Che cosa non fa
//!
//! Non chiede pagine successive, non conserva i risultati di Telegram, non
//! correla: gli indicatori ricavati dagli estratti si contano, e basta. La D
//! parte soltanto se scelta, perché consuma la quota gratuita.

use std::collections::{BTreeMap, BTreeSet};

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::indicator::extract;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;
use lisi_telegram::{ChatId, TelegramConnector};

use crate::cyber_search::{self, Attempt, Branch};
use crate::error::ServiceResult;
use crate::history::{HistoryFilter, HistoryScope, HistoryService};

/// Quanti contenuti dell'archivio, al più, i più recenti.
pub const ARCHIVE_ROWS: usize = 50;
/// L'azione d'audit della ricerca trasversale.
pub const CROSS_SEARCH_AUDIT_ACTION: &str = "ricerca_trasversale";

/// Quali rami chiedere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Branches {
    /// **A**, nell'archivio.
    pub archive: bool,
    /// **B**, nelle chat dell'account.
    pub account_chats: bool,
    /// **C**, dentro questa chat.
    pub in_chat: Option<ChatId>,
    /// **D**, nei post pubblici: consuma la quota gratuita.
    pub public_posts: bool,
}

impl Branches {
    /// Se nessun ramo è scelto.
    #[must_use]
    pub const fn none(&self) -> bool {
        !self.archive && !self.account_chats && self.in_chat.is_none() && !self.public_posts
    }
}

/// Un risultato dell'elenco unito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossRow {
    /// In quale chat, a parole.
    pub chat: String,
    /// Il numero della chat, se si legge.
    pub chat_id: Option<i64>,
    /// Il numero del messaggio, come la fonte lo dichiara.
    pub message_id: String,
    /// Quando è stato pubblicato, come la fonte lo dichiara.
    pub published_at: Timestamp,
    /// Chi l'ha scritto, in una frase.
    pub who: String,
    /// L'inizio del testo.
    pub excerpt: String,
    /// Da quali rami viene: «A» e le lettere di Telegram, in ordine.
    pub found_by: BTreeSet<&'static str>,
}

/// Che cosa ha fatto un ramo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchReport {
    /// La lettera.
    pub letter: &'static str,
    /// Se è stato chiesto.
    pub asked: bool,
    /// Il perimetro, in una frase.
    pub scope: String,
    /// Com'è andata, in una frase.
    pub outcome: String,
    /// Quanti risultati ha dato, prima dell'unione.
    pub results: usize,
}

/// Un indicatore e dove compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndicatorCount {
    /// Il valore normalizzato.
    pub value: String,
    /// In quanti risultati.
    pub rows: usize,
    /// In quante chat diverse.
    pub chats: usize,
}

/// L'esito della ricerca trasversale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossResult {
    /// L'elenco unito, dal più recente.
    pub rows: Vec<CrossRow>,
    /// I quattro rami, chiesti o no.
    pub branches: Vec<BranchReport>,
    /// Gli indicatori ricavati dagli estratti.
    pub indicators: Vec<IndicatorCount>,
    /// Quanti risultati, prima dell'unione.
    pub before_union: usize,
}

/// Fa la ricerca trasversale.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si legge o non si scrive;
/// un rifiuto prima di chiedere è `Ok(Err(frase))`.
pub fn search(
    mut connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    history: &HistoryService,
    operator: &Actor,
    rami: Branches,
    testo: &str,
    now: Timestamp,
) -> ServiceResult<Result<CrossResult, String>> {
    let query = match cyber_search::read_query(testo) {
        Ok(query) => query,
        Err(frase) => return Ok(Err(frase)),
    };
    if rami.none() {
        return Ok(Err(String::from(
            "Scegliere almeno un ramo in cui cercare: la ricerca non \u{e8} partita.",
        )));
    }

    let mut righe: Vec<CrossRow> = Vec::new();
    let mut rapporti = Vec::new();

    // A, NELL'ARCHIVIO: IL FILTRO DELLO STORICO (SEARCH-01).
    if rami.archive {
        let (trovate, rapporto) = archive_rows(history, &query)?;
        righe.extend(trovate);
        rapporti.push(rapporto);
    } else {
        rapporti.push(not_asked("A", archive_scope()));
    }

    // B, C E D: UNA PAGINA CIASCUNO, DAL SERVIZIO DELLE RICERCHE.
    let telegram = [
        (rami.account_chats.then_some(Branch::AccountChats), "B"),
        (rami.in_chat.map(Branch::InChat), "C"),
        (rami.public_posts.then_some(Branch::PublicPosts), "D"),
    ];
    for (scelto, lettera) in telegram {
        let Some(branch) = scelto else {
            rapporti.push(not_asked(lettera, cyber_search::scope_sentence_of(lettera)));
            continue;
        };
        let esito = cyber_search::start(
            connector
                .as_mut()
                .map(|connettore| &mut **connettore as &mut dyn TelegramConnector),
            database,
            operator,
            branch,
            &query,
            now,
        )?;
        match esito {
            Attempt::Refused(frase) => rapporti.push(BranchReport {
                letter: lettera,
                asked: false,
                scope: cyber_search::scope_sentence_of(lettera),
                outcome: frase,
                results: 0,
            }),
            Attempt::Done(ricerca) => {
                let quanti = ricerca.hits.len();
                rapporti.push(BranchReport {
                    letter: lettera,
                    asked: true,
                    scope: ricerca.scope_sentence(),
                    outcome: ricerca.last_outcome.clone(),
                    results: quanti,
                });
                righe.extend(ricerca.hits.into_iter().map(|trovato| CrossRow {
                    chat: trovato.chat,
                    chat_id: Some(trovato.chat_id),
                    message_id: trovato.message_id.to_string(),
                    published_at: trovato.published_at,
                    who: trovato.who,
                    excerpt: trovato.excerpt,
                    found_by: BTreeSet::from([lettera]),
                }));
            }
        }
    }

    let before_union = righe.len();
    let rows = unite(righe);
    let indicators = indicators_of(&rows);

    let chiesti: Vec<&str> = rapporti
        .iter()
        .filter(|rapporto| rapporto.asked)
        .map(|rapporto| rapporto.letter)
        .collect();
    database.append_audit(&NewAuditEntry {
        actor: operator.clone(),
        action: AuditAction::try_new(CROSS_SEARCH_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("ricerca")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "rami {}, {} risultati, {} dopo l'unione",
            if chiesti.is_empty() {
                String::from("nessuno")
            } else {
                chiesti.join(" ")
            },
            before_union,
            rows.len()
        ))?),
        recorded_at: now,
    })?;

    Ok(Ok(CrossResult {
        rows,
        branches: rapporti,
        indicators,
        before_union,
    }))
}

/// I rami scelti nella schermata. La C chiede un numero di chat che si legga:
/// un numero che non si legge non si indovina.
///
/// # Errori
///
/// Restituisce la frase del rifiuto se la C è scelta senza un numero leggibile.
pub fn branches_of(a: bool, b: bool, c: bool, d: bool, chat: &str) -> Result<Branches, String> {
    let in_chat = if c {
        match Branch::in_chat(chat) {
            Some(Branch::InChat(numero)) => Some(numero),
            _ => {
                return Err(String::from(
                    "Per la C scrivere il numero della chat: si legge nella Ricerca puntuale o \
                     nelle Fonti. La ricerca non \u{e8} partita.",
                ));
            }
        }
    } else {
        None
    };
    Ok(Branches {
        archive: a,
        account_chats: b,
        in_chat,
        public_posts: d,
    })
}

/// Il perimetro di A, in una frase.
fn archive_scope() -> String {
    String::from(
        "Nell'archivio di questa postazione: i contenuti gi\u{e0} acquisiti da tutti i \
         monitoraggi, al pi\u{f9} i 50 pi\u{f9} recenti che contengono le parole.",
    )
}

/// Un ramo non scelto.
fn not_asked(letter: &'static str, scope: String) -> BranchReport {
    BranchReport {
        letter,
        asked: false,
        scope,
        outcome: String::from("Non scelto: qui non si \u{e8} cercato."),
        results: 0,
    }
}

/// I contenuti dell'archivio che contengono le parole, al più
/// [`ARCHIVE_ROWS`], con il ramo A.
fn archive_rows(
    history: &HistoryService,
    query: &str,
) -> ServiceResult<(Vec<CrossRow>, BranchReport)> {
    let filtro = HistoryFilter {
        query: query.to_owned(),
        ..HistoryFilter::default()
    };
    let trovati = history.matching(HistoryScope::Everything, &filtro)?;
    let quanti = trovati.len();
    let fonti = history.sources()?;
    let righe: Vec<CrossRow> = trovati
        .into_iter()
        .take(ARCHIVE_ROWS)
        .map(|voce| {
            let identificativo = fonti
                .iter()
                .find(|fonte| fonte.id == voce.content.source_id)
                .map(|fonte| fonte.identifier.as_str().to_owned());
            CrossRow {
                chat: format!("{} (fonte)", voce.source_name.as_str()),
                chat_id: identificativo.and_then(|scritto| scritto.trim().parse::<i64>().ok()),
                message_id: voce.content.remote_message_id.as_str().to_owned(),
                published_at: voce.content.published_at,
                who: voce.content.author.as_ref().map_or_else(
                    || String::from("Autore non dichiarato dalla fonte."),
                    |autore| format!("Scritto da {}.", autore.as_str()),
                ),
                excerpt: cyber_search::excerpt(voce.content.body.as_str()),
                found_by: BTreeSet::from(["A"]),
            }
        })
        .collect();
    let esito = match quanti {
        0 => String::from("Nessun contenuto dell'archivio contiene queste parole."),
        n if n > ARCHIVE_ROWS => format!(
            "{n} contenuti dell'archivio contengono queste parole: qui i {ARCHIVE_ROWS} pi\u{f9} \
             recenti, gli altri nello Storico."
        ),
        1 => String::from("Un contenuto dell'archivio contiene queste parole."),
        n => format!("{n} contenuti dell'archivio contengono queste parole."),
    };
    let rapporto = BranchReport {
        letter: "A",
        asked: true,
        scope: archive_scope(),
        outcome: esito,
        results: righe.len(),
    };
    Ok((righe, rapporto))
}

/// L'unione: lo stesso messaggio una volta, con tutte le provenienze; poi
/// l'ordine per data, dal più recente, stabile.
fn unite(righe: Vec<CrossRow>) -> Vec<CrossRow> {
    let mut uniti: Vec<CrossRow> = Vec::new();
    let mut indice: BTreeMap<(i64, String), usize> = BTreeMap::new();
    for riga in righe {
        let Some(chat) = riga.chat_id else {
            uniti.push(riga);
            continue;
        };
        let chiave = (chat, riga.message_id.clone());
        if let Some(&posizione) = indice.get(&chiave) {
            let gia = &mut uniti[posizione];
            gia.found_by.extend(riga.found_by);
            continue;
        }
        indice.insert(chiave, uniti.len());
        uniti.push(riga);
    }
    uniti.sort_by(|sinistra, destra| {
        destra
            .published_at
            .cmp(&sinistra.published_at)
            .then_with(|| sinistra.chat_id.cmp(&destra.chat_id))
            .then_with(|| sinistra.message_id.cmp(&destra.message_id))
    });
    uniti
}

/// Gli indicatori degli estratti, con quanti risultati e quante chat.
fn indicators_of(righe: &[CrossRow]) -> Vec<IndicatorCount> {
    let mut visti: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
    for riga in righe {
        for indicatore in extract(&riga.excerpt).indicators {
            let voce = visti.entry(indicatore.value).or_default();
            voce.0 += 1;
            voce.1.insert(riga.chat.clone());
        }
    }
    visti
        .into_iter()
        .map(|(value, (rows, chats))| IndicatorCount {
            value,
            rows,
            chats: chats.len(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lisi_core::Timestamp;
    use lisi_core::model::AcquisitionOrigin;
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, LanguageTag, RemoteMessageId, SourceIdentifier,
        TermCategory, TermText,
    };
    use lisi_storage::Database;
    use lisi_telegram::search::{PublicPostLimits, SearchPage, SearchQuery};
    use lisi_telegram::{
        ChatId, IncomingMessage, MessageId, MockTelegramConnector, TelegramConnector, TelegramError,
    };

    use super::{Branches, CrossRow, branches_of, search, unite};
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::history::HistoryService;
    use crate::sources::open_in_memory_database;

    const T0: i64 = 1_760_000_000_000;
    const THIS_MODULE: &str = include_str!("cross_search.rs");

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(T0)
    }

    fn registro() -> Database {
        let Ok(archivio) = open_in_memory_database() else {
            panic!("archivio in memoria");
        };
        archivio
    }

    fn configurazione() -> ResolvedDictionaryConfiguration {
        let mut resolver = ConfigurationResolver::new();
        let (Ok(testo), Ok(categoria), Ok(lingua)) = (
            TermText::try_new("molotov"),
            TermCategory::try_new("prova"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("valori del termine validi");
        };
        let Ok(()) = resolver.add(
            testo,
            categoria,
            lingua,
            MatchMode::NormalizedWord,
            3,
            TermProvenance::ad_hoc(),
        ) else {
            panic!("il termine doveva essere accettato");
        };
        resolver.finish()
    }

    /// Un archivio con la fonte `-1001` e i contenuti `(numero, testo)`.
    fn storico(contenuti: &[(&str, &str)]) -> HistoryService {
        let mut database = registro();
        let (Ok(identificativo), Ok(nome), Ok(etichetta)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
        ) else {
            panic!("valori di prova validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: operatore(),
                active: true,
            },
            adesso(),
        ) else {
            panic!("la fonte deve registrarsi");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            adesso(),
        ) else {
            panic!("la sessione deve crearsi");
        };
        let configurazione = configurazione();
        let mut analisi = AnalysisService::new(database);
        for (numero, testo) in contenuti {
            let (Ok(remoto), Ok(corpo)) = (
                RemoteMessageId::try_new(numero),
                ContentBody::try_new(testo),
            ) else {
                panic!("valori del contenuto validi");
            };
            let Ok(_) = analisi.analyse_and_record(
                &NewContentDraft {
                    session_id,
                    source_id,
                    remote_message_id: remoto,
                    author: None,
                    author_identifier: None,
                    author_username: None,
                    body: corpo,
                    url: None,
                    published_at: Timestamp::from_millis(T0 - 60_000),
                    acquired_at: adesso(),
                    origin: AcquisitionOrigin::Observed,
                },
                &configurazione,
                &operatore(),
                adesso(),
            ) else {
                panic!("l'analisi deve riuscire");
            };
        }
        HistoryService::new(analisi.into_database())
    }

    /// Un connettore simulato con l'accesso completato.
    fn pronto() -> MockTelegramConnector {
        use lisi_telegram::connector::ClientParameters;
        use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

        let mut connettore = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(&"a".repeat(32)))
        else {
            panic!("valori di prova validi");
        };
        let Ok(()) = connettore.start(&ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("."),
            use_test_datacenter: true,
            application_version: String::from("prova"),
            system_language_code: String::from("it"),
        }) else {
            panic!("avvio simulato");
        };
        let (Ok(telefono), Ok(codice)) = (
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("valori di prova validi");
        };
        let (Ok(()), Ok(())) = (
            connettore.submit_phone_number(&telefono),
            connettore.submit_code(&codice),
        ) else {
            panic!("accesso simulato");
        };
        connettore
    }

    /// Una pagina con i messaggi `(chat, numero, minuti prima di T0, testo)`.
    fn pagina(messaggi: &[(i64, i64, i64, &str)]) -> SearchPage {
        SearchPage {
            hits: messaggi
                .iter()
                .map(|(chat, numero, minuti, testo)| {
                    let (Ok(chat_id), Ok(message_id)) =
                        (ChatId::try_new(*chat), MessageId::try_new(*numero))
                    else {
                        panic!("identificativi validi");
                    };
                    IncomingMessage {
                        chat_id,
                        message_id,
                        author: None,
                        author_identifier: None,
                        author_username: None,
                        text: (*testo).to_owned(),
                        published_at_millis: T0 - minuti * 60_000,
                        url: None,
                        attachment: None,
                    }
                })
                .collect(),
            ..SearchPage::default()
        }
    }

    fn fatta(
        connettore: Option<&mut MockTelegramConnector>,
        db: &mut Database,
        storico: &HistoryService,
        rami: Branches,
        parole: &str,
    ) -> super::CrossResult {
        let connettore = connettore.map(|c| c as &mut dyn TelegramConnector);
        match search(
            connettore,
            db,
            storico,
            &operatore(),
            rami,
            parole,
            adesso(),
        ) {
            Ok(Ok(esito)) => esito,
            altro => panic!("la ricerca doveva farsi: {altro:?}"),
        }
    }

    /// **Una domanda su A e B: lo stesso messaggio una volta, con le due
    /// provenienze, e gli indicatori contati** (CYBER-SEARCH-03, criteri 1–3, 5;
    /// prova negativa: unione tolta → rossa).
    #[test]
    fn una_domanda_su_piu_rami_si_unisce_e_dice_le_provenienze() {
        let storico = storico(&[("7", "nuovo ransomware da 192.0.2.45")]);
        let mut db = registro();
        let mut connettore = pronto();
        connettore.queue_search_reply(Ok(pagina(&[
            (-1001, 7, 1, "nuovo ransomware da 192.0.2.45"),
            (-1002, 3, 5, "ransomware, stesso 192.0.2.45"),
        ])));
        let esito = fatta(
            Some(&mut connettore),
            &mut db,
            &storico,
            Branches {
                archive: true,
                account_chats: true,
                ..Branches::default()
            },
            "ransomware",
        );
        assert_eq!(esito.before_union, 3);
        assert_eq!(esito.rows.len(), 2, "lo stesso messaggio compare una volta");
        let unito = &esito.rows[0];
        assert_eq!(unito.message_id, "7");
        assert_eq!(unito.found_by, BTreeSet::from(["A", "B"]));
        assert!(unito.chat.contains("Canale di prova"), "{}", unito.chat);
        assert_eq!(esito.indicators.len(), 1);
        assert_eq!(esito.indicators[0].value, "192.0.2.45");
        assert_eq!(
            (esito.indicators[0].rows, esito.indicators[0].chats),
            (2, 2)
        );
        let lettere: Vec<(&str, bool)> = esito
            .branches
            .iter()
            .map(|ramo| (ramo.letter, ramo.asked))
            .collect();
        assert_eq!(
            lettere,
            [("A", true), ("B", true), ("C", false), ("D", false)]
        );
        assert!(esito.branches[3].outcome.contains("Non scelto"));
        assert_eq!(
            connettore.searched().len(),
            1,
            "soltanto la B chiesta a Telegram"
        );
        assert!(
            connettore.limits_asked().is_empty(),
            "la D non scelta non legge la quota"
        );
    }

    /// **La D parte soltanto se scelta, con la quota** (criterio 1).
    #[test]
    fn la_d_parte_soltanto_se_scelta() {
        let storico = storico(&[]);
        let mut db = registro();
        let mut connettore = pronto();
        connettore.queue_limits_reply(Ok(PublicPostLimits {
            daily_free: 10,
            remaining_free: 3,
            next_free_in_seconds: 0,
            star_count: 10,
            current_query_free: true,
        }));
        connettore.queue_search_reply(Ok(pagina(&[(-1003, 1, 1, "#ransomware")])));
        let esito = fatta(
            Some(&mut connettore),
            &mut db,
            &storico,
            Branches {
                public_posts: true,
                ..Branches::default()
            },
            "#ransomware",
        );
        assert_eq!(connettore.limits_asked(), ["#ransomware"]);
        assert!(matches!(
            connettore.searched(),
            [SearchQuery::PublicPosts { .. }]
        ));
        assert_eq!(esito.rows.len(), 1);
        assert_eq!(esito.rows[0].found_by, BTreeSet::from(["D"]));
    }

    /// **Senza rami, con parole fuori misura o con una C senza numero non
    /// parte nulla** (criterio 1).
    #[test]
    fn senza_rami_o_parole_non_parte_nulla() {
        let storico = storico(&[]);
        let mut db = registro();
        let mut connettore = pronto();
        for (rami, parole) in [
            (Branches::default(), "ransomware"),
            (
                Branches {
                    account_chats: true,
                    ..Branches::default()
                },
                "x",
            ),
        ] {
            assert!(matches!(
                search(
                    Some(&mut connettore as &mut dyn TelegramConnector),
                    &mut db,
                    &storico,
                    &operatore(),
                    rami,
                    parole,
                    adesso()
                ),
                Ok(Err(_))
            ));
        }
        assert!(connettore.searched().is_empty());
        assert!(branches_of(false, false, true, false, "non un numero").is_err());
        assert!(matches!(
            branches_of(true, false, true, false, "-1001"),
            Ok(Branches { archive: true, in_chat: Some(chat), .. }) if chat.get() == -1001
        ));
    }

    /// **Un ramo che fallisce non nasconde gli altri, e lo dice** (criterio 4).
    #[test]
    fn un_ramo_che_fallisce_non_nasconde_gli_altri() {
        let storico = storico(&[("7", "ransomware")]);
        let mut db = registro();
        let mut connettore = pronto();
        connettore.queue_search_reply(Err(TelegramError::Tdlib {
            reason: String::from("errore del componente per Telegram 400: CHANNEL_PRIVATE"),
        }));
        let esito = fatta(
            Some(&mut connettore),
            &mut db,
            &storico,
            Branches {
                archive: true,
                account_chats: true,
                ..Branches::default()
            },
            "ransomware",
        );
        assert_eq!(esito.rows.len(), 1, "il risultato di A resta");
        assert!(esito.branches[1].outcome.contains("CHANNEL_PRIVATE"));

        let senza = fatta(
            None,
            &mut db,
            &storico,
            Branches {
                archive: true,
                account_chats: true,
                ..Branches::default()
            },
            "ransomware",
        );
        assert_eq!(senza.rows.len(), 1);
        assert!(!senza.branches[1].asked);
        assert!(
            senza.branches[1].outcome.contains("account"),
            "{}",
            senza.branches[1].outcome
        );
    }

    /// **L'unione è stabile, e un contenuto senza numero di chat resta da
    /// solo** (criteri 2 e 3).
    #[test]
    fn l_unione_e_stabile_e_senza_numero_resta_da_solo() {
        let riga = |chat: Option<i64>, numero: &str, minuti: i64, ramo: &'static str| CrossRow {
            chat: String::from("chat"),
            chat_id: chat,
            message_id: numero.to_owned(),
            published_at: Timestamp::from_millis(T0 - minuti * 60_000),
            who: String::new(),
            excerpt: String::new(),
            found_by: BTreeSet::from([ramo]),
        };
        let uniti = unite(vec![
            riga(None, "7", 1, "A"),
            riga(Some(-1001), "7", 1, "B"),
            riga(Some(-1001), "7", 1, "D"),
            riga(Some(-1002), "1", 9, "B"),
            riga(Some(-1001), "2", 1, "C"),
        ]);
        assert_eq!(uniti.len(), 4);
        let ordine: Vec<(Option<i64>, &str)> = uniti
            .iter()
            .map(|r| (r.chat_id, r.message_id.as_str()))
            .collect();
        assert_eq!(
            ordine,
            [
                (None, "7"),
                (Some(-1001), "2"),
                (Some(-1001), "7"),
                (Some(-1002), "1")
            ]
        );
        assert_eq!(uniti[2].found_by, BTreeSet::from(["B", "D"]));
    }

    /// **Si registra la ricerca, senza testi; i risultati non sono acquisizioni**
    /// (criterio 6).
    #[test]
    fn si_registra_la_ricerca_senza_testi() {
        let storico = storico(&[("7", "testo riservato ransomware")]);
        let mut db = registro();
        let _ = fatta(
            None,
            &mut db,
            &storico,
            Branches {
                archive: true,
                ..Branches::default()
            },
            "ransomware",
        );
        let Ok(voci) = db.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == super::CROSS_SEARCH_AUDIT_ACTION)
        else {
            panic!("la ricerca trasversale si registra");
        };
        let dettaglio = voce
            .detail
            .as_ref()
            .map(|d| d.as_str().to_owned())
            .unwrap_or_default();
        assert!(dettaglio.contains("rami A"), "{dettaglio}");
        assert!(!dettaglio.contains("riservato"), "nessun testo nell'audit");

        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        for vietato in [
            "insert_content",
            "analyse_and_record",
            "star_count",
            "insert_cyber_search(",
        ] {
            assert!(!produzione.contains(vietato), "«{vietato}»");
        }
    }
}

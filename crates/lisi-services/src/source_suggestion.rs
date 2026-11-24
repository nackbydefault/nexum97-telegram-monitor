//! I suggerimenti di fonti, da ciò che l'ufficio ha già acquisito
//! (SOURCE-SUGGEST-01, ADR-0164).
//!
//! # Da dove nascono
//!
//! Soltanto dai contenuti acquisiti: un collegamento a un **post** di una chat
//! pubblica (`t.me/nome/numero`) dice che la chat esiste e che una fonte
//! sorvegliata la cita. Una menzione `@nome` o un `t.me/nome` senza post non
//! si suggeriscono: possono essere persone.
//!
//! # Che cosa non fa
//!
//! Non chiede nulla a Telegram per suggerire: la scoperta pubblica resta
//! chiusa dal suo cancello (ADR-0074). Non entra da nessuna parte. Non
//! aggiunge da sé: aggiungere passa dalla pagina Fonti, soltanto per una chat
//! già accessibile all'account, una per volta, con chi e quando.

use std::collections::{BTreeMap, BTreeSet};

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::discovery::PublicAddress;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;
use lisi_storage::repository::source_suggestion::NewSuggestionDecision;
use lisi_telegram::TelegramConnector;

use crate::error::{ServiceError, ServiceResult};
use crate::history::{HistoryScope, HistoryService};
use crate::sources::SourceService;

/// Quanti suggerimenti, al più.
pub const MAX_SUGGESTIONS: usize = 100;
/// Quanti caratteri, almeno, nel motivo per ignorare.
pub const MIN_REASON_CHARS: usize = 5;

/// I primi segmenti che non sono il nome di una chat pubblica.
const NOT_A_CHAT: [&str; 18] = [
    "joinchat",
    "addstickers",
    "addemoji",
    "addlist",
    "addtheme",
    "share",
    "proxy",
    "socks",
    "iv",
    "c",
    "login",
    "boost",
    "setlanguage",
    "bg",
    "invoice",
    "giftcode",
    "m",
    "confirmphone",
];

/// Un suggerimento, con il suo motivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// L'indirizzo pubblico della chat citata.
    pub address: PublicAddress,
    /// Quante volte è citata.
    pub mentions: usize,
    /// In quanti contenuti.
    pub contents: usize,
    /// Da quali fonti, per nome.
    pub sources: BTreeSet<String>,
    /// La prima citazione, per data di pubblicazione.
    pub first_at: Timestamp,
    /// L'ultima.
    pub last_at: Timestamp,
}

impl Suggestion {
    /// Il motivo, in una frase. **Citare non è garantire.**
    #[must_use]
    pub fn reason(&self) -> String {
        let fonti: Vec<&str> = self.sources.iter().map(String::as_str).collect();
        let contenuti = if self.contents == 1 {
            String::from("un contenuto")
        } else {
            format!("{} contenuti", self.contents)
        };
        let volte = if self.mentions == 1 {
            String::from("una volta")
        } else {
            format!("{} volte", self.mentions)
        };
        format!(
            "Un post di questa chat \u{e8} citato {volte} in {contenuti} di {}, dal {} al {}. \
             Citare non \u{e8} garantire: \u{e8} un indizio, non una valutazione della fonte.",
            fonti.join(", "),
            self.first_at.to_readable_local(),
            self.last_at.to_readable_local()
        )
    }
}

/// Gli indirizzi delle chat pubbliche di cui un testo cita un **post**, una
/// volta ciascuno, nell'ordine in cui compaiono.
#[must_use]
pub fn cited_post_addresses(testo: &str) -> Vec<PublicAddress> {
    let minuscolo = testo.to_ascii_lowercase();
    let mut trovati: Vec<PublicAddress> = Vec::new();
    let mut visti: BTreeSet<String> = BTreeSet::new();
    for dominio in ["t.me/", "telegram.me/"] {
        let mut da = 0;
        while let Some(posizione) = minuscolo.get(da..).and_then(|resto| resto.find(dominio)) {
            let inizio = da + posizione;
            da = inizio + dominio.len();
            // «xt.me/» non è t.me: il dominio comincia dopo un separatore.
            let prima = minuscolo
                .get(..inizio)
                .and_then(|davanti| davanti.chars().next_back());
            if prima.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
                continue;
            }
            let percorso: String = testo
                .get(da..)
                .unwrap_or_default()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/' | '+'))
                .collect();
            let mut segmenti = percorso.split('/').filter(|segmento| !segmento.is_empty());
            let mut nome = segmenti.next().unwrap_or_default();
            // `t.me/s/nome/numero` è l'anteprima web dello stesso post.
            if nome.eq_ignore_ascii_case("s") {
                nome = segmenti.next().unwrap_or_default();
            }
            let post = segmenti.next().unwrap_or_default();
            if nome.starts_with('+')
                || NOT_A_CHAT
                    .iter()
                    .any(|riservato| nome.eq_ignore_ascii_case(riservato))
                || post.is_empty()
                || !post.bytes().all(|byte| byte.is_ascii_digit())
            {
                continue;
            }
            let Some(indirizzo) = PublicAddress::try_new(nome) else {
                continue;
            };
            if visti.insert(indirizzo.as_str().to_ascii_lowercase()) {
                trovati.push(indirizzo);
            }
        }
    }
    trovati
}

/// I suggerimenti, dal più citato: i contenuti dell'archivio, meno le chat già
/// decise e quelle già fra le fonti per indirizzo.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge.
pub fn suggestions(
    history: &HistoryService,
    database: &Database,
) -> ServiceResult<Vec<Suggestion>> {
    let decisi: BTreeSet<String> = database
        .suggestion_decisions()?
        .into_iter()
        .map(|decisione| decisione.address)
        .collect();
    let gia_fonti: BTreeSet<String> = history
        .sources()?
        .into_iter()
        .map(|fonte| fonte.identifier.as_str().to_ascii_lowercase())
        .collect();

    let mut raccolti: BTreeMap<String, Suggestion> = BTreeMap::new();
    for voce in history.entries(HistoryScope::Everything)? {
        let testo = voce.content.body.as_str();
        for indirizzo in cited_post_addresses(testo) {
            let chiave = indirizzo.as_str().to_ascii_lowercase();
            if decisi.contains(&chiave) || gia_fonti.contains(&chiave) {
                continue;
            }
            let volte = testo
                .to_ascii_lowercase()
                .matches(&format!("/{chiave}/"))
                .count()
                .max(1);
            let quando = voce.content.published_at;
            let fonte = voce.source_name.as_str().to_owned();
            raccolti
                .entry(chiave)
                .and_modify(|gia| {
                    gia.mentions += volte;
                    gia.contents += 1;
                    gia.sources.insert(fonte.clone());
                    gia.first_at = gia.first_at.min(quando);
                    gia.last_at = gia.last_at.max(quando);
                })
                .or_insert_with(|| Suggestion {
                    address: indirizzo,
                    mentions: volte,
                    contents: 1,
                    sources: BTreeSet::from([fonte.clone()]),
                    first_at: quando,
                    last_at: quando,
                });
        }
    }
    let mut elenco: Vec<Suggestion> = raccolti.into_values().collect();
    elenco.sort_by(|sinistra, destra| {
        destra
            .contents
            .cmp(&sinistra.contents)
            .then_with(|| destra.last_at.cmp(&sinistra.last_at))
            .then_with(|| sinistra.address.cmp(&destra.address))
    });
    elenco.truncate(MAX_SUGGESTIONS);
    Ok(elenco)
}

/// Ignora un suggerimento, con il motivo: non torna, e la decisione resta.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si scrive; un rifiuto è
/// `Ok(Err(frase))`.
pub fn ignore(
    database: &mut Database,
    operator: &Actor,
    address: &str,
    reason: &str,
    now: Timestamp,
) -> ServiceResult<Result<(), String>> {
    let Some(indirizzo) = PublicAddress::try_new(address) else {
        return Ok(Err(String::from(
            "Questo indirizzo non \u{e8} quello di una chat pubblica.",
        )));
    };
    let motivo = reason.trim();
    if motivo.chars().count() < MIN_REASON_CHARS {
        return Ok(Err(format!(
            "Scrivere perch\u{e9} si ignora il suggerimento, almeno {MIN_REASON_CHARS} caratteri: \
             la decisione resta con il motivo."
        )));
    }
    record(
        database, operator, &indirizzo, "ignorato", motivo, None, now,
    )?;
    Ok(Ok(()))
}

/// Aggiunge come fonte la chat suggerita, **soltanto** se è fra le chat già
/// accessibili all'account: con la stessa strada e la stessa firma della
/// pagina Fonti.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si scrive; un rifiuto è
/// `Ok(Err(frase))`.
pub fn add(
    connector: Option<&mut dyn TelegramConnector>,
    sources: &SourceService,
    database: &mut Database,
    operator: &Actor,
    address: &str,
    now: Timestamp,
) -> ServiceResult<Result<i64, String>> {
    let Some(indirizzo) = PublicAddress::try_new(address) else {
        return Ok(Err(String::from(
            "Questo indirizzo non \u{e8} quello di una chat pubblica.",
        )));
    };
    let Some(connector) = connector else {
        return Ok(Err(String::from(
            "Non c'\u{e8} un account collegato: una fonte si aggiunge soltanto fra le chat \
             accessibili all'account, e nulla \u{e8} stato aggiunto.",
        )));
    };
    let Ok(chat) = connector.accessible_chats() else {
        return Ok(Err(String::from(
            "L'elenco delle chat dell'account non si \u{e8} potuto leggere: nulla \u{e8} stato \
             aggiunto.",
        )));
    };
    let Some(accessibile) = chat.into_iter().find(|chat| {
        chat.username
            .as_deref()
            .is_some_and(|nome| nome.eq_ignore_ascii_case(indirizzo.as_str()))
    }) else {
        return Ok(Err(format!(
            "@{} non \u{e8} fra le chat accessibili all'account: per sorvegliarla l'account \
             dovrebbe gi\u{e0} farne parte, e il programma non entra da nessuna parte. Nulla \
             \u{e8} stato aggiunto.",
            indirizzo.as_str()
        )));
    };
    let fonte = match sources.add(connector, accessibile.chat_id.get(), operator, now) {
        Ok(fonte) => fonte,
        Err(ServiceError::SourceAlreadyConfigured) => {
            return Ok(Err(String::from(
                "Questa chat \u{e8} gi\u{e0} fra le fonti: nulla \u{e8} cambiato.",
            )));
        }
        Err(ServiceError::SourceNotAccessible) => {
            return Ok(Err(String::from(
                "L'account non pu\u{f2} leggere lo storico di questa chat: non \u{e8} \
                 monitorabile, e nulla \u{e8} stato aggiunto.",
            )));
        }
        Err(altro) => return Err(altro),
    };
    record(
        database,
        operator,
        &indirizzo,
        "aggiunto",
        "aggiunta come fonte: chat gi\u{e0} accessibile all'account",
        Some(fonte.get()),
        now,
    )?;
    Ok(Ok(fonte.get()))
}

/// Registra la decisione, con l'audit nella stessa transazione.
fn record(
    database: &mut Database,
    operator: &Actor,
    indirizzo: &PublicAddress,
    decisione: &'static str,
    motivo: &str,
    fonte: Option<i64>,
    now: Timestamp,
) -> ServiceResult<()> {
    let audit = NewAuditEntry {
        actor: operator.clone(),
        action: AuditAction::try_new(if fonte.is_some() {
            "suggerimento_aggiunto"
        } else {
            "suggerimento_ignorato"
        })?,
        entity: AuditEntity::try_new("suggerimento_fonte")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "@{}: {decisione} \u{2014} {motivo}",
            indirizzo.as_str()
        ))?),
        recorded_at: now,
    };
    database.insert_suggestion_decision(
        &NewSuggestionDecision {
            address: indirizzo.as_str().to_ascii_lowercase(),
            decision: decisione,
            actor: operator.as_str().to_owned(),
            reason: motivo.to_owned(),
            decided_at: now,
            source_id: fonte,
        },
        &audit,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
    use lisi_telegram::{
        AccessibleChat, ChatId, ChatKind, MockTelegramConnector, TelegramConnector,
    };

    use super::{add, cited_post_addresses, ignore, suggestions};
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::history::HistoryService;
    use crate::sources::{SourceService, open_in_memory_database};

    const T0: i64 = 1_760_000_000_000;
    const THIS_MODULE: &str = include_str!("source_suggestion.rs");

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(T0)
    }

    fn archivio() -> Database {
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

    /// Un archivio con una fonte e i contenuti `(minuti dopo T0, testo)`.
    fn storico(contenuti: &[(i64, &str)]) -> HistoryService {
        let mut database = archivio();
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
        for (indice, (minuti, testo)) in contenuti.iter().enumerate() {
            let (Ok(remoto), Ok(corpo)) = (
                RemoteMessageId::try_new(&format!("m{indice}")),
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
                    published_at: Timestamp::from_millis(T0 + minuti * 60_000),
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

    /// Un connettore con l'accesso completato e le chat indicate.
    fn pronto(chat: Vec<AccessibleChat>) -> MockTelegramConnector {
        use lisi_telegram::connector::ClientParameters;
        use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

        let mut connettore = MockTelegramConnector::new().with_accessible_chats(chat);
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

    fn chat(numero: i64, nome: &str) -> AccessibleChat {
        let Ok(chat_id) = ChatId::try_new(numero) else {
            panic!("identificativo valido");
        };
        AccessibleChat {
            chat_id,
            title: format!("Chat {nome}"),
            kind: ChatKind::Channel,
            username: Some(nome.to_owned()),
            can_read_history: true,
        }
    }

    /// **Si suggerisce una chat di cui è citato un post; una persona, un
    /// invito o una chat privata no** (SOURCE-SUGGEST-01, criteri 1 e 2; prova
    /// negativa: richiesta del post tolta → rossa).
    #[test]
    fn i_post_citati_si_riconoscono_e_le_persone_no() {
        let testo = "Vedi https://t.me/canale_cyber/123 e t.me/s/altro_canale/45, poi \
                     telegram.me/Terzo_Canale/7. Scrivete a @mario_rossi o t.me/mario_rossi; \
                     invito t.me/+AbCdEfGh e t.me/joinchat/xyz, privato t.me/c/123456/7, \
                     falso xt.me/falso_canale/1, corto t.me/abc/1, doppio t.me/Canale_Cyber/124.";
        let trovati: Vec<String> = cited_post_addresses(testo)
            .iter()
            .map(|indirizzo| indirizzo.as_str().to_owned())
            .collect();
        assert_eq!(trovati, ["canale_cyber", "altro_canale", "Terzo_Canale"]);
    }

    /// **I suggerimenti dicono il motivo, dal più citato, e una chat ignorata
    /// non torna** (criteri 3 e 4).
    #[test]
    fn i_suggerimenti_dicono_il_motivo_e_una_ignorata_non_torna() {
        let storico = storico(&[
            (1, "allerta da t.me/canale_cyber/10"),
            (
                2,
                "ancora https://t.me/canale_cyber/11 e t.me/altro_canale/3",
            ),
            (3, "nessun collegamento qui"),
        ]);
        let mut db = archivio();
        let Ok(elenco) = suggestions(&storico, &db) else {
            panic!("i suggerimenti devono leggersi");
        };
        assert_eq!(elenco.len(), 2);
        assert_eq!(elenco[0].address.as_str(), "canale_cyber");
        assert_eq!(elenco[0].contents, 2);
        let motivo = elenco[0].reason();
        assert!(
            motivo.contains("in 2 contenuti di Canale di prova"),
            "{motivo}"
        );
        assert!(motivo.contains("Citare non \u{e8} garantire"), "{motivo}");

        assert!(matches!(
            ignore(&mut db, &operatore(), "canale_cyber", "no", adesso()),
            Ok(Err(_))
        ));
        assert_eq!(
            ignore(
                &mut db,
                &operatore(),
                "canale_cyber",
                "fuori dall'indagine",
                adesso()
            )
            .ok(),
            Some(Ok(()))
        );
        let Ok(dopo) = suggestions(&storico, &db) else {
            panic!("i suggerimenti devono leggersi");
        };
        assert_eq!(dopo.len(), 1, "l'ignorata non torna");
        assert_eq!(dopo[0].address.as_str(), "altro_canale");
    }

    /// **Si aggiunge soltanto una chat già accessibile all'account, con la
    /// strada della pagina Fonti; altrimenti nulla** (criterio 5; prova
    /// negativa: controllo dell'accessibilità tolto → rossa).
    #[test]
    fn si_aggiunge_soltanto_una_chat_accessibile() {
        let mut db = archivio();
        let fonti = SourceService::new(archivio());
        let mut connettore = pronto(vec![chat(-1002, "Canale_Cyber")]);

        let Ok(Err(frase)) = add(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &fonti,
            &mut db,
            &operatore(),
            "altro_canale",
            adesso(),
        ) else {
            panic!("una chat non accessibile non si aggiunge");
        };
        assert!(frase.contains("non entra da nessuna parte"), "{frase}");
        assert!(fonti.configured().map(|f| f.is_empty()).unwrap_or(false));

        let Ok(Ok(_)) = add(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &fonti,
            &mut db,
            &operatore(),
            "canale_cyber",
            adesso(),
        ) else {
            panic!("una chat accessibile si aggiunge");
        };
        let Ok(configurate) = fonti.configured() else {
            panic!("le fonti devono leggersi");
        };
        assert_eq!(configurate.len(), 1);
        assert_eq!(configurate[0].identifier.as_str(), "-1002");
        let Ok(decisioni) = db.suggestion_decisions() else {
            panic!("le decisioni devono leggersi");
        };
        assert_eq!(
            decisioni.len(),
            1,
            "soltanto l'aggiunta riuscita si registra"
        );
        assert_eq!(decisioni[0].decision, "aggiunto");

        assert!(matches!(
            add(
                None,
                &fonti,
                &mut db,
                &operatore(),
                "canale_cyber",
                adesso()
            ),
            Ok(Err(_))
        ));
    }

    /// **Per suggerire non si chiede nulla a Telegram, e non si aggiunge una
    /// fonte se non dalla pagina Fonti** (criteri 1 e 6).
    #[test]
    fn per_suggerire_non_si_chiede_nulla_a_telegram() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        for vietato in [
            "searchPublicChats",
            "getChatSimilarChats",
            "joinChat",
            "validated_policy",
            "insert_source",
            "discovery_gate",
        ] {
            assert!(!produzione.contains(vietato), "«{vietato}»");
        }
        assert_eq!(
            produzione.matches(".accessible_chats()").count(),
            1,
            "una sola lettura, quella che verifica l'accessibilità"
        );
        assert_eq!(produzione.matches("sources.add(").count(), 1);
    }
}

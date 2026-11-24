//! La ricerca ricorrente **E**: una ricerca B, C o D salvata, che si ripete a
//! programma aperto dentro un budget dichiarato (CYBER-WATCH-02, ADR-0162).
//!
//! # Che cosa fa
//!
//! A ogni occasione — il programma la offre al più una volta al minuto —
//! esegue **una** ricorrente scaduta: una pagina, con il servizio delle
//! ricerche ([`crate::cyber_search`]), che registra la pagina e conta il tetto
//! orario. Poi tiene soltanto le **novità**: i messaggi pubblicati dopo il più
//! recente già visto da quella ricorrente. Le novità si mostrano e non si
//! conservano; si conserva la data del più recente, non il messaggio.
//!
//! # Limiti dichiarati, scelti e non misurati
//!
//! Intervallo da [`MIN_INTERVAL_MINUTES`] a [`MAX_INTERVAL_MINUTES`] minuti; al
//! più [`MAX_LIVE`] ricorrenti non ritirate; una pagina per esecuzione; al più
//! [`MAX_PAGES_PER_HOUR`] pagine all'ora per tutte le ricorrenti, dentro il
//! tetto comune di [`crate::cyber_search::MAX_PER_HOUR`]; per la D la riserva
//! di metà della quota gratuita a chi cerca a mano.
//!
//! # Che cosa non fa
//!
//! Non si ripete a programma chiuso, non avvia il monitoraggio ordinario
//! (DEC-412, decisione 1), non spende Stelle, non acquisisce.

use std::collections::HashSet;

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;
use lisi_storage::repository::recurring_search::{
    NewRecurringRun, NewRecurringSearch, StoredRecurringSearch,
};
use lisi_telegram::{AuthorizationState, TelegramConnector};

use crate::cyber_search::{self, Attempt, Branch, Hit};
use crate::error::ServiceResult;

/// L'intervallo più breve, in minuti.
pub const MIN_INTERVAL_MINUTES: u32 = 60;
/// L'intervallo più lungo, in minuti.
pub const MAX_INTERVAL_MINUTES: u32 = 1_440;
/// Quante ricorrenti non ritirate, al più, per postazione.
pub const MAX_LIVE: usize = 10;
/// Quante pagine all'ora, al più, per tutte le ricorrenti insieme.
pub const MAX_PAGES_PER_HOUR: u32 = 10;

const MINUTO: i64 = 60_000;
const ORA: i64 = 3_600_000;
/// Quante esecuzioni si leggono per dire la copertura.
const RUNS_FOR_COVERAGE: u32 = 20;

/// Una ricorrente, come si mostra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecurringView {
    /// Il numero.
    pub id: i64,
    /// Ramo, parole e intervallo, in una riga.
    pub title: String,
    /// Se è sospesa.
    pub suspended: bool,
    /// L'ultima esecuzione e la copertura, in frasi.
    pub coverage: String,
}

/// Che cosa ha fatto un'esecuzione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// Quale ricorrente.
    pub recurring_id: i64,
    /// I messaggi nuovi, nell'ordine di Telegram. **Non sono acquisizioni.**
    pub novelties: Vec<Hit>,
    /// Che cosa è successo, in una frase.
    pub sentence: String,
}

/// Legge l'intervallo scritto in ore, da 1 a 24.
///
/// # Errori
///
/// Restituisce la frase del rifiuto se le ore non si leggono o sono fuori
/// misura.
pub fn read_hours(scritto: &str) -> Result<u32, String> {
    let ore = scritto
        .trim()
        .parse::<u32>()
        .map_err(|_| String::from("Scrivere ogni quante ore ripetere la ricerca, da 1 a 24."))?;
    let minuti = ore.saturating_mul(60);
    if (MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&minuti) {
        Ok(minuti)
    } else {
        Err(format!(
            "Una ricerca ricorrente si ripete ogni 1 a 24 ore; ne sono state scritte {ore}."
        ))
    }
}

/// Salva una ricorrente, con l'audit.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si legge o non si scrive;
/// un rifiuto è `Ok(Err(frase))`.
pub fn save(
    database: &mut Database,
    operator: &Actor,
    branch: Branch,
    testo: &str,
    interval_minutes: u32,
    now: Timestamp,
) -> ServiceResult<Result<i64, String>> {
    let query = match cyber_search::read_query(testo) {
        Ok(query) => query,
        Err(frase) => return Ok(Err(frase)),
    };
    if !(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&interval_minutes) {
        return Ok(Err(String::from(
            "Una ricerca ricorrente si ripete ogni 1 a 24 ore.",
        )));
    }
    if database.recurring_searches()?.len() >= MAX_LIVE {
        return Ok(Err(format!(
            "Ci sono gi\u{e0} {MAX_LIVE} ricerche ricorrenti su questa postazione: per salvarne \
             un'altra, ritirarne una."
        )));
    }
    let nuova = NewRecurringSearch {
        branch: branch.letter(),
        query,
        chat_id: branch.chat_id(),
        interval_minutes,
        created_by: operator.as_str().to_owned(),
        created_at: now,
    };
    let audit = audit_of(
        operator,
        "ricerca_ricorrente_salvata",
        &format!("ramo {}, ogni {} minuti", nuova.branch, interval_minutes),
        now,
    )?;
    Ok(Ok(database.insert_recurring_search(&nuova, &audit)?))
}

/// Sospende o riprende una ricorrente, con l'audit.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si scrive; una ricorrente
/// che non c'è più è `Ok(Err(frase))`.
pub fn set_suspended(
    database: &mut Database,
    operator: &Actor,
    id: i64,
    sospesa: bool,
    now: Timestamp,
) -> ServiceResult<Result<(), String>> {
    let azione = if sospesa {
        "ricerca_ricorrente_sospesa"
    } else {
        "ricerca_ricorrente_ripresa"
    };
    let audit = audit_of(operator, azione, &format!("ricorrente {id}"), now)?;
    if database.set_recurring_search_suspended(id, sospesa, &audit)? {
        Ok(Ok(()))
    } else {
        Ok(Err(String::from(
            "Questa ricerca ricorrente non c'\u{e8} pi\u{f9}: \u{e8} stata ritirata.",
        )))
    }
}

/// Ritira una ricorrente, con l'audit. Non si cancella, e non torna.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si scrive; una ricorrente
/// già ritirata è `Ok(Err(frase))`.
pub fn withdraw(
    database: &mut Database,
    operator: &Actor,
    id: i64,
    now: Timestamp,
) -> ServiceResult<Result<(), String>> {
    let audit = audit_of(
        operator,
        "ricerca_ricorrente_ritirata",
        &format!("ricorrente {id}"),
        now,
    )?;
    if database.withdraw_recurring_search(id, operator.as_str(), now, &audit)? {
        Ok(Ok(()))
    } else {
        Ok(Err(String::from(
            "Questa ricerca ricorrente era gi\u{e0} stata ritirata.",
        )))
    }
}

/// Le ricorrenti non ritirate, con l'ultima esecuzione e la copertura.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge.
pub fn list(database: &Database, now: Timestamp) -> ServiceResult<Vec<RecurringView>> {
    let mut viste = Vec::new();
    for ricorrente in database.recurring_searches()? {
        let coverage = coverage_of(database, &ricorrente, now)?;
        viste.push(RecurringView {
            id: ricorrente.id,
            title: title_of(&ricorrente),
            suspended: ricorrente.suspended,
            coverage,
        });
    }
    Ok(viste)
}

/// Esegue **una** ricorrente scaduta, se ce n'è una: la più in ritardo.
/// Senza connettore non fa nulla e non registra nulla: il tempo senza ricerca
/// lo dice la copertura.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si legge o non si scrive.
pub fn run_due(
    connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    operator: &Actor,
    now: Timestamp,
) -> ServiceResult<Option<RunReport>> {
    let Some(connector) = connector else {
        return Ok(None);
    };
    // Prima dell'accesso completato non si chiede nulla, e non si registra
    // nulla: il tempo senza ricerca lo dice la copertura.
    if connector.authorization_state() != AuthorizationState::Ready {
        return Ok(None);
    }
    let Some((ricorrente, branch)) = most_overdue(database, now)? else {
        return Ok(None);
    };

    // IL BUDGET DELLE RICORRENTI, PRIMA DI CHIEDERE (ADR-0162, decisione 3).
    let dal = Timestamp::from_millis(now.as_millis() - ORA);
    if database.recurring_pages_since(dal)? >= MAX_PAGES_PER_HOUR {
        let frase = format!(
            "Le ricerche ricorrenti hanno gi\u{e0} chiesto {MAX_PAGES_PER_HOUR} pagine \
             nell'ultima ora: questa esecuzione \u{e8} saltata, e si riprova al prossimo \
             intervallo."
        );
        return skipped(database, ricorrente.id, now, frase);
    }

    let esito = cyber_search::start_recurring(
        Some(connector),
        database,
        operator,
        branch,
        &ricorrente.query,
        now,
    )?;
    let ricerca = match esito {
        Attempt::Refused(frase) => return skipped(database, ricorrente.id, now, frase),
        Attempt::Done(ricerca) => ricerca,
    };

    // LE NOVITÀ: DOPO IL PIÙ RECENTE GIÀ VISTO, UNA VOLTA SOLA (decisione 4).
    let gia_visto = database.recurring_newest_seen(ricorrente.id)?;
    let mut viste = HashSet::new();
    let novelties: Vec<Hit> = ricerca
        .hits
        .iter()
        .filter(|trovato| gia_visto.is_none_or(|soglia| trovato.published_at > soglia))
        .filter(|trovato| viste.insert((trovato.chat_id, trovato.message_id)))
        .cloned()
        .collect();
    let newest_published_at = ricerca
        .hits
        .iter()
        .map(|trovato| trovato.published_at)
        .max();
    let page_full = ricerca.can_continue();
    let quante = novelties.len();

    let (outcome, mut sentence) = match ricerca.last_code() {
        "trovati" | "nessun_risultato" if quante == 1 => (
            "novita",
            String::from("Un messaggio nuovo dall'ultima esecuzione. Non \u{e8} acquisito."),
        ),
        "trovati" | "nessun_risultato" if quante > 1 => (
            "novita",
            format!("{quante} messaggi nuovi dall'ultima esecuzione. Non sono acquisiti."),
        ),
        "trovati" | "nessun_risultato" => (
            "nessuna_novita",
            String::from("Nessun messaggio nuovo dall'ultima esecuzione."),
        ),
        "rifiutata" => ("rifiutata", ricerca.last_outcome.clone()),
        _ => ("non_riuscita", ricerca.last_outcome.clone()),
    };
    if page_full {
        sentence.push_str(
            " La pagina era piena: possono esserci altri messaggi, pi\u{f9} vecchi, che questa \
             esecuzione non ha letto.",
        );
    }
    database.insert_recurring_run(&NewRecurringRun {
        recurring_id: ricorrente.id,
        ran_at: now,
        search_id: ricerca.last_search_id(),
        outcome,
        new_results: u32::try_from(quante).unwrap_or(u32::MAX),
        page_full,
        newest_published_at,
        reason: sentence.clone(),
    })?;
    Ok(Some(RunReport {
        recurring_id: ricorrente.id,
        novelties,
        sentence,
    }))
}

/// La ricorrente scaduta più in ritardo, se ce n'è una, con il suo ramo.
fn most_overdue(
    database: &Database,
    now: Timestamp,
) -> ServiceResult<Option<(StoredRecurringSearch, Branch)>> {
    let mut scelta: Option<(i64, StoredRecurringSearch, Branch)> = None;
    for ricorrente in database.recurring_searches()? {
        if ricorrente.suspended {
            continue;
        }
        let Some(branch) = Branch::from_stored(&ricorrente.branch, ricorrente.chat_id) else {
            continue;
        };
        let scade = match database.recurring_runs(ricorrente.id, 1)?.first() {
            Some(ultima) => ultima
                .ran_at
                .as_millis()
                .saturating_add(i64::from(ricorrente.interval_minutes) * MINUTO),
            None => ricorrente.created_at.as_millis(),
        };
        if scade > now.as_millis() {
            continue;
        }
        if scelta.as_ref().is_none_or(|(prima, ..)| scade < *prima) {
            scelta = Some((scade, ricorrente, branch));
        }
    }
    Ok(scelta.map(|(_, ricorrente, branch)| (ricorrente, branch)))
}

/// Registra un'esecuzione saltata, senza richiesta.
fn skipped(
    database: &mut Database,
    recurring_id: i64,
    now: Timestamp,
    sentence: String,
) -> ServiceResult<Option<RunReport>> {
    database.insert_recurring_run(&NewRecurringRun {
        recurring_id,
        ran_at: now,
        search_id: None,
        outcome: "saltata",
        new_results: 0,
        page_full: false,
        newest_published_at: None,
        reason: sentence.clone(),
    })?;
    Ok(Some(RunReport {
        recurring_id,
        novelties: Vec::new(),
        sentence,
    }))
}

/// Ramo, parole e intervallo, in una riga.
fn title_of(ricorrente: &StoredRecurringSearch) -> String {
    let dove = match (ricorrente.branch.as_str(), ricorrente.chat_id) {
        ("C", Some(chat)) => format!("C, dentro la chat {chat}"),
        ("D", _) => String::from("D, nei post pubblici"),
        _ => String::from("B, nelle chat dell'account"),
    };
    let ore = ricorrente.interval_minutes / 60;
    let ogni = if ore == 1 {
        String::from("ogni ora")
    } else {
        format!("ogni {ore} ore")
    };
    format!(
        "\u{ab}{}\u{bb} \u{b7} {dove} \u{b7} {ogni}",
        ricorrente.query
    )
}

/// L'ultima esecuzione e la copertura, in frasi (ADR-0162, decisione 6).
fn coverage_of(
    database: &Database,
    ricorrente: &StoredRecurringSearch,
    now: Timestamp,
) -> ServiceResult<String> {
    let esecuzioni = database.recurring_runs(ricorrente.id, RUNS_FOR_COVERAGE)?;
    let intervallo = i64::from(ricorrente.interval_minutes) * MINUTO;
    let Some(ultima) = esecuzioni.first() else {
        return Ok(String::from(
            "Non ancora eseguita: parte alla prima occasione, con il programma aperto e \
             l'account collegato.",
        ));
    };
    let mut frasi = vec![format!(
        "Ultima esecuzione {}: {}",
        ultima.ran_at.to_readable_local(),
        ultima.reason
    )];
    // Il tempo senza ricerca, adesso e fra le esecuzioni lette.
    let soglia = intervallo.saturating_mul(2);
    if now.as_millis().saturating_sub(ultima.ran_at.as_millis()) > soglia {
        frasi.push(format!(
            "Dalle {} non si \u{e8} cercato: il programma era chiuso, bloccato o senza account.",
            ultima.ran_at.to_readable_local()
        ));
    }
    let vuoti = esecuzioni
        .windows(2)
        .filter(|coppia| {
            coppia[0]
                .ran_at
                .as_millis()
                .saturating_sub(coppia[1].ran_at.as_millis())
                > soglia
        })
        .count();
    if vuoti > 0 {
        frasi.push(format!(
            "Fra le ultime {} esecuzioni ci sono {vuoti} intervalli senza ricerca.",
            esecuzioni.len()
        ));
    }
    if ricorrente.suspended {
        frasi.push(String::from(
            "Sospesa: non si ripete finch\u{e9} non si riprende.",
        ));
    }
    Ok(frasi.join(" "))
}

/// La riga d'audit di un gesto su una ricorrente.
fn audit_of(
    operator: &Actor,
    azione: &str,
    dettaglio: &str,
    now: Timestamp,
) -> ServiceResult<NewAuditEntry> {
    Ok(NewAuditEntry {
        actor: operator.clone(),
        action: AuditAction::try_new(azione)?,
        entity: AuditEntity::try_new("ricerca_ricorrente")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(dettaglio)?),
        recorded_at: now,
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::text::Actor;
    use lisi_storage::Database;
    use lisi_telegram::search::{PublicPostLimits, SearchPage};
    use lisi_telegram::{
        ChatId, IncomingMessage, MessageId, MockTelegramConnector, TelegramConnector,
    };

    use super::{
        MAX_LIVE, MAX_PAGES_PER_HOUR, RunReport, list, read_hours, run_due, save, set_suspended,
        withdraw,
    };
    use crate::cyber_search::Branch;

    const T0: i64 = 1_760_000_000_000;
    const ORA: i64 = 3_600_000;
    const THIS_MODULE: &str = include_str!("cyber_recurring.rs");

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn archivio() -> Database {
        let Ok(archivio) = crate::sources::open_in_memory_database() else {
            panic!("archivio in memoria");
        };
        archivio
    }

    fn adesso(dopo: i64) -> Timestamp {
        Timestamp::from_millis(T0 + dopo)
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

    /// Una pagina con i messaggi `(numero, minuti dopo T0)`.
    fn pagina(messaggi: &[(i64, i64)], prossima: &str) -> SearchPage {
        SearchPage {
            hits: messaggi
                .iter()
                .map(|(id, minuti)| {
                    let (Ok(chat_id), Ok(message_id)) =
                        (ChatId::try_new(-1001), MessageId::try_new(*id))
                    else {
                        panic!("identificativi validi");
                    };
                    IncomingMessage {
                        chat_id,
                        message_id,
                        author: Some(String::from("Persona")),
                        author_identifier: Some(String::from("42")),
                        author_username: None,
                        text: String::from("ransomware"),
                        published_at_millis: T0 + minuti * 60_000,
                        url: None,
                        attachment: None,
                    }
                })
                .collect(),
            total_count: None,
            next_offset: Some(String::from(prossima)),
            next_from_message_id: None,
            limits: None,
            limits_exceeded: false,
        }
    }

    fn salvata(db: &mut Database, branch: Branch, ore: u32, quando: i64) -> i64 {
        match save(
            db,
            &operatore(),
            branch,
            "ransomware",
            ore * 60,
            adesso(quando),
        ) {
            Ok(Ok(id)) => id,
            altro => panic!("la ricorrente doveva salvarsi: {altro:?}"),
        }
    }

    fn esegui(
        connettore: &mut MockTelegramConnector,
        db: &mut Database,
        quando: i64,
    ) -> Option<RunReport> {
        match run_due(
            Some(connettore as &mut dyn TelegramConnector),
            db,
            &operatore(),
            adesso(quando),
        ) {
            Ok(esito) => esito,
            Err(errore) => panic!("l'archivio deve funzionare: {errore:?}"),
        }
    }

    /// **Una ricorrente si salva dentro i suoi limiti, e si dice** (criterio 1).
    #[test]
    fn una_ricorrente_si_salva_dentro_i_suoi_limiti() {
        for sbagliate in ["0", "25", "x", ""] {
            assert!(read_hours(sbagliate).is_err(), "«{sbagliate}»");
        }
        assert_eq!(read_hours(" 6 "), Ok(360));

        let mut db = archivio();
        assert!(matches!(
            save(
                &mut db,
                &operatore(),
                Branch::AccountChats,
                "x",
                60,
                adesso(0)
            ),
            Ok(Err(_))
        ));
        assert!(matches!(
            save(
                &mut db,
                &operatore(),
                Branch::AccountChats,
                "ransomware",
                59,
                adesso(0)
            ),
            Ok(Err(_))
        ));
        for _ in 0..MAX_LIVE {
            let _ = salvata(&mut db, Branch::PublicPosts, 6, 0);
        }
        let Ok(Err(frase)) = save(
            &mut db,
            &operatore(),
            Branch::AccountChats,
            "ransomware",
            60,
            adesso(0),
        ) else {
            panic!("oltre le dieci non si salva");
        };
        assert!(frase.contains("ritirarne una"), "{frase}");
        let Ok(viste) = list(&db, adesso(0)) else {
            panic!("l'elenco deve leggersi");
        };
        assert_eq!(viste.len(), MAX_LIVE);
        assert!(
            viste[0].title.contains("\u{ab}ransomware\u{bb}"),
            "{}",
            viste[0].title
        );
        assert!(viste[0].title.contains("D, nei post pubblici"));
        assert!(viste[0].title.contains("ogni 6 ore"));
        assert!(viste[0].coverage.contains("Non ancora eseguita"));
    }

    /// **La ricorrente scaduta si esegue e mostra soltanto le novità**
    /// (criteri 2 e 4; prova negativa: soglia delle novità tolta → rossa).
    #[test]
    fn la_ricorrente_scaduta_mostra_soltanto_le_novita() {
        let mut db = archivio();
        let mut connettore = pronto();
        let id = salvata(&mut db, Branch::AccountChats, 1, 0);
        connettore.queue_search_reply(Ok(pagina(&[(3, 3), (2, 2), (1, 1)], "")));
        let Some(prima) = esegui(&mut connettore, &mut db, 0) else {
            panic!("appena salvata, la ricorrente è scaduta");
        };
        assert_eq!(prima.recurring_id, id);
        assert_eq!(prima.novelties.len(), 3, "la prima esecuzione mostra tutto");

        assert!(
            esegui(&mut connettore, &mut db, 30 * 60_000).is_none(),
            "prima dell'intervallo non si esegue"
        );
        assert_eq!(connettore.searched().len(), 1);

        connettore.queue_search_reply(Ok(pagina(&[(4, 90), (4, 90), (3, 3), (2, 2)], "")));
        let Some(seconda) = esegui(&mut connettore, &mut db, ORA) else {
            panic!("dopo l'intervallo si esegue");
        };
        assert_eq!(
            seconda.novelties.len(),
            1,
            "un messaggio nuovo, una volta sola"
        );
        assert_eq!(seconda.novelties[0].message_id, 4);
        assert!(
            seconda.sentence.contains("Un messaggio nuovo"),
            "{}",
            seconda.sentence
        );

        connettore.queue_search_reply(Ok(pagina(&[(4, 90), (3, 3)], "")));
        let Some(terza) = esegui(&mut connettore, &mut db, 2 * ORA) else {
            panic!("dopo l'intervallo si esegue");
        };
        assert!(terza.novelties.is_empty());
        assert!(terza.sentence.contains("Nessun messaggio nuovo"));
        let Ok(registro) = db.recent_cyber_searches(10) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(registro.len(), 3, "ogni pagina è fra le ricerche");
    }

    /// **Sospesa o ritirata, una ricorrente non si esegue** (criterio 1).
    #[test]
    fn sospesa_o_ritirata_non_si_esegue() {
        let mut db = archivio();
        let mut connettore = pronto();
        let id = salvata(&mut db, Branch::AccountChats, 1, 0);
        assert_eq!(
            set_suspended(&mut db, &operatore(), id, true, adesso(0)).ok(),
            Some(Ok(()))
        );
        assert!(esegui(&mut connettore, &mut db, 0).is_none());
        assert_eq!(
            set_suspended(&mut db, &operatore(), id, false, adesso(1)).ok(),
            Some(Ok(()))
        );
        assert!(esegui(&mut connettore, &mut db, 1).is_some());

        assert_eq!(
            withdraw(&mut db, &operatore(), id, adesso(2)).ok(),
            Some(Ok(()))
        );
        assert!(esegui(&mut connettore, &mut db, 2 * ORA).is_none());
        assert!(matches!(
            withdraw(&mut db, &operatore(), id, adesso(3)),
            Ok(Err(_))
        ));
        assert!(matches!(
            set_suspended(&mut db, &operatore(), id, true, adesso(3)),
            Ok(Err(_))
        ));
        let Ok(viste) = list(&db, adesso(3)) else {
            panic!("l'elenco deve leggersi");
        };
        assert!(viste.is_empty(), "una ritirata non si mostra");
    }

    /// **Oltre le dieci pagine all'ora l'esecuzione si salta, e si dice**
    /// (criterio 3; prova negativa: budget tolto → rossa).
    #[test]
    fn oltre_il_budget_orario_si_salta_e_si_dice() {
        let mut db = archivio();
        let mut connettore = pronto();
        let mut ultima = 0;
        for _ in 0..MAX_LIVE {
            ultima = salvata(&mut db, Branch::AccountChats, 1, 0);
        }
        for secondi in 0..i64::from(MAX_PAGES_PER_HOUR) {
            assert!(esegui(&mut connettore, &mut db, secondi * 1_000).is_some());
        }
        assert_eq!(connettore.searched().len(), 10);
        assert_eq!(
            withdraw(&mut db, &operatore(), ultima, adesso(20_000)).ok(),
            Some(Ok(()))
        );
        let _ = salvata(&mut db, Branch::AccountChats, 1, 20_000);
        let Some(saltata) = esegui(&mut connettore, &mut db, 21_000) else {
            panic!("la nuova ricorrente è scaduta");
        };
        assert!(saltata.sentence.contains("saltata"), "{}", saltata.sentence);
        assert_eq!(
            connettore.searched().len(),
            10,
            "nulla chiesto oltre il budget"
        );
    }

    /// **Senza accesso completato non si chiede e non si registra nulla**
    /// (criterio 2; prova negativa: controllo dell'accesso tolto → rossa).
    #[test]
    fn senza_accesso_non_si_chiede_nulla() {
        let mut db = archivio();
        let id = salvata(&mut db, Branch::AccountChats, 1, 0);
        let Ok(None) = run_due(None, &mut db, &operatore(), adesso(0)) else {
            panic!("senza connettore nulla");
        };
        let mut non_collegato = MockTelegramConnector::new();
        assert!(esegui(&mut non_collegato, &mut db, 0).is_none());
        assert!(non_collegato.searched().is_empty());
        let Ok(esecuzioni) = db.recurring_runs(id, 10) else {
            panic!("il registro deve leggersi");
        };
        assert!(esecuzioni.is_empty(), "nessuna esecuzione registrata");
    }

    /// **La D ricorrente lascia metà della quota gratuita a chi cerca a mano**
    /// (criterio 3; prova negativa: riserva tolta → rossa).
    #[test]
    fn la_d_ricorrente_lascia_meta_della_quota() {
        let quota = |restano: i32| PublicPostLimits {
            daily_free: 10,
            remaining_free: restano,
            next_free_in_seconds: 0,
            star_count: 10,
            current_query_free: true,
        };
        let mut db = archivio();
        let mut connettore = pronto();
        let _ = salvata(&mut db, Branch::PublicPosts, 1, 0);
        connettore.queue_limits_reply(Ok(quota(5)));
        let Some(ferma) = esegui(&mut connettore, &mut db, 0) else {
            panic!("la ricorrente è scaduta");
        };
        assert!(
            connettore.searched().is_empty(),
            "con 5 su 10 la ricorrente non cerca"
        );
        assert!(ferma.sentence.contains("met\u{e0}"), "{}", ferma.sentence);

        connettore.queue_limits_reply(Ok(quota(8)));
        connettore.queue_search_reply(Ok(pagina(&[(1, 1)], "")));
        let Some(fatta) = esegui(&mut connettore, &mut db, ORA) else {
            panic!("dopo l'intervallo si esegue");
        };
        assert_eq!(connettore.searched().len(), 1, "con 8 su 10 cerca");
        assert_eq!(fatta.novelties.len(), 1);
    }

    /// **La copertura dice la pagina piena e il tempo senza ricerca**
    /// (criterio 5).
    #[test]
    fn la_copertura_dice_la_pagina_piena_e_il_tempo_senza_ricerca() {
        let mut db = archivio();
        let mut connettore = pronto();
        let _ = salvata(&mut db, Branch::AccountChats, 1, 0);
        connettore.queue_search_reply(Ok(pagina(&[(2, 2), (1, 1)], "ancora")));
        let Some(piena) = esegui(&mut connettore, &mut db, 0) else {
            panic!("la ricorrente è scaduta");
        };
        assert!(
            piena.sentence.contains("La pagina era piena"),
            "{}",
            piena.sentence
        );
        let Ok(viste) = list(&db, adesso(3 * ORA)) else {
            panic!("l'elenco deve leggersi");
        };
        assert!(
            viste[0].coverage.contains("non si \u{e8} cercato"),
            "{}",
            viste[0].coverage
        );
        assert!(viste[0].coverage.contains("La pagina era piena"));
    }

    /// **La ricorrente non acquisisce, non spende, non registra da sé e non
    /// avvia il monitoraggio ordinario** (criterio 6).
    #[test]
    fn la_ricorrente_non_acquisisce_e_non_spende() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        for vietato in [
            "insert_content",
            "analyse_and_record",
            "insert_alert",
            "AcquisitionService",
            "star_count",
            "insert_cyber_search(",
            "MonitoringService",
            "start_session",
        ] {
            assert!(
                !produzione.contains(vietato),
                "la ricorrente chiama «{vietato}»"
            );
        }
        assert_eq!(
            produzione.matches("cyber_search::start_recurring(").count(),
            1,
            "una sola strada verso Telegram, quella delle ricerche"
        );
    }
}

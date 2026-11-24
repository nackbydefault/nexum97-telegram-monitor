//! La risoluzione di un indicatore dal PC, su comando (IOC-RESOLVE-01,
//! ADR-0202).
//!
//! # Chi decide
//!
//! Si risolve soltanto se l'amministratore lo ha abilitato: è l'undicesima
//! azione riservata, e di fabbrica è spenta ([`choose`]).
//!
//! # Che cosa fa
//!
//! Per **un** indicatore e per un gesto, chiede al risolutore di Windows gli
//! indirizzi di un dominio (o dell'host di un indirizzo web), o i nomi di un
//! indirizzo. Registra chi, quando, che cosa si è chiesto e che cosa è
//! tornato, con la riga d'audit nella stessa transazione.
//!
//! # Il prezzo, detto prima
//!
//! Una richiesta DNS si vede: il server DNS la registra, e chi gestisce il
//! dominio può vederla arrivare. La schermata lo dice prima del pulsante.
//!
//! # Che cosa non fa
//!
//! - Non parte se la risoluzione non è abilitata, né in Esercitazione.
//! - Non si collega all'indirizzo trovato e non preleva nulla.
//! - Non ripete: una richiesta per gesto, e mai due troppo vicine sullo
//!   stesso indicatore.

use std::net::IpAddr;

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, Timestamp};
use lisi_platform::name_lookup::{self, LookupOutcome};
use lisi_storage::Database;
use lisi_storage::repository::indicator_resolution::NewIndicatorResolution;
pub use lisi_storage::repository::indicator_resolution::StoredIndicatorResolution;

use crate::error::{ServiceError, ServiceResult};

/// L'azione d'audit della scelta.
pub const CHOICE_AUDIT_ACTION: &str = "risoluzione_indicatori_scelta";
/// L'azione d'audit di una richiesta.
pub const REQUEST_AUDIT_ACTION: &str = "indicatore_risolto";
/// Secondi, almeno, fra due richieste sullo stesso indicatore.
pub const MIN_SECONDS_BETWEEN: i64 = 10;
/// Quante richieste la schermata mostra, per indicatore.
pub const SHOWN: u32 = 10;

/// Il risolutore. In produzione è quello di Windows ([`Resolver::of_this_pc`]);
/// le prove ne passano uno finto, e nessuna richiesta parte.
#[derive(Debug, Clone, Copy)]
pub struct Resolver {
    /// Gli indirizzi di un nome.
    pub addresses: fn(&str) -> LookupOutcome,
    /// I nomi di un indirizzo.
    pub names: fn(IpAddr) -> LookupOutcome,
}

impl Resolver {
    /// Il risolutore configurato sulla postazione.
    #[must_use]
    pub const fn of_this_pc() -> Self {
        Self {
            addresses: name_lookup::addresses_of,
            names: name_lookup::names_of,
        }
    }
}

/// Che cosa si chiede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Gli indirizzi di questo nome.
    Name(String),
    /// I nomi di questo indirizzo.
    Address(IpAddr),
}

impl Query {
    /// Il nome chiesto al risolutore, per il registro.
    #[must_use]
    pub fn queried_name(&self) -> String {
        match self {
            Self::Name(nome) => nome.clone(),
            Self::Address(indirizzo) => name_lookup::reverse_name(*indirizzo),
        }
    }
}

/// Com'è andata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionAttempt {
    /// La richiesta è partita ed è registrata.
    Recorded {
        /// La riga della richiesta.
        id: i64,
        /// La frase che dice l'esito.
        sentence: String,
    },
    /// Il prodotto ha rifiutato di chiedere: il perché. Nessuna richiesta.
    Refused(String),
}

/// Se un genere d'indicatore si può risolvere.
#[must_use]
pub fn resolvable(kind: &str) -> bool {
    matches!(kind, "ipv4" | "ipv6" | "dominio" | "url")
}

/// Che cosa si chiederebbe per un indicatore, se si può chiedere.
#[must_use]
pub fn query_for(kind: &str, value: &str) -> Option<Query> {
    let valore = value.trim();
    match kind {
        "ipv4" | "ipv6" => valore.parse::<IpAddr>().ok().map(Query::Address),
        "dominio" => nome(valore),
        "url" => {
            let host = host_of_url(valore)?;
            host.parse::<IpAddr>()
                .ok()
                .map(Query::Address)
                .or_else(|| nome(&host))
        }
        _ => None,
    }
}

fn nome(valore: &str) -> Option<Query> {
    let nome = valore.trim_end_matches('.').to_ascii_lowercase();
    name_lookup::is_queryable_name(&nome).then_some(Query::Name(nome))
}

/// L'host di un indirizzo web: dopo lo schema, senza credenziali né porta.
fn host_of_url(url: &str) -> Option<String> {
    let (_, resto) = url.split_once("://")?;
    let autorita = resto.split(['/', '?', '#']).next().unwrap_or(resto);
    let autorita = autorita.rsplit_once('@').map_or(autorita, |(_, host)| host);
    let host = if let Some(dentro) = autorita.strip_prefix('[') {
        dentro.split(']').next().unwrap_or_default()
    } else {
        autorita.split(':').next().unwrap_or_default()
    };
    (!host.is_empty()).then(|| host.to_owned())
}

/// Se la risoluzione è abilitata.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn enabled(database: &Database) -> ServiceResult<bool> {
    Ok(database.indicator_resolution_enabled()?)
}

/// Abilita o spegne la risoluzione. Soltanto l'amministratore.
///
/// # Errori
///
/// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore; un
/// errore se la scrittura non riesce.
pub fn choose(
    database: &mut Database,
    enable: bool,
    mode: OperatingMode,
    actor: &Actor,
    now: Timestamp,
) -> ServiceResult<String> {
    if !mode.allows(RestrictedAction::ChooseIndicatorResolution) {
        return Err(ServiceError::ActionReservedToAdministrator {
            action: RestrictedAction::ChooseIndicatorResolution,
        });
    }
    let audit = NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(CHOICE_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("postazione")?,
        entity_id: None,
        actor_mode: Some(mode),
        detail: Some(AuditDetail::try_new(if enable {
            "abilitata"
        } else {
            "spenta"
        })?),
        recorded_at: now,
    };
    database.save_indicator_resolution_enabled(enable, actor, &audit)?;
    Ok(String::from(if enable {
        "Gli indicatori si possono risolvere dal PC. Ogni richiesta si vede fuori, e resta nel \
         registro."
    } else {
        "Gli indicatori non si risolvono più dal PC."
    }))
}

/// La richiesta: i rifiuti prima di chiedere, poi **una** richiesta, poi il
/// registro.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge o non si scrive.
pub fn resolve(
    database: &mut Database,
    resolver: Resolver,
    kind: &str,
    value: &str,
    actor: &Actor,
    exercise: bool,
    now: Timestamp,
) -> ServiceResult<ResolutionAttempt> {
    if !database.indicator_resolution_enabled()? {
        return Ok(ResolutionAttempt::Refused(String::from(
            "La risoluzione degli indicatori non è abilitata: la abilita l'amministratore, nelle \
             Impostazioni.",
        )));
    }
    if exercise {
        return Ok(ResolutionAttempt::Refused(String::from(
            "In Esercitazione nessuna richiesta parte dal PC.",
        )));
    }
    let Some(richiesta) = query_for(kind, value) else {
        return Ok(ResolutionAttempt::Refused(String::from(
            "Questo indicatore non si risolve: si chiedono soltanto domini e indirizzi scritti in modo corretto, anche dentro un indirizzo web.",
        )));
    };
    if let Some(ultima) = database
        .indicator_resolutions(kind, value, 1)?
        .first()
        .map(|ultima| ultima.requested_at)
        && now.millis_since(ultima) < MIN_SECONDS_BETWEEN * 1_000
    {
        return Ok(ResolutionAttempt::Refused(format!(
            "Questo indicatore è stato chiesto da meno di {MIN_SECONDS_BETWEEN} secondi: la \
             risposta è qui sotto."
        )));
    }

    // UNA richiesta, e una sola. Nessuna ripetizione, qualunque sia l'esito.
    let esito = match &richiesta {
        Query::Name(nome) => (resolver.addresses)(nome),
        Query::Address(indirizzo) => (resolver.names)(*indirizzo),
    };
    let (outcome, error_code, risposte) = match esito {
        LookupOutcome::Found(valori) => ("trovato", None, valori),
        LookupOutcome::NoRecords => ("nessun_record", None, Vec::new()),
        LookupOutcome::NotFound => ("inesistente", None, Vec::new()),
        LookupOutcome::Refused => {
            return Ok(ResolutionAttempt::Refused(String::from(
                "Il nome non si può chiedere: nessuna richiesta è partita.",
            )));
        }
        LookupOutcome::Failed { code } => ("non_riuscito", Some(i64::from(code)), Vec::new()),
    };
    let answers = risposte.join("\n");
    let sentence = outcome_sentence(outcome, &answers, error_code);
    let registro = NewIndicatorResolution {
        indicator_kind: match kind {
            "ipv4" => "ipv4",
            "ipv6" => "ipv6",
            "dominio" => "dominio",
            _ => "url",
        },
        indicator_value: value.to_owned(),
        queried_name: richiesta.queried_name(),
        requested_by: actor.as_str().to_owned(),
        requested_at: now,
        outcome,
        error_code,
        answers,
    };
    let audit = NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(REQUEST_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("indicatore")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "{} {}: chiesto «{}», {}, {} risposte",
            registro.indicator_kind,
            value,
            registro.queried_name,
            outcome,
            risposte.len()
        ))?),
        recorded_at: now,
    };
    let id = database.insert_indicator_resolution(&registro, &audit)?;
    Ok(ResolutionAttempt::Recorded { id, sentence })
}

/// L'esito in una frase.
#[must_use]
pub fn outcome_sentence(outcome: &str, answers: &str, error_code: Option<i64>) -> String {
    match outcome {
        "trovato" => format!(
            "Il servizio dei nomi di rete ha risposto: {}.",
            answers.lines().collect::<Vec<_>>().join(", ")
        ),
        "nessun_record" => String::from("Il nome esiste, ma non ha risposte di questo genere."),
        "inesistente" => String::from("Il servizio dei nomi di rete dice che il nome non esiste."),
        _ => error_code.map_or_else(
            || String::from("Il servizio dei nomi di rete non ha risposto."),
            |codice| {
                format!(
                    "Il servizio dei nomi di rete non ha risposto (codice di Windows {codice})."
                )
            },
        ),
    }
}

/// Le richieste per un indicatore, dalla più nuova.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn recent(
    database: &Database,
    kind: &str,
    value: &str,
) -> ServiceResult<Vec<StoredIndicatorResolution>> {
    Ok(database.indicator_resolutions(kind, value, SHOWN)?)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, Timestamp};
    use lisi_platform::name_lookup::LookupOutcome;
    use lisi_storage::Database;

    use super::{Query, ResolutionAttempt, Resolver, choose, query_for, recent, resolve};
    use crate::error::ServiceError;

    fn adesso(secondi: i64) -> Timestamp {
        Timestamp::from_millis(1_800_000_000_000 + secondi * 1_000)
    }

    fn chi() -> Actor {
        let Ok(chi) = Actor::try_new("operatore.prova") else {
            panic!("valori di prova validi");
        };
        chi
    }

    fn archivio(abilitata: bool) -> Database {
        let Ok(mut database) = Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        if abilitata {
            let Ok(_) = choose(
                &mut database,
                true,
                OperatingMode::Administrator,
                &chi(),
                adesso(0),
            ) else {
                panic!("l'amministratore abilita");
            };
        }
        database
    }

    fn trova(_: &str) -> LookupOutcome {
        LookupOutcome::Found(vec![String::from("192.0.2.10")])
    }

    fn nomi(_: IpAddr) -> LookupOutcome {
        LookupOutcome::Found(vec![String::from("host.esempio.invalid")])
    }

    fn non_deve_partire(_: &str) -> LookupOutcome {
        panic!("nessuna richiesta doveva partire")
    }

    fn non_deve_partire_ip(_: IpAddr) -> LookupOutcome {
        panic!("nessuna richiesta doveva partire")
    }

    const FINTO: Resolver = Resolver {
        addresses: trova,
        names: nomi,
    };
    const MUTO: Resolver = Resolver {
        addresses: non_deve_partire,
        names: non_deve_partire_ip,
    };

    #[test]
    fn che_cosa_si_chiede_per_ogni_genere() {
        assert_eq!(
            query_for("dominio", "Esempio.Invalid."),
            Some(Query::Name(String::from("esempio.invalid")))
        );
        assert_eq!(
            query_for(
                "url",
                "https://utente@host.esempio.invalid:8443/percorso?x=1"
            ),
            Some(Query::Name(String::from("host.esempio.invalid")))
        );
        let Ok(indirizzo) = "2001:db8::1".parse::<IpAddr>() else {
            panic!("indirizzo di prova");
        };
        assert_eq!(
            query_for("url", "http://[2001:db8::1]:80/"),
            Some(Query::Address(indirizzo))
        );
        assert_eq!(query_for("sha256", "abc"), None);
        assert_eq!(query_for("dominio", "non un nome"), None);
    }

    #[test]
    fn spenta_di_fabbrica_e_riservata_all_amministratore() {
        let mut database = archivio(false);
        assert!(matches!(
            resolve(
                &mut database,
                MUTO,
                "dominio",
                "esempio.invalid",
                &chi(),
                false,
                adesso(1)
            ),
            Ok(ResolutionAttempt::Refused(_))
        ));
        assert!(matches!(
            choose(
                &mut database,
                true,
                OperatingMode::Operator,
                &chi(),
                adesso(1)
            ),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
    }

    #[test]
    fn in_esercitazione_non_parte_nulla() {
        let mut database = archivio(true);
        let Ok(esito) = resolve(
            &mut database,
            MUTO,
            "dominio",
            "esempio.invalid",
            &chi(),
            true,
            adesso(1),
        ) else {
            panic!("il rifiuto non è un errore");
        };
        assert!(matches!(esito, ResolutionAttempt::Refused(_)));
        assert_eq!(
            recent(&database, "dominio", "esempio.invalid")
                .map(|r| r.len())
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn una_richiesta_si_registra_e_non_si_ripete_subito() {
        let mut database = archivio(true);
        let Ok(ResolutionAttempt::Recorded { sentence, .. }) = resolve(
            &mut database,
            FINTO,
            "dominio",
            "esempio.invalid",
            &chi(),
            false,
            adesso(1),
        ) else {
            panic!("la richiesta parte e si registra");
        };
        assert!(sentence.contains("192.0.2.10"), "{sentence}");
        assert!(matches!(
            resolve(
                &mut database,
                MUTO,
                "dominio",
                "esempio.invalid",
                &chi(),
                false,
                adesso(3)
            ),
            Ok(ResolutionAttempt::Refused(_))
        ));
        let Ok(ResolutionAttempt::Recorded { .. }) = resolve(
            &mut database,
            FINTO,
            "ipv4",
            "192.0.2.10",
            &chi(),
            false,
            adesso(4),
        ) else {
            panic!("un altro indicatore si chiede");
        };
        let Ok(registro) = recent(&database, "ipv4", "192.0.2.10") else {
            panic!("la lettura riesce");
        };
        assert_eq!(registro[0].queried_name, "10.2.0.192.in-addr.arpa");
        assert_eq!(registro[0].answers, "host.esempio.invalid");
    }
}

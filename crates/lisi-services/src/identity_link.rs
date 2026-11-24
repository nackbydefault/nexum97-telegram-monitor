//! Associazione manuale fra un'identità osservata e un soggetto (PERS-06).
//!
//! # Il divieto non è stato tolto
//!
//! PERS-02, PERS-03, PERS-04 e PERS-05 non nominano `PersonId`, e le loro
//! guardie restano dove sono. Questo servizio è **l'unica strada** per cui un
//! legame può esistere, e la percorre solo chi lo ha deciso.
//!
//! Se un giorno il servizio delle identità osservate cominciasse a collegare, la
//! sua guardia diventerebbe rossa — e sarebbe giusto: l'esistenza di questa
//! strada non è un permesso per le altre.
//!
//! # Il motivo è un terzo, e non è nessuno degli altri due
//!
//! - **ADR-0024** autorizza a *guardare* un elenco di persone;
//! - la **ragione di apertura** (PERS-01) dice perché si è aperto quel fascicolo;
//! - la **ragione di valutazione** (PERS-05) dice perché quel livello;
//! - questa dice **perché quell'identità è quella persona**.
//!
//! È la più concreta delle quattro, ed è quella che qualcuno dovrà saper
//! ripetere: «l'ho collegata perché…». Riusarne un'altra farebbe passare la
//! decisione senza che nessuno l'abbia scritta.
//!
//! # Mai per somiglianza di nome
//!
//! Non c'è alcuna funzione che cerchi identità da collegare, che ne proponga o
//! che le ordini per verosimiglianza. **L'identificativo si scrive.**
//!
//! Il prodotto ha un algoritmo di somiglianza (ADR-0055) per riconoscere due
//! ripubblicazioni dello stesso testo: questo modulo non lo nomina, e una
//! guardia lo verifica.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::identity_link::{
    IdentityLinkEntry, LinkAct, LinkedIdentity, NewIdentityLink, current_links,
};
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{IdentityLinkId, IdentityResolutionId, PersonId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// L'azione di audit con cui si registra un atto su un legame.
const AZIONE: &str = "identita_associata";

/// I generi di profilo che sono l'identità di una persona (PR-10, ADR-0126),
/// come la ricerca puntuale li registra. Lo stesso elenco sta nel trigger della
/// migrazione 0055.
const LINKABLE_KINDS: [&str; 2] = ["persona", "account"];

/// Servizio dell'associazione manuale.
#[derive(Debug)]
pub struct IdentityLinkService {
    database: Database,
}

impl IdentityLinkService {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// L'archivio, in sola lettura.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce l'archivio al chiamante.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Registra un atto su un legame, con la sua voce di audit.
    ///
    /// # Perché l'identificativo arriva come stringa
    ///
    /// Perché **è** una stringa: è l'identificativo che la piattaforma assegna, e
    /// non esiste un tipo del dominio che lo convalidi oltre al non essere vuoto
    /// — inventarne uno significherebbe dichiarare di conoscere la forma degli
    /// identificativi di Telegram, che è una cosa che può cambiare.
    ///
    /// Il vuoto lo rifiutano questa funzione e un vincolo dell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::Domain`] se l'identificativo è vuoto.
    /// Restituisce un errore se il soggetto non esiste, se è **chiuso** — un
    /// trigger lo rifiuta — o se la scrittura non riesce.
    pub fn record(
        &self,
        person: PersonId,
        identifier: &str,
        act: LinkAct,
        reason: &OperationalReason,
        by: &Actor,
        at: Timestamp,
    ) -> ServiceResult<IdentityLinkId> {
        self.write(NewIdentityLink {
            person,
            identifier: identifier.to_owned(),
            act,
            reason: reason.clone(),
            by: by.clone(),
            at,
            resolution: None,
        })
    }

    /// Collega a un soggetto il profilo che una ricerca puntuale ha trovato
    /// (PR-10, ADR-0126).
    ///
    /// # Lo decide una persona
    ///
    /// È la stessa strada di [`Self::record`], con una base in più: nessun'altra
    /// funzione crea un legame da una ricerca, e la ricerca stessa non ne crea.
    /// L'identificativo **non si sceglie**: è quello che Telegram ha restituito.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::LinkBasisRefused`] se la ricerca non esiste,
    /// non è un «trovato», o non è di una persona o di un account. Gli altri
    /// errori sono quelli di [`Self::record`].
    pub fn link_from_resolution(
        &self,
        person: PersonId,
        ricerca: IdentityResolutionId,
        reason: &OperationalReason,
        by: &Actor,
        at: Timestamp,
    ) -> ServiceResult<IdentityLinkId> {
        let Some(registrata) = self.database.identity_resolution(ricerca.get())? else {
            return Err(ServiceError::LinkBasisRefused {
                reason: "La ricerca non c'è nel registro: non c'è nulla da collegare.",
            });
        };
        let Some(profilo) = registrata
            .resolution
            .found
            .as_ref()
            .filter(|_| registrata.resolution.outcome == "trovato")
        else {
            return Err(ServiceError::LinkBasisRefused {
                reason: "Si collega soltanto un esito «Trovato»: gli altri esiti non hanno nulla \
                         da collegare.",
            });
        };
        if !LINKABLE_KINDS.contains(&profilo.kind.as_str()) {
            return Err(ServiceError::LinkBasisRefused {
                reason: "Un canale, un gruppo, un bot o un account cancellato non sono \
                         l'identità di una persona.",
            });
        }
        self.write(NewIdentityLink {
            person,
            identifier: profilo.telegram_id.to_string(),
            act: LinkAct::Link,
            reason: reason.clone(),
            by: by.clone(),
            at,
            resolution: Some(ricerca),
        })
    }

    /// Scrive un atto e la sua voce di audit: la strada comune ai due legami.
    fn write(&self, legame: NewIdentityLink) -> ServiceResult<IdentityLinkId> {
        // UN IDENTIFICATIVO VUOTO NON E' UN'IDENTITA'.
        //
        // Collegarne uno creerebbe un legame che non punta a nessuno, e che chi
        // rilegge non potrebbe ne' verificare ne' sciogliere con cognizione.
        let pulito = legame.identifier.trim().to_owned();
        if pulito.is_empty() {
            return Err(ServiceError::Domain(lisi_core::DomainError::Empty {
                field: "identificativo dell'identit\u{e0} osservata",
            }));
        }
        // UN LEGAME NUOVO, SCRITTO A MANO, DEVE AVERE LA FORMA DI UN'IDENTITA'
        // TELEGRAM (OPERATOR-E2E-REMEDIATION-01, F-18). «abc» era stato
        // accettato e scritto nel fascicolo. Sciogliere resta sempre possibile,
        // anche un legame vecchio con un identificativo che oggi si
        // rifiuterebbe: chi lo scioglie lo corregge.
        if legame.act == LinkAct::Link
            && legame.resolution.is_none()
            && !lisi_core::model::identity_link::is_telegram_identity(&pulito)
        {
            return Err(ServiceError::LinkBasisRefused {
                reason: "Un'identità Telegram è un nome utente oppure un identificativo \
                         numerico. Il nome utente ha da 5 a 32 caratteri fra lettere, cifre e \
                         trattino basso, con o senza la @ iniziale. Quello scritto non è né l'uno né l'altro, \
                         e il legame non è stato registrato.",
            });
        }

        // LA STESSA IDENTITA' DUE VOLTE (CAPABILITY-AUDIT-02, CA02-11; ADR-0166):
        // un secondo legame mentre il primo e' in vigore non aggiunge nulla.
        if legame.act == LinkAct::Link
            && self
                .current(legame.person)?
                .iter()
                .any(|attuale| same_identity(&attuale.identifier, &pulito))
        {
            return Err(ServiceError::LinkBasisRefused {
                reason: "Questa identità è già collegata a questo soggetto: un secondo legame \
                         non aggiunge nulla, e non è stato registrato.",
            });
        }

        let id = self.database.insert_identity_link(&NewIdentityLink {
            identifier: pulito.clone(),
            ..legame.clone()
        })?;

        // L'AUDIT PORTA L'ATTO E L'IDENTIFICATIVO, NON LA RAGIONE.
        //
        // La ragione sta sulla riga del legame, dove chi rilegge la trova
        // accanto alla decisione che spiega. E' la scelta di PERS-01 e PERS-05.
        // La base, quando c'è, si dice: è la differenza fra i due legami.
        let base = legame.resolution.map_or_else(String::new, |ricerca| {
            format!(" dalla ricerca puntuale {}", ricerca.get())
        });
        self.database.append_audit(&NewAuditEntry {
            actor: legame.by.clone(),
            action: AuditAction::try_new(AZIONE)?,
            entity: AuditEntity::try_new("person")?,
            entity_id: Some(legame.person.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{} {pulito}{base}",
                legame.act.as_str()
            ))?),
            recorded_at: legame.at,
        })?;

        Ok(id)
    }

    /// I legami **in essere** di un soggetto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn current(&self, person: PersonId) -> ServiceResult<Vec<LinkedIdentity>> {
        Ok(current_links(&self.history(person)?))
    }

    /// La storia degli atti sui legami, dal più antico.
    ///
    /// # Perché la storia è pubblica quanto i legami
    ///
    /// Perché un legame sciolto racconta qualcosa che l'assenza di un legame non
    /// racconta: qualcuno lo aveva fatto, e qualcuno lo ha disfatto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn history(&self, person: PersonId) -> ServiceResult<Vec<IdentityLinkEntry>> {
        Ok(self.database.identity_link_history(person)?)
    }
}

/// Se due identificativi indicano la stessa identità Telegram: i nomi utente
/// come li confronta Telegram, senza la chiocciola e senza maiuscole; gli
/// identificativi numerici esatti (ADR-0166).
fn same_identity(primo: &str, secondo: &str) -> bool {
    let primo = primo.trim().trim_start_matches('@');
    let secondo = secondo.trim().trim_start_matches('@');
    let numerico =
        |testo: &str| !testo.is_empty() && testo.bytes().all(|b| b.is_ascii_digit() || b == b'-');
    if numerico(primo) || numerico(secondo) {
        return primo == secondo;
    }
    primo.eq_ignore_ascii_case(secondo)
}

#[cfg(test)]
mod tests {
    use lisi_core::model::identity_link::LinkAct;
    use lisi_core::model::person::NewPerson;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::{Actor, DisplayName};
    use lisi_core::{PersonId, Timestamp};
    use lisi_storage::Database;

    use super::IdentityLinkService;
    use crate::sources::open_in_memory_database;

    const ORA: i64 = 1_760_000_000_000;

    fn attore() -> Actor {
        let Ok(valore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore deve essere valido");
        };
        valore
    }

    fn ragione(testo: &str) -> OperationalReason {
        let Ok(valore) = OperationalReason::try_new(testo) else {
            panic!("la ragione di prova deve essere valida");
        };
        valore
    }

    fn servizio() -> (IdentityLinkService, PersonId) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let database: Database = database;
        let Ok(etichetta) = DisplayName::try_new("Soggetto di prova") else {
            panic!("l'etichetta deve essere valida");
        };
        let Ok(person) = database.insert_person(
            &NewPerson::open(
                etichetta,
                ragione("richiesta dell'autorita' procedente del 4 marzo"),
            ),
            &attore(),
            Timestamp::from_millis(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };
        (IdentityLinkService::new(database), person)
    }

    /// **Un atto lascia una voce di audit.**
    #[test]
    fn un_atto_lascia_una_voce_di_audit() {
        let (servizio, person) = servizio();
        let Ok(_) = servizio.record(
            person,
            "111",
            LinkAct::Link,
            &ragione("riscontro documentale con l'autorita' procedente"),
            &attore(),
            Timestamp::from_millis(ORA + 100),
        ) else {
            panic!("l'atto deve potersi registrare");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            voci.iter()
                .any(|voce| voce.action.as_str() == "identita_associata"),
            "l'azione deve comparire nell'audit"
        );
    }

    /// **Un testo che non può essere un'identità Telegram non si collega**, e
    /// sciogliere resta possibile (F-18).
    ///
    /// Vista rossa prima della correzione: «abc» veniva registrato.
    #[test]
    fn un_testo_che_non_e_un_identita_non_si_collega() {
        let (servizio, person) = servizio();
        let esito = servizio.record(
            person,
            "abc",
            LinkAct::Link,
            &ragione("riscontro documentale con l'autorita' procedente"),
            &attore(),
            Timestamp::from_millis(ORA + 100),
        );
        assert!(
            matches!(
                esito,
                Err(crate::error::ServiceError::LinkBasisRefused { .. })
            ),
            "{esito:?}"
        );
        assert!(
            servizio
                .record(
                    person,
                    "@mario_rossi",
                    LinkAct::Link,
                    &ragione("riscontro documentale con l'autorita' procedente"),
                    &attore(),
                    Timestamp::from_millis(ORA + 200),
                )
                .is_ok(),
            "un nome utente valido si collega"
        );
        assert!(
            servizio
                .record(
                    person,
                    "abc",
                    LinkAct::Unlink,
                    &ragione("legame vecchio scritto male, da correggere"),
                    &attore(),
                    Timestamp::from_millis(ORA + 300),
                )
                .is_ok(),
            "sciogliere non chiede la forma: corregge"
        );
    }

    /// **Un identificativo vuoto non è un'identità.**
    #[test]
    fn un_identificativo_vuoto_non_e_un_identita() {
        let (servizio, person) = servizio();
        for vuoto in ["", "   ", "\t"] {
            let esito = servizio.record(
                person,
                vuoto,
                LinkAct::Link,
                &ragione("riscontro documentale con l'autorita' procedente"),
                &attore(),
                Timestamp::from_millis(ORA + 100),
            );
            assert!(
                esito.is_err(),
                "«{vuoto}» non e' un identificativo: il legame non punterebbe a nessuno"
            );
        }
    }

    /// **Il servizio non cerca, non propone e non confronta nomi.**
    ///
    /// # Perché è la guardia che il congelamento chiede per nome
    ///
    /// Perché il freeze §9 elenca «una fusione automatica di identità per
    /// somiglianza di nome» fra i controlli negativi attesi.
    #[test]
    fn il_servizio_non_cerca_non_propone_e_non_confronta_nomi() {
        let codice = codice_senza_commenti().to_lowercase();
        for vietata in [
            "similarity",
            "somigli",
            "levenshtein",
            "distance",
            "fuzzy",
            "candidate",
            "candidat",
            "suggest",
            "suggeri",
            "propose",
            "propon",
            "session_contents",
            "participant",
            "observed_identit",
        ] {
            assert!(
                !codice.contains(vietata),
                "il servizio nomina «{vietata}»: un legame proposto dal programma e' una fusione \
                 automatica, comunque la si chiami"
            );
        }
    }

    /// **Il motivo è un terzo, e non è quello degli elenchi né dell'apertura.**
    #[test]
    fn il_motivo_e_un_terzo() {
        let codice = codice_senza_commenti();
        assert!(
            !codice.contains("elenco_persone_motivato"),
            "collegare non passa dalla ragione degli elenchi: sono autorizzazioni diverse"
        );
        assert!(
            !codice.contains("basis_recorded"),
            "e nemmeno dalla sua verifica"
        );
        assert!(
            codice.contains("reason: &OperationalReason"),
            "il motivo e' il tipo del dominio, e non una stringa che si passa vuota"
        );
    }

    /// **Non esiste un modo di cambiare o cancellare un atto.**
    #[test]
    fn non_esiste_un_modo_di_cambiare_o_cancellare_un_atto() {
        let codice = codice_senza_commenti();
        for scrittura in [
            "update_identity_link",
            "delete_identity_link",
            "fn update",
            "fn delete",
            "fn remove",
        ] {
            assert!(
                !codice.contains(scrittura),
                "il servizio nomina «{scrittura}»: sciogliere e' un atto, non una cancellazione"
            );
        }
    }

    /// **Sciogliere e ricollegare: la storia racconta, l'elenco no.**
    #[test]
    fn sciogliere_e_ricollegare_lasciano_la_storia() {
        let (servizio, person) = servizio();
        for (act, quando) in [
            (LinkAct::Link, ORA + 100),
            (LinkAct::Unlink, ORA + 200),
            (LinkAct::Link, ORA + 300),
        ] {
            let Ok(_) = servizio.record(
                person,
                "111",
                act,
                &ragione("riscontro documentale con l'autorita' procedente"),
                &attore(),
                Timestamp::from_millis(quando),
            ) else {
                panic!("l'atto deve potersi registrare");
            };
        }

        let Ok(legami) = servizio.current(person) else {
            panic!("i legami devono potersi leggere");
        };
        assert_eq!(legami.len(), 1, "vale l'atto piu' recente");

        let Ok(storia) = servizio.history(person) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia.len(), 3, "e tutti e tre restano scritti");
    }

    /// **Un soggetto chiuso non si collega.**
    #[test]
    fn un_soggetto_chiuso_non_si_collega() {
        let (servizio, person) = servizio();
        let Ok(()) = servizio.database().close_person(
            person,
            &attore(),
            &ragione("il procedimento si e' concluso senza rilievi"),
            Timestamp::from_millis(ORA + 50),
        ) else {
            panic!("il soggetto deve potersi chiudere");
        };

        let esito = servizio.record(
            person,
            "111",
            LinkAct::Link,
            &ragione("riscontro documentale con l'autorita' procedente"),
            &attore(),
            Timestamp::from_millis(ORA + 100),
        );
        assert!(esito.is_err(), "un soggetto chiuso non si collega");
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("identity_link.rs");
        let Some(taglio) = sorgente.find("#[cfg(test)]") else {
            panic!("il modulo deve avere una sezione di prove");
        };
        sorgente[..taglio]
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Registra una ricerca puntuale nell'archivio del servizio.
    fn con_ricerca(
        servizio: IdentityLinkService,
        esito: &str,
        profilo: Option<(&str, i64)>,
    ) -> (IdentityLinkService, lisi_core::IdentityResolutionId) {
        use lisi_core::model::NewAuditEntry;
        use lisi_core::text::{AuditAction, AuditEntity};
        use lisi_storage::repository::identity_resolution::{FoundProfile, NewIdentityResolution};

        let mut database = servizio.into_database();
        let (Ok(azione), Ok(entita)) = (
            AuditAction::try_new("ricerca_puntuale"),
            AuditEntity::try_new("ricerca"),
        ) else {
            panic!("valori d'audit validi");
        };
        let Ok(id) = database.insert_identity_resolution(
            &NewIdentityResolution {
                requested_by: String::from("operatore.prova"),
                reason: String::from("fascicolo 12/2026"),
                input_kind: String::from("numero"),
                input_value: String::from("390000000000"),
                requested_at: Timestamp::from_millis(ORA),
                executed: true,
                outcome: String::from(esito),
                outcome_reason: String::from("motivo"),
                wait_seconds: None,
                technical_detail: None,
                found: profilo.map(|(genere, id)| FoundProfile {
                    kind: String::from(genere),
                    telegram_id: id,
                    name: String::from("Nome restituito"),
                    username: None,
                    details: None,
                }),
                table_version: 1,
            },
            &NewAuditEntry {
                actor: attore(),
                action: azione,
                entity: entita,
                entity_id: None,
                actor_mode: None,
                detail: None,
                recorded_at: Timestamp::from_millis(ORA),
            },
        ) else {
            panic!("la ricerca deve registrarsi");
        };
        (
            IdentityLinkService::new(database),
            lisi_core::IdentityResolutionId::new(id),
        )
    }

    /// **Si collega soltanto un «trovato» di una persona, e il legame dice la
    /// sua base** (PR-10): origine Operatore, identificativo quello restituito
    /// da Telegram, motivo quello scritto.
    #[test]
    fn si_collega_soltanto_un_trovato_di_una_persona() {
        use lisi_core::model::origin::Origin;

        let (servizio, persona) = servizio();
        let (servizio, trovata) = con_ricerca(servizio, "trovato", Some(("persona", 42)));
        let (servizio, canale) = con_ricerca(servizio, "trovato", Some(("canale", -1_001)));
        let (servizio, assente) = con_ricerca(servizio, "dato_non_disponibile", None);
        let motivo = ragione("stesso numero dichiarato negli atti del procedimento");
        let quando = Timestamp::from_millis(ORA + 10);

        for base in [canale, assente, lisi_core::IdentityResolutionId::new(999)] {
            let esito = servizio.link_from_resolution(persona, base, &motivo, &attore(), quando);
            assert!(
                matches!(
                    esito,
                    Err(crate::error::ServiceError::LinkBasisRefused { .. })
                ),
                "la base {base:?} doveva essere rifiutata: {esito:?}"
            );
        }
        let Ok(_) = servizio.link_from_resolution(persona, trovata, &motivo, &attore(), quando)
        else {
            panic!("un «trovato» di una persona si collega");
        };
        let Ok(legami) = servizio.current(persona) else {
            panic!("i legami devono leggersi");
        };
        assert_eq!(legami.len(), 1);
        assert_eq!(
            legami[0].identifier, "42",
            "l'identificativo restituito, non uno scelto"
        );
        assert_eq!(legami[0].origin(), Origin::Operator);
        assert_eq!(legami[0].resolution, Some(trovata));
        assert!(legami[0].as_sentence().contains("ricerca puntuale"));
        assert_eq!(
            legami[0].reason, motivo,
            "il motivo scritto resta (controllo negativo 4)"
        );
    }

    /// Il codice di produzione di un modulo, senza commenti.
    fn produzione_senza_commenti(sorgente: &str) -> String {
        let produzione = sorgente
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Il resolver non collega, e nessuno suggerisce** (PR-10, controlli
    /// negativi 1 e 2): la ricerca puntuale non nomina i legami, e né il
    /// servizio dei legami né quello della ricerca contengono un posto dove
    /// una corrispondenza possa essere proposta.
    #[test]
    fn il_resolver_non_collega_e_nessuno_suggerisce() {
        const RESOLVER: &str = include_str!("identity_resolver.rs");
        const LEGAMI: &str = include_str!("identity_link.rs");

        let resolver = produzione_senza_commenti(RESOLVER);
        for vietato in [
            "identity_link",
            "insert_identity_link",
            "PersonId",
            "link_from_resolution",
        ] {
            assert!(
                !resolver.contains(vietato),
                "«{vietato}» nella ricerca puntuale: un legame nasce soltanto da una persona"
            );
        }
        for (nome, codice) in [
            ("ricerca", resolver),
            ("legami", produzione_senza_commenti(LEGAMI)),
        ] {
            let minuscolo = codice.to_lowercase();
            for vietato in [
                "suggeri",
                "suggest",
                "candidat",
                "similar",
                "somiglian",
                "probabil",
                "score",
            ] {
                assert!(
                    !minuscolo.contains(vietato),
                    "«{vietato}» nel modulo {nome}: nessuna corrispondenza si propone"
                );
            }
        }
    }

    /// **La stessa identità non si collega due volte allo stesso soggetto**
    /// (SUBJECT-02, CA02-11; prova negativa: controllo tolto → rossa).
    #[test]
    fn la_stessa_identita_non_si_collega_due_volte() {
        let (servizio, person) = servizio();
        let collega = |identificativo: &str, act: LinkAct, quando: i64| {
            servizio.record(
                person,
                identificativo,
                act,
                &ragione("riscontro documentale con l'autorita' procedente"),
                &attore(),
                Timestamp::from_millis(ORA + quando),
            )
        };
        for (primo, secondo) in [("@Mario_Rossi", "mario_rossi"), ("123456", "123456")] {
            let Ok(_) = collega(primo, LinkAct::Link, 100) else {
                panic!("il primo legame deve registrarsi");
            };
            assert!(
                matches!(
                    collega(secondo, LinkAct::Link, 200),
                    Err(crate::error::ServiceError::LinkBasisRefused { .. })
                ),
                "«{secondo}» è già collegata"
            );
        }
        assert!(
            collega("1234567", LinkAct::Link, 300).is_ok(),
            "un altro identificativo numerico è un'altra identità"
        );
        let Ok(_) = collega("123456", LinkAct::Unlink, 400) else {
            panic!("sciogliere resta possibile");
        };
        assert!(
            collega("123456", LinkAct::Link, 500).is_ok(),
            "dopo averla sciolta si ricollega"
        );
        let Ok(legami) = servizio.current(person) else {
            panic!("i legami devono leggersi");
        };
        assert_eq!(legami.len(), 3, "tre identità, ciascuna una volta");
    }
}

//! Associazioni manuali fra identità osservate e soggetti (PERS-06).
//!
//! # Che cosa questo modulo non fa
//!
//! Non cerca identità da collegare, non ne propone, non le ordina per
//! verosimiglianza e non le chiama «candidate».
//!
//! Il prodotto ha un algoritmo di somiglianza — serve a riconoscere due
//! ripubblicazioni dello stesso testo (ADR-0055) — e **questo modulo non lo
//! nomina**: applicarlo a due nomi di persona unirebbe due omonimi, che è
//! l'errore che PERS-02 aveva evitato raggruppando per identificativo.
//!
//! L'identificativo da collegare arriva da chi lo ha scritto, o non arriva.
//!
//! # Si aggiunge, non si cambia
//!
//! Non c'è una funzione che aggiorni un legame, e non c'è una funzione che ne
//! cancelli uno: **sciogliere è un atto**, non una cancellazione, e due trigger
//! rifiutano il resto.

use core::str::FromStr;

use lisi_core::model::identity_link::{IdentityLinkEntry, LinkAct, NewIdentityLink};
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::Actor;
use lisi_core::{IdentityLinkId, IdentityResolutionId, PersonId};

use crate::database::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

impl Database {
    /// Registra un atto su un legame.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il soggetto non esiste, se è **chiuso** — un
    /// trigger lo rifiuta — o se la scrittura non riesce.
    pub fn insert_identity_link(&self, link: &NewIdentityLink) -> StorageResult<IdentityLinkId> {
        // LA BASE (PR-10): vuota per un legame di sempre; la ricerca puntuale
        // da cui nasce, altrimenti. Un trigger rifiuta una base che non sia un
        // «trovato» di una persona, con il suo stesso identificativo.
        self.connection.execute(
            "INSERT INTO identity_links (
                 person_id, identifier, act, reason, linked_by, linked_at, resolution_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                link.person.get(),
                link.identifier.as_str(),
                link.act.as_str(),
                link.reason.as_str(),
                link.by.as_str(),
                millis(link.at),
                link.resolution.map(|ricerca| ricerca.get()),
            ],
        )?;
        Ok(IdentityLinkId::new(self.connection.last_insert_rowid()))
    }

    /// La storia degli atti sui legami di un soggetto, dal più antico.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn identity_link_history(&self, person: PersonId) -> StorageResult<Vec<IdentityLinkEntry>> {
        let mut statement = self.connection.prepare(
            "SELECT id, person_id, identifier, act, reason, linked_by, linked_at, resolution_id
             FROM identity_links
             WHERE person_id = ?1
             ORDER BY linked_at ASC, id ASC",
        )?;
        // ORDINE ESPLICITO, con criterio secondario: due atti nello stesso
        // millisecondo darebbero altrimenti due storie diverse a due letture.
        type Riga = (i64, i64, String, String, String, String, i64, Option<i64>);
        let grezze: Vec<Riga> = statement
            .query_map([person.get()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut voci = Vec::with_capacity(grezze.len());
        for (id, person_id, identifier, act, reason, by, at, ricerca) in grezze {
            voci.push(IdentityLinkEntry {
                id: IdentityLinkId::new(id),
                person: PersonId::new(person_id),
                identifier,
                act: LinkAct::from_str(&act)?,
                reason: OperationalReason::try_new(&reason)?,
                by: Actor::try_new(&by)?,
                at: instant(at),
                resolution: ricerca.map(IdentityResolutionId::new),
            });
        }
        Ok(voci)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::identity_link::{LinkAct, NewIdentityLink, current_links};
    use lisi_core::model::person::NewPerson;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::{Actor, DisplayName};
    use lisi_core::{PersonId, Timestamp};

    use crate::test_support::database_with_session;

    const ORA: i64 = 1_760_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

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

    fn archivio_con_soggetto() -> (crate::Database, PersonId) {
        let (database, _, _) = database_with_session();
        let Ok(etichetta) = DisplayName::try_new("Soggetto di prova") else {
            panic!("l'etichetta deve essere valida");
        };
        let Ok(person_id) = database.insert_person(
            &NewPerson::open(
                etichetta,
                ragione("richiesta dell'autorita' procedente del 4 marzo"),
            ),
            &attore(),
            istante(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };
        (database, person_id)
    }

    fn atto(person: PersonId, act: LinkAct, quando: i64) -> NewIdentityLink {
        NewIdentityLink {
            person,
            identifier: "111".to_owned(),
            act,
            reason: ragione("riscontro documentale con l'autorita' procedente"),
            by: attore(),
            at: istante(quando),
            resolution: None,
        }
    }

    /// Una ricerca puntuale registrata, con l'esito e il profilo indicati.
    fn ricerca(
        database: &mut crate::Database,
        esito: &str,
        profilo: Option<(&str, i64)>,
    ) -> lisi_core::IdentityResolutionId {
        use lisi_core::model::NewAuditEntry;
        use lisi_core::text::{AuditAction, AuditEntity};

        use crate::repository::identity_resolution::{FoundProfile, NewIdentityResolution};

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
                requested_at: istante(ORA),
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
                recorded_at: istante(ORA),
            },
        ) else {
            panic!("la ricerca deve registrarsi");
        };
        lisi_core::IdentityResolutionId::new(id)
    }

    /// **Un legame dal resolver nasce soltanto da un «trovato» di una persona,
    /// con il suo stesso identificativo** (PR-10): lo schema lo rifiuta
    /// altrimenti.
    #[test]
    fn un_legame_da_ricerca_nasce_solo_da_una_persona_trovata() {
        let (mut database, person) = archivio_con_soggetto();
        let trovata = ricerca(&mut database, "trovato", Some(("persona", 111)));
        let canale = ricerca(&mut database, "trovato", Some(("canale", 111)));
        let assente = ricerca(&mut database, "dato_non_disponibile", None);

        let mut con_base = atto(person, LinkAct::Link, ORA + 100);
        for (base, identificativo) in [(canale, "111"), (assente, "111"), (trovata, "222")] {
            con_base.resolution = Some(base);
            con_base.identifier = String::from(identificativo);
            assert!(
                database.insert_identity_link(&con_base).is_err(),
                "base {base:?} con {identificativo} doveva essere rifiutata"
            );
        }
        con_base.resolution = Some(trovata);
        con_base.identifier = String::from("111");
        let Ok(_) = database.insert_identity_link(&con_base) else {
            panic!("un «trovato» di una persona si collega");
        };
        let Ok(storia) = database.identity_link_history(person) else {
            panic!("la storia deve leggersi");
        };
        assert_eq!(storia.len(), 1);
        assert_eq!(storia[0].resolution, Some(trovata), "la base si rilegge");
    }

    /// **Un atto si registra, e la storia lo restituisce.**
    #[test]
    fn un_atto_si_registra_e_la_storia_lo_restituisce() {
        let (database, person) = archivio_con_soggetto();
        let Ok(_) = database.insert_identity_link(&atto(person, LinkAct::Link, ORA + 100)) else {
            panic!("l'atto deve potersi registrare");
        };

        let Ok(storia) = database.identity_link_history(person) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia.len(), 1);
        assert_eq!(storia[0].act, LinkAct::Link);

        let legami = current_links(&storia);
        assert_eq!(legami.len(), 1);
        assert_eq!(legami[0].identifier, "111");
    }

    /// **Sciogliere non cancella: la storia resta di due righe.**
    #[test]
    fn sciogliere_non_cancella() {
        let (database, person) = archivio_con_soggetto();
        for (act, quando) in [(LinkAct::Link, ORA + 100), (LinkAct::Unlink, ORA + 200)] {
            let Ok(_) = database.insert_identity_link(&atto(person, act, quando)) else {
                panic!("l'atto deve potersi registrare");
            };
        }

        let Ok(storia) = database.identity_link_history(person) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia.len(), 2, "la storia non si accorcia");
        assert!(
            current_links(&storia).is_empty(),
            "ma il legame non e' piu' in essere"
        );
    }

    /// **Un atto su un legame non si riscrive.**
    #[test]
    fn un_atto_non_si_riscrive() {
        let (database, person) = archivio_con_soggetto();
        let Ok(id) = database.insert_identity_link(&atto(person, LinkAct::Link, ORA + 100)) else {
            panic!("l'atto deve potersi registrare");
        };

        let esito = database.connection.execute(
            "UPDATE identity_links SET act = 'sciolta' WHERE id = ?1",
            [id.get()],
        );
        assert!(esito.is_err(), "il trigger deve rifiutare la riscrittura");
    }

    /// **Un atto su un legame non si cancella.**
    #[test]
    fn un_atto_non_si_cancella() {
        let (database, person) = archivio_con_soggetto();
        let Ok(id) = database.insert_identity_link(&atto(person, LinkAct::Link, ORA + 100)) else {
            panic!("l'atto deve potersi registrare");
        };

        let esito = database
            .connection
            .execute("DELETE FROM identity_links WHERE id = ?1", [id.get()]);
        assert!(esito.is_err(), "il trigger deve rifiutare la cancellazione");
    }

    /// **Un soggetto chiuso non si collega.**
    #[test]
    fn un_soggetto_chiuso_non_si_collega() {
        let (database, person) = archivio_con_soggetto();
        let Ok(()) = database.close_person(
            person,
            &attore(),
            &ragione("il procedimento si e' concluso senza rilievi"),
            istante(ORA + 50),
        ) else {
            panic!("il soggetto deve potersi chiudere");
        };

        let esito = database.insert_identity_link(&atto(person, LinkAct::Link, ORA + 100));
        assert!(
            esito.is_err(),
            "il trigger deve rifiutare il collegamento su un soggetto chiuso"
        );
    }

    /// **Un motivo troppo corto non entra, e nemmeno un identificativo vuoto.**
    #[test]
    fn un_motivo_corto_e_un_identificativo_vuoto_non_entrano() {
        let (database, person) = archivio_con_soggetto();

        let corta = database.connection.execute(
            "INSERT INTO identity_links (person_id, identifier, act, reason, linked_by, linked_at)
             VALUES (?1, '111', 'collegata', 'boh', 'x', ?2)",
            rusqlite::params![person.get(), ORA],
        );
        assert!(corta.is_err(), "il CHECK deve rifiutare un motivo vuoto");

        let vuoto = database.connection.execute(
            "INSERT INTO identity_links (person_id, identifier, act, reason, linked_by, linked_at)
             VALUES (?1, '   ', 'collegata', 'una ragione lunga abbastanza per passare', 'x', ?2)",
            rusqlite::params![person.get(), ORA],
        );
        assert!(
            vuoto.is_err(),
            "il CHECK deve rifiutare un identificativo vuoto"
        );
    }

    /// **La tabella non ha una colonna in cui una confidenza possa stare.**
    ///
    /// # Perché la guardia legge lo schema
    ///
    /// Perché un punteggio è vietato «anche spento»: una colonna aggiunta domani
    /// e mai riempita sarebbe comunque il posto in cui una misura può stare — e
    /// su un legame fra una persona e un fascicolo sarebbe una confidenza.
    #[test]
    fn la_tabella_non_ha_una_colonna_in_cui_una_confidenza_possa_stare() {
        const SCHEMA: &str = include_str!("../../migrations/0033_identity_links.sql");
        let Some(inizio) = SCHEMA.find("CREATE TABLE identity_links (") else {
            panic!("la tabella deve esistere");
        };
        let Some(fine) = SCHEMA[inizio..].find("\n);") else {
            panic!("la tabella deve chiudersi");
        };
        let corpo = &SCHEMA[inizio..inizio + fine];

        let numeriche: Vec<&str> = corpo
            .lines()
            .map(str::trim)
            .filter(|riga| !riga.starts_with("--"))
            .filter(|riga| riga.contains(" INTEGER") || riga.contains(" REAL"))
            .collect();

        assert_eq!(
            numeriche.len(),
            3,
            "le colonne numeriche devono restare tre \u{2014} {numeriche:?}"
        );
        for attesa in ["id INTEGER", "person_id INTEGER", "linked_at INTEGER"] {
            assert!(
                numeriche.iter().any(|riga| riga.starts_with(attesa)),
                "manca «{attesa}» fra le colonne numeriche ammesse"
            );
        }
        assert!(
            !corpo.contains(" REAL"),
            "una colonna REAL su un legame e' una confidenza"
        );
    }

    /// **Lo schema non offre un posto a una somiglianza.**
    #[test]
    fn lo_schema_non_offre_un_posto_a_una_somiglianza() {
        const SCHEMA: &str = include_str!("../../migrations/0033_identity_links.sql");
        let Some(inizio) = SCHEMA.find("CREATE TABLE identity_links (") else {
            panic!("la tabella deve esistere");
        };
        let Some(fine) = SCHEMA[inizio..].find("\n);") else {
            panic!("la tabella deve chiudersi");
        };
        let corpo = SCHEMA[inizio..inizio + fine].to_lowercase();

        for vietata in [
            "similarity",
            "somiglianza",
            "confidence",
            "confidenza",
            "candidate",
            "candidato",
            "suggested",
            "suggerito",
            "auto",
        ] {
            // Le righe di commento nominano cio' che vietano, per spiegarlo:
            // qui si guarda soltanto alle definizioni di colonna.
            let colonne: String = corpo
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !colonne.contains(vietata),
                "una colonna «{vietata}» sarebbe il posto in cui una fusione automatica puo' \
                 nascondersi"
            );
        }
    }
}

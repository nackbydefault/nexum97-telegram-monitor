//! Le organizzazioni che un amministratore ha dichiarato di sorvegliare.
//!
//! # La domanda che queste tabelle esistono per rispondere
//!
//! «Quali organizzazioni, dichiarate da chi amministra questa postazione,
//! possono comparire nei contenuti — e in quale settore le ha collocate.»
//!
//! È la sola cosa che permette a un settore di essere attribuito a un contenuto
//! senza inventarlo: la regola non la scrive il prodotto, la scrive una persona,
//! e ciò che si legge qui è quella scrittura.
//!
//! # Perché la lettura è completa e non pigra
//!
//! [`Database::watched_organisations`] carica alias e domini di ogni
//! organizzazione in una volta sola. È deliberato: il riscontro settoriale
//! confronta **ogni** contenuto con **ogni** organizzazione attiva, e leggere
//! gli alias per contenuto significherebbe una query per contenuto per
//! organizzazione.
//!
//! Il costo è che l'elenco intero sta in memoria. Con qualche centinaio di
//! organizzazioni — che è l'ordine di grandezza di ciò che un ufficio dichiara —
//! sono decine di chilobyte.

use lisi_core::model::organisation::{
    NewWatchedOrganisation, OrganisationAlias, OrganisationDomain, WatchedOrganisation,
};
use lisi_core::model::relevance::Sector;
use lisi_core::text::{Actor, DisplayName, Note};
use lisi_core::{Timestamp, WatchedOrganisationId};

use super::millis;
use crate::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, classify};

impl Database {
    /// Dichiara un'organizzazione sorvegliata.
    ///
    /// Scrive organizzazione, alias e domini in **una sola transazione**:
    /// un'organizzazione con metà dei propri alias riscontrerebbe meno di
    /// quanto l'amministratore ha dichiarato, e nessuno se ne accorgerebbe.
    ///
    /// # Errori
    ///
    /// - [`StorageError::DuplicateOrganisation`] se il nome è già dichiarato;
    /// - [`StorageError::DuplicateOrganisationDomain`] se uno dei domini è già
    ///   dichiarato per un'altra organizzazione.
    pub fn insert_watched_organisation(
        &mut self,
        organisation: &NewWatchedOrganisation,
    ) -> StorageResult<WatchedOrganisationId> {
        let transazione = self.connection.transaction()?;

        let id: i64 = transazione
            .query_row(
                "INSERT INTO watched_organisations (
                     name, sector, note, active, declared_by, declared_at, updated_at
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?5)
                 RETURNING id",
                rusqlite::params![
                    organisation.name.as_str(),
                    organisation.sector.as_str(),
                    organisation.note.as_ref().map(Note::as_str),
                    organisation.declared_by.as_str(),
                    millis(organisation.declared_at),
                ],
                |row| row.get(0),
            )
            .map_err(|errore| {
                classify(
                    errore,
                    ConstraintKind::Unique,
                    StorageError::DuplicateOrganisation,
                )
            })?;

        for alias in &organisation.aliases {
            transazione
                .execute(
                    "INSERT INTO watched_organisation_aliases (
                         organisation_id, written, normalised
                     ) VALUES (?1, ?2, ?3)",
                    rusqlite::params![id, alias.written(), alias.normalised()],
                )
                .map_err(|errore| {
                    classify(
                        errore,
                        ConstraintKind::Unique,
                        StorageError::DuplicateOrganisation,
                    )
                })?;
        }

        for dominio in &organisation.domains {
            transazione
                .execute(
                    "INSERT INTO watched_organisation_domains (organisation_id, domain)
                     VALUES (?1, ?2)",
                    rusqlite::params![id, dominio.as_str()],
                )
                .map_err(|errore| {
                    classify(
                        errore,
                        ConstraintKind::Unique,
                        StorageError::DuplicateOrganisationDomain,
                    )
                })?;
        }

        transazione.commit()?;
        Ok(WatchedOrganisationId::new(id))
    }

    /// Elenca le organizzazioni dichiarate, con i loro alias e domini.
    ///
    /// Ordinate per nome: l'elenco che l'amministratore rilegge non deve
    /// cambiare ordine fra due aperture.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore che il dominio rifiuta — che indica un archivio alterato.
    pub fn watched_organisations(&self) -> StorageResult<Vec<WatchedOrganisation>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, sector, note, active, declared_by, declared_at, updated_at
             FROM watched_organisations
             ORDER BY name, id",
        )?;

        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })?;

        let mut esito = Vec::new();
        for riga in righe {
            let (id, name, sector, note, active, declared_by, declared_at, updated_at) = riga?;

            let note = match note {
                Some(testo) => Some(Note::try_new(&testo)?),
                None => None,
            };

            esito.push(WatchedOrganisation {
                id: WatchedOrganisationId::new(id),
                name: DisplayName::try_new(&name)?,
                sector: Sector::try_from_str(&sector)?,
                aliases: Vec::new(),
                domains: Vec::new(),
                note,
                active,
                declared_by: Actor::try_new(&declared_by)?,
                declared_at: Timestamp::from_millis(declared_at),
                updated_at: Timestamp::from_millis(updated_at),
            });
        }
        drop(statement);

        self.fill_aliases_and_domains(&mut esito)?;
        Ok(esito)
    }

    /// Riempie alias e domini di ogni organizzazione.
    ///
    /// Due letture in tutto, non due per organizzazione: la seconda forma
    /// costerebbe il numero delle organizzazioni in interrogazioni, che su un
    /// elenco lungo si sente.
    fn fill_aliases_and_domains(
        &self,
        organizzazioni: &mut [WatchedOrganisation],
    ) -> StorageResult<()> {
        let mut per_id: std::collections::BTreeMap<i64, usize> = std::collections::BTreeMap::new();
        for (indice, organizzazione) in organizzazioni.iter().enumerate() {
            per_id.insert(organizzazione.id.get(), indice);
        }

        {
            let mut statement = self.connection.prepare(
                "SELECT organisation_id, written
                 FROM watched_organisation_aliases
                 ORDER BY organisation_id, normalised",
            )?;
            let righe = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            for riga in righe {
                let (organisation_id, written) = riga?;
                if let Some(indice) = per_id.get(&organisation_id) {
                    organizzazioni[*indice]
                        .aliases
                        .push(OrganisationAlias::try_new(&written)?);
                }
            }
        }

        let mut statement = self.connection.prepare(
            "SELECT organisation_id, domain
             FROM watched_organisation_domains
             ORDER BY organisation_id, domain",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        for riga in righe {
            let (organisation_id, domain) = riga?;
            if let Some(indice) = per_id.get(&organisation_id) {
                organizzazioni[*indice]
                    .domains
                    .push(OrganisationDomain::try_new(&domain)?);
            }
        }

        Ok(())
    }

    /// Attiva o disattiva un'organizzazione.
    ///
    /// # Perché non si cancella
    ///
    /// Un monitoraggio già svolto ha prodotto attribuzioni che nominano questa
    /// organizzazione. Cancellarla renderebbe inspiegabile un'attribuzione già
    /// registrata: chi rileggesse un vecchio alert troverebbe un settore e
    /// nessuna ragione.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se l'organizzazione non esiste.
    pub fn set_watched_organisation_active(
        &self,
        id: WatchedOrganisationId,
        active: bool,
        now: Timestamp,
    ) -> StorageResult<()> {
        let toccate = self.connection.execute(
            "UPDATE watched_organisations
             SET active = ?2, updated_at = ?3
             WHERE id = ?1",
            rusqlite::params![id.get(), active, millis(now)],
        )?;

        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "organizzazione sorvegliata",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Cancella un'organizzazione dichiarata per errore.
    ///
    /// # Perché esiste, accanto alla disattivazione
    ///
    /// Chi digita un nome sbagliato deve poterlo togliere: lasciare una riga
    /// errata «disattivata» sporcherebbe l'elenco per sempre. La disattivazione
    /// resta la scelta giusta per un'organizzazione che ha già prodotto
    /// attribuzioni, e la differenza fra i due atti la decide chi amministra —
    /// entrambi sono auditati.
    ///
    /// Alias e domini seguono per `ON DELETE CASCADE`.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se l'organizzazione non esiste.
    pub fn delete_watched_organisation(&self, id: WatchedOrganisationId) -> StorageResult<()> {
        let toccate = self.connection.execute(
            "DELETE FROM watched_organisations WHERE id = ?1",
            [id.get()],
        )?;

        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "organizzazione sorvegliata",
                id: id.get(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::organisation::{
        NewWatchedOrganisation, OrganisationAlias, OrganisationDomain,
    };
    use lisi_core::model::relevance::Sector;
    use lisi_core::text::{Actor, DisplayName};
    use lisi_core::{Timestamp, WatchedOrganisationId};

    use crate::error::StorageError;
    use crate::test_support::database;

    fn dichiarazione(
        nome: &str,
        settore: Sector,
        alias: &[&str],
        domini: &[&str],
    ) -> NewWatchedOrganisation {
        let (Ok(name), Ok(declared_by)) = (
            DisplayName::try_new(nome),
            Actor::try_new("amministratore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let aliases = alias
            .iter()
            .map(|voce| match OrganisationAlias::try_new(voce) {
                Ok(valore) => valore,
                Err(_) => panic!("alias di prova non valido: {voce}"),
            })
            .collect();
        let domains = domini
            .iter()
            .map(|voce| match OrganisationDomain::try_new(voce) {
                Ok(valore) => valore,
                Err(_) => panic!("dominio di prova non valido: {voce}"),
            })
            .collect();

        let Ok(valore) = NewWatchedOrganisation::try_new(
            name,
            settore,
            aliases,
            domains,
            None,
            declared_by,
            Timestamp::from_millis(1_000),
        ) else {
            panic!("la dichiarazione di prova deve essere valida");
        };
        valore
    }

    #[test]
    fn unorganizzazione_dichiarata_si_rilegge_con_alias_e_domini() {
        let mut database = database();

        let Ok(_) = database.insert_watched_organisation(&dichiarazione(
            "Ente Alfa",
            Sector::Energia,
            &["Ente Alfa", "Alfa Energia"],
            &["alfa.example"],
        )) else {
            panic!("la dichiarazione deve potersi scrivere");
        };

        let Ok(elenco) = database.watched_organisations() else {
            panic!("l'elenco deve potersi leggere");
        };

        assert_eq!(elenco.len(), 1);
        assert_eq!(elenco[0].sector, Sector::Energia);
        assert_eq!(elenco[0].aliases.len(), 2);
        assert_eq!(elenco[0].domains.len(), 1);
        assert!(elenco[0].active, "una dichiarazione nasce attiva");
        assert_eq!(elenco[0].declared_by.as_str(), "amministratore.prova");
    }

    #[test]
    fn due_organizzazioni_con_lo_stesso_nome_sono_rifiutate() {
        let mut database = database();

        let prima = dichiarazione("Ente Alfa", Sector::Sanita, &["Alfa"], &[]);
        let seconda = dichiarazione("Ente Alfa", Sector::Trasporti, &["Beta"], &[]);

        let Ok(_) = database.insert_watched_organisation(&prima) else {
            panic!("la prima deve potersi scrivere");
        };

        assert!(matches!(
            database.insert_watched_organisation(&seconda),
            Err(StorageError::DuplicateOrganisation)
        ));
    }

    /// **Lo stesso dominio non si dichiara per due organizzazioni.**
    ///
    /// Produrrebbe due settori per lo stesso fatto, e nessuno dei due sarebbe
    /// contestabile piu' dell'altro.
    #[test]
    fn lo_stesso_dominio_per_due_organizzazioni_e_rifiutato() {
        let mut database = database();

        let prima = dichiarazione("Ente Alfa", Sector::Sanita, &[], &["comune.example"]);
        let seconda = dichiarazione("Ente Beta", Sector::Trasporti, &[], &["comune.example"]);

        let Ok(_) = database.insert_watched_organisation(&prima) else {
            panic!("la prima deve potersi scrivere");
        };

        assert!(matches!(
            database.insert_watched_organisation(&seconda),
            Err(StorageError::DuplicateOrganisationDomain)
        ));
    }

    /// **Una dichiarazione rifiutata non lascia meta' organizzazione.**
    ///
    /// Il dominio duplicato viene rifiutato dopo che l'organizzazione e i suoi
    /// alias sono gia' stati scritti: senza la transazione resterebbe un'entita'
    /// senza il dominio che l'amministratore aveva dichiarato, e nessuno se ne
    /// accorgerebbe.
    #[test]
    fn una_dichiarazione_rifiutata_non_lascia_stato_parziale() {
        let mut database = database();

        let prima = dichiarazione("Ente Alfa", Sector::Sanita, &[], &["comune.example"]);
        let Ok(_) = database.insert_watched_organisation(&prima) else {
            panic!("la prima deve potersi scrivere");
        };

        let seconda = dichiarazione(
            "Ente Beta",
            Sector::Trasporti,
            &["Beta Trasporti"],
            &["proprio.example", "comune.example"],
        );
        assert!(database.insert_watched_organisation(&seconda).is_err());

        let Ok(elenco) = database.watched_organisations() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(
            elenco.len(),
            1,
            "l'organizzazione rifiutata non deve restare a meta'"
        );
    }

    #[test]
    fn la_disattivazione_conserva_la_riga() {
        let mut database = database();

        let Ok(id) = database.insert_watched_organisation(&dichiarazione(
            "Ente Alfa",
            Sector::Spazio,
            &["Alfa"],
            &[],
        )) else {
            panic!("la dichiarazione deve potersi scrivere");
        };

        let Ok(()) =
            database.set_watched_organisation_active(id, false, Timestamp::from_millis(2_000))
        else {
            panic!("la disattivazione deve riuscire");
        };

        let Ok(elenco) = database.watched_organisations() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(elenco.len(), 1, "la riga resta leggibile");
        assert!(!elenco[0].active);
    }

    #[test]
    fn la_cancellazione_porta_via_alias_e_domini() {
        let mut database = database();

        let Ok(id) = database.insert_watched_organisation(&dichiarazione(
            "Ente Alfa",
            Sector::Ricerca,
            &["Alfa"],
            &["alfa.example"],
        )) else {
            panic!("la dichiarazione deve potersi scrivere");
        };

        let Ok(()) = database.delete_watched_organisation(id) else {
            panic!("la cancellazione deve riuscire");
        };

        // Se alias e domini fossero rimasti, ridichiarare lo stesso dominio
        // fallirebbe: la prova lo esercita invece di leggere le tabelle.
        assert!(
            database
                .insert_watched_organisation(&dichiarazione(
                    "Ente Beta",
                    Sector::Ricerca,
                    &["Beta"],
                    &["alfa.example"],
                ))
                .is_ok(),
            "il dominio deve essere stato liberato dalla cancellazione"
        );
    }

    #[test]
    fn disattivare_unorganizzazione_inesistente_e_un_errore_dichiarato() {
        let database = database();

        assert!(matches!(
            database.set_watched_organisation_active(
                WatchedOrganisationId::new(999),
                false,
                Timestamp::from_millis(1_000)
            ),
            Err(StorageError::NotFound { .. })
        ));
    }
}

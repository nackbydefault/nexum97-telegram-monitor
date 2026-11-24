//! Dichiarare, sospendere e togliere le organizzazioni sorvegliate.
//!
//! # Perché è un atto e non una configurazione
//!
//! Dichiarare che un'organizzazione appartiene a un settore è la **regola** che
//! permette a un settore di comparire su un contenuto. Da quel momento, ogni
//! contenuto che la nomina porterà quel settore in un alert, in uno storico e in
//! un documento consegnato.
//!
//! Per questo ogni operazione qui dentro è **riservata all'amministratore** ed è
//! **auditata**: chi rilegge un'attribuzione fra sei mesi deve poter risalire a
//! chi ha scritto la regola, e quando.
//!
//! # Che cosa questo servizio non fa
//!
//! Non deduce settori. Non propone organizzazioni. Non contiene alcun elenco di
//! enti — quello lo scrive una persona, e il prodotto lo legge.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::organisation::{NewWatchedOrganisation, WatchedOrganisation};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, Timestamp, WatchedOrganisationId};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Entità con cui le voci di audit di questo servizio si presentano.
const ENTITY: &str = "organizzazione_sorvegliata";

/// Gestione dell'elenco delle organizzazioni sorvegliate.
#[derive(Debug)]
pub struct OrganisationService {
    database: Database,
    mode: OperatingMode,
}

impl OrganisationService {
    /// Crea il servizio nella modalità operativa indicata.
    #[must_use]
    pub const fn new(database: Database, mode: OperatingMode) -> Self {
        Self { database, mode }
    }

    /// Archivio sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Elenca le organizzazioni dichiarate.
    ///
    /// **La lettura non è riservata**: un operatore che vede un settore su un
    /// alert deve poter sapere da dove viene, e negargli l'elenco renderebbe
    /// l'attribuzione incontestabile — che è il contrario di ciò che serve.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn organisations(&self) -> ServiceResult<Vec<WatchedOrganisation>> {
        Ok(self.database.watched_organisations()?)
    }

    /// Dichiara un'organizzazione sorvegliata.
    ///
    /// # Errori
    ///
    /// - [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// - un errore dell'archivio se il nome o un dominio sono già dichiarati.
    pub fn declare(
        &mut self,
        organisation: &NewWatchedOrganisation,
        now: Timestamp,
    ) -> ServiceResult<WatchedOrganisationId> {
        self.require_administrator()?;

        let id = self.database.insert_watched_organisation(organisation)?;

        // Il dettaglio porta il settore e **quante** ancore sono state
        // dichiarate, non quali: gli alias e i domini stanno nell'archivio, e
        // ripeterli nell'audit ne farebbe due copie da tenere allineate.
        self.record(
            &organisation.declared_by,
            "organizzazione_dichiarata",
            Some(id.get()),
            &format!(
                "settore {}, {} nomi, {} domini",
                organisation.sector.as_str(),
                organisation.aliases.len(),
                organisation.domains.len()
            ),
            now,
        )?;

        Ok(id)
    }

    /// Sospende o riattiva un'organizzazione.
    ///
    /// Sospenderla ferma i riscontri futuri e lascia leggibili quelli già
    /// registrati: è la ragione per cui esiste, accanto alla rimozione.
    ///
    /// # Errori
    ///
    /// - [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// - un errore dell'archivio se l'organizzazione non esiste.
    pub fn set_active(
        &mut self,
        id: WatchedOrganisationId,
        active: bool,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.require_administrator()?;

        self.database
            .set_watched_organisation_active(id, active, now)?;

        let azione = if active {
            "organizzazione_riattivata"
        } else {
            "organizzazione_sospesa"
        };
        self.record(actor, azione, Some(id.get()), "", now)
    }

    /// Toglie un'organizzazione dichiarata per errore.
    ///
    /// # Perché il motivo è obbligatorio
    ///
    /// Sospendere è reversibile e lascia una traccia leggibile; togliere no. Chi
    /// toglie deve dire perché, altrimenti fra sei mesi l'unica cosa che si
    /// saprà è che qualcosa c'era e non c'è più.
    ///
    /// # Errori
    ///
    /// - [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// - [`ServiceError::ReasonRequired`] se il motivo è vuoto;
    /// - un errore dell'archivio se l'organizzazione non esiste.
    pub fn remove(
        &mut self,
        id: WatchedOrganisationId,
        reason: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.require_administrator()?;

        if reason.trim().is_empty() {
            return Err(ServiceError::ReasonRequired);
        }

        self.database.delete_watched_organisation(id)?;
        self.record(actor, "organizzazione_rimossa", Some(id.get()), reason, now)
    }

    /// Se la modalità corrente permette di scrivere l'elenco.
    ///
    /// Serve all'interfaccia per non offrire un comando che il servizio
    /// rifiuterebbe. **Non sostituisce il controllo**: quello resta qui, e ogni
    /// scrittura vi passa comunque.
    #[must_use]
    pub fn can_declare(&self) -> bool {
        self.mode.allows(RestrictedAction::ConfigureSources)
    }

    /// Verifica che la modalità corrente permetta di scrivere l'elenco.
    ///
    /// Si riusa [`RestrictedAction::ConfigureSources`]: dichiarare quali
    /// organizzazioni si sorvegliano è configurazione del monitoraggio, come
    /// dichiarare quali fonti si leggono. Aggiungere un'azione riservata nuova
    /// avrebbe costretto ogni postazione a riassegnarla, per una distinzione che
    /// nessuno ha chiesto.
    fn require_administrator(&self) -> ServiceResult<()> {
        if self.mode.allows(RestrictedAction::ConfigureSources) {
            return Ok(());
        }
        Err(ServiceError::ActionReservedToAdministrator {
            action: RestrictedAction::ConfigureSources,
        })
    }

    /// Scrive una voce di audit.
    fn record(
        &self,
        actor: &Actor,
        action: &str,
        entity_id: Option<i64>,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = if detail.trim().is_empty() {
            None
        } else {
            Some(AuditDetail::try_new(detail)?)
        };

        let entry = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new(ENTITY)?,
            entity_id,
            actor_mode: Some(self.mode),
            detail,
            recorded_at: now,
        };

        self.database.append_audit(&entry)?;
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
    use lisi_core::{OperatingMode, Timestamp};

    use super::OrganisationService;
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    fn attore() -> Actor {
        let Ok(valore) = Actor::try_new("amministratore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        valore
    }

    fn dichiarazione(nome: &str, settore: Sector, domini: &[&str]) -> NewWatchedOrganisation {
        let Ok(name) = DisplayName::try_new(nome) else {
            panic!("il nome di prova deve essere valido");
        };
        let Ok(alias) = OrganisationAlias::try_new(nome) else {
            panic!("l'alias di prova deve essere valido");
        };
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
            vec![alias],
            domains,
            None,
            attore(),
            Timestamp::from_millis(1_000),
        ) else {
            panic!("la dichiarazione di prova deve essere valida");
        };
        valore
    }

    fn servizio(mode: OperatingMode) -> OrganisationService {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        OrganisationService::new(database, mode)
    }

    #[test]
    fn lamministratore_dichiara_e_lelenco_lo_riporta() {
        let mut servizio = servizio(OperatingMode::Administrator);

        let Ok(_) = servizio.declare(
            &dichiarazione("Ente Alfa", Sector::Energia, &["alfa.example"]),
            Timestamp::from_millis(2_000),
        ) else {
            panic!("la dichiarazione deve riuscire");
        };

        let Ok(elenco) = servizio.organisations() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(elenco.len(), 1);
        assert_eq!(elenco[0].sector, Sector::Energia);
    }

    /// **In modalita' operatore l'elenco si scrive, e ogni atto lascia traccia**
    /// (ADR-0140).
    ///
    /// Fino al 2026-10-15 la prova diceva il contrario
    /// (`in_modalita_operatore_dichiarare_e_rifiutato`): dichiarare
    /// un'organizzazione era un atto di chi amministra. Il proprietario ha
    /// deciso che configurare il monitoraggio e' lavoro del personale
    /// autorizzato; la protezione e' il motivo obbligatorio alla rimozione e
    /// l'audit, non il rifiuto.
    #[test]
    fn in_modalita_operatore_dichiarare_sospendere_e_rimuovere_si_puo() {
        let mut servizio = servizio(OperatingMode::Operator);
        assert!(servizio.can_declare());

        let Ok(id) = servizio.declare(
            &dichiarazione("Ente Alfa", Sector::Sanita, &[]),
            Timestamp::from_millis(2_000),
        ) else {
            panic!("l'operatore dichiara un'organizzazione");
        };
        assert!(
            servizio
                .set_active(id, false, &attore(), Timestamp::from_millis(3_000))
                .is_ok()
        );
        assert!(
            servizio
                .remove(
                    id,
                    "errore di battitura",
                    &attore(),
                    Timestamp::from_millis(4_000)
                )
                .is_ok()
        );
        let Ok(voci) = servizio.database.audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            voci.iter()
                .any(|voce| voce.action.as_str() == "organizzazione_rimossa"),
            "la rimozione lascia traccia"
        );
    }

    /// **L'operatore puo' sempre LEGGERE l'elenco.**
    ///
    /// Chi vede un settore su un alert deve poter sapere da dove viene: negargli
    /// l'elenco renderebbe l'attribuzione incontestabile.
    #[test]
    fn in_modalita_operatore_lelenco_si_legge() {
        let servizio = servizio(OperatingMode::Operator);
        assert!(servizio.organisations().is_ok());
    }

    #[test]
    fn togliere_unorganizzazione_senza_motivo_e_rifiutato() {
        let mut servizio = servizio(OperatingMode::Administrator);

        let Ok(id) = servizio.declare(
            &dichiarazione("Ente Alfa", Sector::Trasporti, &[]),
            Timestamp::from_millis(2_000),
        ) else {
            panic!("la dichiarazione deve riuscire");
        };

        assert!(matches!(
            servizio.remove(id, "   ", &attore(), Timestamp::from_millis(3_000)),
            Err(ServiceError::ReasonRequired)
        ));
    }

    /// **Ogni atto lascia una voce di audit.**
    ///
    /// E' cio' che permette, fra sei mesi, di risalire da un'attribuzione a chi
    /// ha scritto la regola che l'ha prodotta.
    #[test]
    fn ogni_atto_sullelenco_e_auditato() {
        let mut servizio = servizio(OperatingMode::Administrator);

        let Ok(id) = servizio.declare(
            &dichiarazione("Ente Alfa", Sector::Bancario, &["alfa.example"]),
            Timestamp::from_millis(2_000),
        ) else {
            panic!("la dichiarazione deve riuscire");
        };
        let Ok(()) = servizio.set_active(id, false, &attore(), Timestamp::from_millis(3_000))
        else {
            panic!("la sospensione deve riuscire");
        };
        let Ok(()) = servizio.remove(
            id,
            "dichiarata per errore",
            &attore(),
            Timestamp::from_millis(4_000),
        ) else {
            panic!("la rimozione deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };

        let azioni: Vec<&str> = voci.iter().map(|voce| voce.action.as_str()).collect();
        assert!(azioni.contains(&"organizzazione_dichiarata"));
        assert!(azioni.contains(&"organizzazione_sospesa"));
        assert!(azioni.contains(&"organizzazione_rimossa"));
    }

    /// **L'audit non ripete alias e domini.**
    ///
    /// L'audit documenta le azioni, non i dati su cui insistono: gli alias
    /// stanno nell'archivio, e copiarli qui ne farebbe due copie da tenere
    /// allineate.
    #[test]
    fn laudit_non_ripete_le_ancore_dichiarate() {
        let mut servizio = servizio(OperatingMode::Administrator);

        let Ok(_) = servizio.declare(
            &dichiarazione(
                "Ente Riconoscibile",
                Sector::Spazio,
                &["riconoscibile.example"],
            ),
            Timestamp::from_millis(2_000),
        ) else {
            panic!("la dichiarazione deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };

        for voce in &voci {
            if let Some(dettaglio) = &voce.detail {
                assert!(
                    !dettaglio.as_str().contains("riconoscibile.example"),
                    "il dettaglio dell'audit non deve ripetere i domini dichiarati"
                );
            }
        }
    }
}

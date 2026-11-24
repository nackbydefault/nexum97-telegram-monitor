//! Impostazioni delle notifiche: le legge, le valida e le conserva.
//!
//! Il servizio è sottile: la persistenza è nell'archivio (DEC-103) e i limiti
//! sono nel dominio (`NotificationSettings::sanitized`). Qui si mette in fila
//! lettura, validazione e traccia d'audit.
//!
//! # Un limite dichiarato
//!
//! Le impostazioni si salvano e si rileggono, ma il consumatore vero — il motore
//! che durante l'acquisizione dal vivo decide se notificare — non è ancora
//! collegato: dipende da M3B. Finché non lo è, cambiarle è una scelta che varrà
//! quando l'acquisizione esisterà, non un effetto immediato.

use lisi_core::Timestamp;
use lisi_core::model::{NewAuditEntry, NotificationSettings};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// Servizio delle impostazioni.
#[derive(Debug)]
pub struct SettingsService {
    database: Database,
}

impl SettingsService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Database sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce il database, consumando il servizio.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Legge le impostazioni conservate.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn load(&self) -> ServiceResult<NotificationSettings> {
        Ok(self.database.notification_settings()?)
    }

    /// Salva le impostazioni, ricondotte entro i limiti, e ne lascia traccia.
    ///
    /// Restituisce le impostazioni **effettivamente** conservate: se un valore
    /// era fuori scala, quello salvato è quello ricondotto, e chi chiama deve
    /// mostrare ciò che vale davvero, non ciò che era stato chiesto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura o la registrazione non riescono.
    pub fn save(
        &self,
        settings: NotificationSettings,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<NotificationSettings> {
        let sanitized = settings.sanitized();
        self.database.save_notification_settings(&sanitized)?;
        self.audit(&sanitized, actor, now)?;
        Ok(sanitized)
    }

    /// Registra nell'audit l'attivazione o la disattivazione dell'avvio
    /// automatico all'accesso a Windows.
    ///
    /// **Non conserva lo stato**, e la distinzione è deliberata: lo stato vive
    /// nel registro di Windows, che è l'unica fonte. Qui resta il *fatto* che
    /// qualcuno lo ha cambiato e quando — che il registro, da solo, non dice.
    ///
    /// Che una postazione avvii da sola un programma di monitoraggio è una sua
    /// proprietà, non una preferenza estetica: chi rilegge l'audit deve poterla
    /// ricostruire.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la registrazione non riesce.
    pub fn record_autostart_change(
        &self,
        enabled: bool,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(if enabled {
                "avvio_automatico_attivato"
            } else {
                "avvio_automatico_disattivato"
            })?,
            entity: AuditEntity::try_new("station")?,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Registra nell'audit l'acquisto o la perdita della parola di sblocco di
    /// un account.
    ///
    /// **Non conserva la parola né lo stato**: quelli vivono nel file protetto
    /// del blocco. Qui resta il *fatto* che qualcuno ha cambiato la protezione
    /// di un account e quando — che il file protetto, da solo, non dice.
    ///
    /// L'account è identificato dal proprio UUID, che non è un dato personale e
    /// non rivela nulla di chi lo usa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la registrazione non riesce.
    pub fn record_lock_change(
        &self,
        account_uuid: &str,
        protected: bool,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(if protected {
                "blocco_parola_impostata"
            } else {
                "blocco_parola_rimossa"
            })?,
            entity: AuditEntity::try_new("telegram_account")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(account_uuid)?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Registra nell'audit la modifica delle impostazioni.
    ///
    /// Il dettaglio è la forma delle impostazioni — riservatezza, soglia, tetto —
    /// non un dato riservato: documenta *come* la postazione notificherà, non
    /// alcun contenuto.
    fn audit(
        &self,
        settings: &NotificationSettings,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = format!(
            "{}/liv{}/max{}/url:{}",
            settings.privacy.as_str(),
            settings.minimum_level,
            settings.max_per_session,
            if settings.include_url { "si" } else { "no" }
        );
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("impostazioni_notifiche_salvate")?,
            entity: AuditEntity::try_new("settings")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&detail)?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::{NotificationPrivacy, NotificationSettings};
    use lisi_core::text::Actor;

    use super::SettingsService;
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn service() -> SettingsService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        SettingsService::new(database)
    }

    #[test]
    fn a_fresh_station_reads_the_prudent_default() {
        // La migrazione scrive una riga predefinita: chi legge non trova mai
        // l'assenza, e il default coincide con quello del dominio.
        let service = service();
        let Ok(settings) = service.load() else {
            panic!("le impostazioni predefinite devono potersi leggere");
        };
        assert_eq!(settings, NotificationSettings::default());
    }

    #[test]
    fn saved_settings_are_read_back() {
        let service = service();
        let chosen = NotificationSettings {
            privacy: NotificationPrivacy::Full,
            minimum_level: 3,
            max_per_session: 10,
            include_url: true,
            cyber_enabled: true,
            cyber_minimum_contents: 4,
            cyber_minimum_sources: 3,
        };

        let Ok(saved) = service.save(chosen, &operator(), now()) else {
            panic!("il salvataggio deve riuscire");
        };
        assert_eq!(saved, chosen);

        let Ok(reloaded) = service.load() else {
            panic!("le impostazioni salvate devono potersi rileggere");
        };
        assert_eq!(reloaded, chosen);
    }

    #[test]
    fn turning_the_automatic_start_on_and_off_leaves_two_distinguishable_traces() {
        let service = service();

        let (Ok(()), Ok(())) = (
            service.record_autostart_change(true, &operator(), now()),
            service.record_autostart_change(false, &operator(), now()),
        ) else {
            panic!("la registrazione deve riuscire in entrambi i casi");
        };

        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let actions: Vec<&str> = audit
            .iter()
            .map(|entry| entry.action.as_str())
            .filter(|action| action.starts_with("avvio_automatico"))
            .collect();

        // Due voci **diverse**: che una postazione si avvii da sola e che smetta
        // di farlo sono due fatti opposti, e un'unica azione con un dettaglio
        // costringerebbe chi rilegge a fidarsi del dettaglio per distinguerli.
        assert!(actions.contains(&"avvio_automatico_attivato"));
        assert!(actions.contains(&"avvio_automatico_disattivato"));
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn out_of_range_values_are_brought_back_before_saving() {
        let service = service();
        let wild = NotificationSettings {
            privacy: NotificationPrivacy::Confidential,
            minimum_level: 9,
            max_per_session: 100_000,
            include_url: false,
            // Fuori scala anche queste: la ricomposizione deve riportarle
            // dentro invece di far fallire il salvataggio.
            cyber_enabled: true,
            cyber_minimum_contents: 0,
            cyber_minimum_sources: 9_999,
        };

        let Ok(saved) = service.save(wild, &operator(), now()) else {
            panic!("un valore fuori scala non deve far fallire il salvataggio");
        };
        assert_eq!(saved.minimum_level, 4);
        assert!(saved.max_per_session <= 1_000);

        // E cio' che e' in archivio e' il valore ricondotto, non quello chiesto.
        let Ok(reloaded) = service.load() else {
            panic!("le impostazioni devono potersi rileggere");
        };
        assert_eq!(reloaded, saved);
    }

    #[test]
    fn saving_leaves_a_trace_in_the_audit() {
        let service = service();
        let Ok(_) = service.save(NotificationSettings::default(), &operator(), now()) else {
            panic!("il salvataggio deve riuscire");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            entries
                .iter()
                .any(|entry| entry.action.as_str() == "impostazioni_notifiche_salvate"),
            "la modifica delle impostazioni va registrata"
        );
    }
}

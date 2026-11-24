//! Impostazioni delle notifiche, conservate per postazione.
//!
//! Una riga sola (`CHECK (id = 1)`), scritta con i valori predefiniti dalla
//! migrazione: chi legge non gestisce mai l'assenza. Le scelte sono in DEC-103.

use core::str::FromStr;

use lisi_core::model::language::InterfaceLanguage;
use lisi_core::model::motion::MotionPreference;
use lisi_core::model::{ExportDestination, NotificationPrivacy, NotificationSettings};
use lisi_core::text::Actor;
use rusqlite::Row;

use crate::database::Database;
use crate::error::StorageResult;

fn read(row: &Row<'_>) -> StorageResult<NotificationSettings> {
    let privacy = NotificationPrivacy::from_str(&row.get::<_, String>(0)?)?;
    let minimum_level = u8::try_from(row.get::<_, i64>(1)?).unwrap_or(1);
    let max_per_session = usize::try_from(row.get::<_, i64>(2)?).unwrap_or(0);
    let include_url = row.get::<_, i64>(3)? != 0;
    let cyber_enabled = row.get::<_, i64>(4)? != 0;
    // Un valore illeggibile ricade sul PREDEFINITO del dominio, non su zero:
    // zero non e' una soglia ammessa, e scriverlo qui produrrebbe un grappolo
    // annunciato appena nato.
    let predefinite = NotificationSettings::default();
    let cyber_minimum_contents =
        u32::try_from(row.get::<_, i64>(5)?).unwrap_or(predefinite.cyber_minimum_contents);
    let cyber_minimum_sources =
        u32::try_from(row.get::<_, i64>(6)?).unwrap_or(predefinite.cyber_minimum_sources);

    Ok(NotificationSettings {
        privacy,
        minimum_level,
        max_per_session,
        include_url,
        cyber_enabled,
        cyber_minimum_contents,
        cyber_minimum_sources,
    })
}

impl Database {
    /// Legge le impostazioni delle notifiche.
    ///
    /// La riga esiste sempre: la migrazione ne scrive una predefinita. Non c'è
    /// quindi un caso «assenti».
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se un valore conservato
    /// non è interpretabile (database alterato).
    pub fn notification_settings(&self) -> StorageResult<NotificationSettings> {
        self.connection.query_row(
            "SELECT privacy, minimum_level, max_per_session, include_url,
                    cyber_enabled, cyber_minimum_contents, cyber_minimum_sources
                 FROM notification_settings WHERE id = 1",
            [],
            |row| Ok(read(row)),
        )?
    }

    /// Salva le impostazioni delle notifiche, sostituendo l'unica riga.
    ///
    /// I `CHECK` dello schema rifiutano una riservatezza o un livello fuori
    /// dominio: sono la rete di sicurezza sotto la validazione del servizio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce o se un valore viola un
    /// vincolo dello schema.
    pub fn save_notification_settings(&self, settings: &NotificationSettings) -> StorageResult<()> {
        let max = i64::try_from(settings.max_per_session).unwrap_or(i64::MAX);
        self.connection.execute(
            "UPDATE notification_settings
             SET privacy = ?1, minimum_level = ?2, max_per_session = ?3, include_url = ?4,
                 cyber_enabled = ?5, cyber_minimum_contents = ?6, cyber_minimum_sources = ?7
             WHERE id = 1",
            rusqlite::params![
                settings.privacy.as_str(),
                i64::from(settings.minimum_level),
                max,
                i64::from(settings.include_url),
                i64::from(settings.cyber_enabled),
                i64::from(settings.cyber_minimum_contents),
                i64::from(settings.cyber_minimum_sources),
            ],
        )?;
        Ok(())
    }

    /// La cartella scelta per i documenti, se ne e' stata scelta una.
    ///
    /// `None` significa **cartella predefinita della postazione**, e non
    /// «impostazione mancante»: la riga esiste sempre, la scrive la migrazione.
    ///
    /// # Perche' il percorso si riconvalida qui
    ///
    /// Perche' esce dall'archivio, e l'archivio e' un file su disco che qualcuno
    /// puo' aver modificato. Un percorso relativo o con un `..` in mezzo, riletto
    /// senza guardarlo, farebbe scrivere i documenti altrove. Un valore
    /// conservato che il dominio non accetta piu' non si accomoda in silenzio: e'
    /// un archivio manomesso o una regola cambiata, e in entrambi i casi va detto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se il percorso
    /// conservato non e' piu' accettabile.
    pub fn export_destination(&self) -> StorageResult<Option<ExportDestination>> {
        let stored: Option<String> = self.connection.query_row(
            "SELECT path FROM export_destination WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        stored
            .as_deref()
            .map(ExportDestination::try_new)
            .transpose()
            .map_err(Into::into)
    }

    /// Salva la cartella scelta, o torna alla predefinita passando `None`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn save_export_destination(
        &self,
        destination: Option<&ExportDestination>,
        actor: &Actor,
        now_ms: i64,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE export_destination
             SET path = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![
                destination.map(ExportDestination::as_str),
                now_ms,
                actor.as_str(),
            ],
        )?;
        Ok(())
    }
}

impl Database {
    /// La preferenza sul movimento conservata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn motion_preference(&self) -> StorageResult<MotionPreference> {
        let scelta: String = self.connection.query_row(
            "SELECT choice FROM motion_preference WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(MotionPreference::from_stored(&scelta))
    }

    /// Salva la preferenza sul movimento.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn save_motion_preference(
        &self,
        choice: MotionPreference,
        actor: &Actor,
        now_ms: i64,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE motion_preference
             SET choice = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![choice.as_str(), now_ms, actor.as_str()],
        )?;
        Ok(())
    }

    /// La lingua dell'interfaccia conservata (I18N-01, ADR-0197).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn interface_language(&self) -> StorageResult<InterfaceLanguage> {
        let scelta: String = self.connection.query_row(
            "SELECT choice FROM interface_language WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(InterfaceLanguage::from_stored(&scelta))
    }

    /// Salva la lingua dell'interfaccia, con chi l'ha scelta e quando.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn save_interface_language(
        &self,
        choice: InterfaceLanguage,
        actor: &Actor,
        now_ms: i64,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE interface_language
             SET choice = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![choice.as_str(), now_ms, actor.as_str()],
        )?;
        Ok(())
    }
}

impl Database {
    /// Il canale degli aggiornamenti scelto per questa postazione.
    ///
    /// # Perché torna una stringa e non un tipo
    ///
    /// Il canale vive in `lisi-services`, perché è anche un campo del manifesto
    /// e ne segue la serializzazione. L'archivio non può nominarlo senza
    /// invertire la direzione delle dipendenze, e **duplicarne l'enumerazione
    /// qui** produrrebbe due elenchi destinati a divergere.
    ///
    /// L'etichetta conservata è quella del manifesto (`stable`, `pilot`), e il
    /// vincolo che la tiene sta nella migrazione: un valore inventato a mano
    /// non entra.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn update_channel(&self) -> StorageResult<String> {
        let scelta: String = self.connection.query_row(
            "SELECT choice FROM update_channel WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(scelta)
    }

    /// Salva il canale scelto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, **compreso** il caso
    /// di un'etichetta che la migrazione non ammette: il vincolo è là, e questo
    /// metodo non lo ripete: lo lascia parlare.
    pub fn save_update_channel(
        &self,
        choice: &str,
        actor: &Actor,
        now_ms: i64,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE update_channel
             SET choice = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![choice, now_ms, actor.as_str()],
        )?;
        Ok(())
    }
}

impl Database {
    /// L'origine del manifesto degli aggiornamenti, se configurata.
    ///
    /// # Perché l'assenza è un valore e non un errore
    ///
    /// Di fabbrica non c'è: nulla è pubblicato su alcun canale finché manca il
    /// certificato di firma, e un'origine inventata sarebbe un indirizzo che un
    /// giorno qualcuno contatta. `None` è la verità, non un caso limite.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn update_origin(&self) -> StorageResult<Option<String>> {
        let origine: Option<String> = self.connection.query_row(
            "SELECT origin FROM update_origin WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(origine)
    }

    /// Salva l'origine, o la svuota passando `None`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, **compreso** il caso di
    /// un indirizzo che non comincia con `https://`: il vincolo sta nella
    /// migrazione, e questo metodo lo lascia parlare invece di ripeterlo.
    pub fn save_update_origin(
        &self,
        origin: Option<&str>,
        actor: &Actor,
        now_ms: i64,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE update_origin
             SET origin = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![origin, now_ms, actor.as_str()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use lisi_core::model::{ExportDestination, NotificationPrivacy, NotificationSettings};
    use lisi_core::text::Actor;

    use crate::test_support::database;

    #[test]
    fn a_fresh_database_carries_the_default_row() {
        // La migrazione scrive una riga predefinita: chi legge non trova mai
        // l'assenza, e i valori coincidono con il Default del dominio.
        let database = database();
        let Ok(settings) = database.notification_settings() else {
            panic!("la riga predefinita deve potersi leggere");
        };
        assert_eq!(settings, NotificationSettings::default());
    }

    #[test]
    fn valid_settings_round_trip() {
        let database = database();
        let chosen = NotificationSettings {
            privacy: NotificationPrivacy::Full,
            minimum_level: 4,
            max_per_session: 7,
            include_url: true,
            cyber_enabled: true,
            cyber_minimum_contents: 6,
            cyber_minimum_sources: 4,
        };
        let Ok(()) = database.save_notification_settings(&chosen) else {
            panic!("il salvataggio deve riuscire");
        };
        assert_eq!(database.notification_settings().ok(), Some(chosen));
    }

    #[test]
    fn the_schema_check_refuses_an_out_of_range_level() {
        // La rete sotto la validazione del servizio: un valore che aggirasse
        // `sanitized` verrebbe respinto dallo schema con un errore, non scritto
        // in una riga fuori dominio.
        let database = database();
        let out_of_range = NotificationSettings {
            minimum_level: 9,
            ..NotificationSettings::default()
        };
        assert!(
            database.save_notification_settings(&out_of_range).is_err(),
            "un livello fuori scala deve essere respinto dal vincolo dello schema"
        );
        // E la riga resta quella valida di prima.
        assert_eq!(
            database.notification_settings().ok(),
            Some(NotificationSettings::default())
        );
    }
    #[test]
    fn a_fresh_database_has_no_chosen_folder_and_that_means_the_default_one() {
        // La riga esiste, il percorso e' NULL: «non scelta» e «predefinita»
        // sono la stessa cosa, e chi legge non gestisce l'assenza di riga.
        let database = database();
        let Ok(destination) = database.export_destination() else {
            panic!("la riga predefinita deve potersi leggere");
        };
        assert!(destination.is_none());
    }

    #[test]
    fn a_chosen_folder_round_trips() {
        let database = database();
        let attore = Actor::try_new("operatore").expect("attore valido");
        let scelta = ExportDestination::try_new(r"C:\Documenti\Relazioni").expect("valido");

        let Ok(()) = database.save_export_destination(Some(&scelta), &attore, 1_700_000_000_000)
        else {
            panic!("il salvataggio deve riuscire");
        };
        assert_eq!(database.export_destination().ok().flatten(), Some(scelta));
    }

    #[test]
    fn choosing_nothing_goes_back_to_the_default_folder() {
        // Tornare alla predefinita deve essere possibile senza cancellare la
        // riga: e' una scelta come le altre, non un ripristino di fabbrica.
        let database = database();
        let attore = Actor::try_new("operatore").expect("attore valido");
        let scelta = ExportDestination::try_new(r"C:\Documenti").expect("valido");
        let _ = database.save_export_destination(Some(&scelta), &attore, 1);
        let _ = database.save_export_destination(None, &attore, 2);

        assert!(database.export_destination().ok().flatten().is_none());
    }

    #[test]
    fn a_tampered_relative_path_is_an_error_and_not_a_guess() {
        // L'archivio e' un file su disco. Un percorso relativo scritto a mano
        // farebbe scrivere i documenti rispetto alla cartella di lavoro del
        // processo, che nessuno ha scelto: qui deve venire fuori un errore.
        let database = database();
        let Ok(_) = database.connection.execute(
            "UPDATE export_destination SET path = 'Relazioni' WHERE id = 1",
            [],
        ) else {
            panic!("la manomissione di prova deve potersi scrivere");
        };

        assert!(
            database.export_destination().is_err(),
            "un percorso conservato non valido non si accomoda in silenzio"
        );
    }

    /// **Una postazione nuova e' sul canale stabile, e lo trova gia' scritto.**
    #[test]
    fn una_postazione_nuova_e_sul_canale_stabile() {
        let database = database();
        let Ok(canale) = database.update_channel() else {
            panic!("la riga predefinita deve potersi leggere");
        };
        assert_eq!(canale, "stable");
    }

    #[test]
    fn il_canale_scelto_si_rilegge() {
        let database = database();
        let Ok(attore) = Actor::try_new("amministratore") else {
            panic!("l'attore di prova deve essere valido");
        };
        let Ok(()) = database.save_update_channel("pilot", &attore, 7) else {
            panic!("il canale deve potersi cambiare");
        };
        assert_eq!(database.update_channel().ok().as_deref(), Some("pilot"));
    }

    /// **Un canale inventato non entra, e non perche' lo controlli il codice.**
    ///
    /// Il vincolo sta nella migrazione. Senza, una postazione crederebbe di
    /// essere su un canale che non esiste, e il confronto con il manifesto
    /// direbbe sempre «canale diverso» senza che nessuno capisca perche'.
    #[test]
    fn un_canale_inventato_non_entra() {
        let database = database();
        let Ok(attore) = Actor::try_new("amministratore") else {
            panic!("l'attore di prova deve essere valido");
        };
        assert!(
            database.save_update_channel("interno", &attore, 7).is_err(),
            "un'etichetta che non esiste non deve poter entrare in archivio"
        );
        assert_eq!(database.update_channel().ok().as_deref(), Some("stable"));
    }

    /// **Di fabbrica non c'e' un'origine, e l'assenza e' la verita'.**
    ///
    /// Un indirizzo scritto nel prodotto sarebbe un indirizzo inventato, perche'
    /// non esiste ancora nulla di pubblicato: e un indirizzo inventato e' un
    /// indirizzo che un giorno qualcuno contatta.
    #[test]
    fn una_postazione_nuova_non_ha_un_origine() {
        let database = database();
        assert_eq!(database.update_origin().ok(), Some(None));
    }

    #[test]
    fn l_origine_scelta_si_rilegge_e_si_puo_svuotare() {
        let database = database();
        let Ok(attore) = Actor::try_new("amministratore") else {
            panic!("l'attore di prova deve essere valido");
        };
        let Ok(()) = database.save_update_origin(Some("https://esempio.test/m.json"), &attore, 1)
        else {
            panic!("l'origine deve potersi scrivere");
        };
        assert_eq!(
            database.update_origin().ok().flatten().as_deref(),
            Some("https://esempio.test/m.json")
        );

        let Ok(()) = database.save_update_origin(None, &attore, 2) else {
            panic!("l'origine deve potersi svuotare");
        };
        assert_eq!(database.update_origin().ok(), Some(None));
    }

    /// **Un'origine in chiaro non entra, e non perche' lo controlli il codice.**
    ///
    /// Il vincolo sta nella migrazione. Senza, un'origine scritta a mano in
    /// archivio aggirerebbe il controllo che il codice fa prima di uscire.
    #[test]
    fn un_origine_in_chiaro_non_entra_in_archivio() {
        let database = database();
        let Ok(attore) = Actor::try_new("amministratore") else {
            panic!("l'attore di prova deve essere valido");
        };
        for cattiva in [
            "http://esempio.test/m.json",
            "ftp://esempio.test/m.json",
            "esempio.test/m.json",
        ] {
            assert!(
                database
                    .save_update_origin(Some(cattiva), &attore, 3)
                    .is_err(),
                "«{cattiva}» non deve poter entrare in archivio"
            );
        }
        assert_eq!(database.update_origin().ok(), Some(None));
    }

    /// **La riga dell'origine non si cancella: si svuota.**
    #[test]
    fn la_riga_dell_origine_non_si_cancella() {
        let database = database();
        assert!(
            database
                .connection
                .execute("DELETE FROM update_origin WHERE id = 1", [])
                .is_err(),
            "la riga dell'origine non deve potersi cancellare"
        );
    }

    /// **La riga del canale non si cancella: si cambia.**
    ///
    /// Cancellarla lascerebbe la postazione senza canale, e chi legge dovrebbe
    /// indovinare quale fosse — dove «indovinare» significa «stabile», cioe' il
    /// contrario di cio' che qualcuno aveva scelto.
    #[test]
    fn la_riga_del_canale_non_si_cancella() {
        let database = database();
        assert!(
            database
                .connection
                .execute("DELETE FROM update_channel WHERE id = 1", [])
                .is_err(),
            "la riga del canale non deve potersi cancellare"
        );
    }
}

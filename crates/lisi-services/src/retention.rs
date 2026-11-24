//! Per quanto tempo l'ufficio conserva ciò che ha acquisito.
//!
//! Il servizio è sottile per scelta: la politica è nel dominio
//! (`RetentionPolicy`), la cancellazione e la sua traccia sono nell'archivio, in
//! una sola transazione. Qui si mette in fila lettura, salvataggio, anteprima e
//! applicazione, e si costruisce la voce d'audit.
//!
//! # Perché l'anteprima è un'operazione a sé
//!
//! Una cancellazione che non si può prevedere è una cancellazione che si scopre
//! quando è troppo tardi. Chi cambia la politica deve poter leggere **quanti**
//! contenuti sparirebbero prima che ne sparisca uno.
//!
//! # Che cosa il servizio non toglie mai
//!
//! L'audit, le fotografie dei rapporti, i contenuti citati da un pacchetto già
//! prodotto, e la configurazione — dizionari, fonti, account, credenziali. Il
//! vincolo è nell'archivio, dove sta la query; qui è dichiarato perché chi legge
//! il servizio lo sappia senza cercarlo.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::retention::RetentionPolicy;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;
pub use lisi_storage::repository::integrity::IntegrityReport;
pub use lisi_storage::repository::retention::RetentionPreview;

use crate::error::ServiceResult;

/// Servizio della conservazione.
#[derive(Debug)]
pub struct RetentionService {
    database: Database,
}

impl RetentionService {
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

    /// La politica conservata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn policy(&self) -> ServiceResult<RetentionPolicy> {
        Ok(self.database.retention_policy()?)
    }

    /// Salva la politica scelta e ne lascia traccia.
    ///
    /// **Salvare non cancella nulla.** Sono due gesti distinti proprio perché
    /// chi sceglie «90 giorni» deve poter vedere l'anteprima e cambiare idea
    /// prima che qualcosa sparisca.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura o la registrazione non riescono.
    pub fn save_policy(
        &self,
        policy: RetentionPolicy,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database
            .save_retention_policy(policy, actor, now.as_millis())?;
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("conservazione_impostata")?,
            entity: AuditEntity::try_new("retention")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&descrizione(policy))?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Che cosa la politica indicata toglierebbe, se applicata adesso.
    ///
    /// Non cancella nulla: conta soltanto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn preview(
        &self,
        policy: RetentionPolicy,
        now: Timestamp,
    ) -> ServiceResult<RetentionPreview> {
        Ok(self.database.retention_preview(policy, now.as_millis())?)
    }

    /// Che cosa la politica **conservata** toglierebbe, se applicata adesso.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o il conteggio non riescono.
    pub fn preview_current(&self, now: Timestamp) -> ServiceResult<RetentionPreview> {
        self.preview(self.policy()?, now)
    }

    /// Applica la politica conservata e restituisce ciò che è stato tolto.
    ///
    /// La traccia d'audit entra nella stessa transazione della cancellazione: o
    /// restano entrambe, o non accade nessuna delle due.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura, la cancellazione o la registrazione
    /// non riescono.
    pub fn apply(&mut self, actor: &Actor, now: Timestamp) -> ServiceResult<RetentionPreview> {
        let policy = self.policy()?;
        self.apply_policy(policy, actor, now)
    }

    /// Applica la politica indicata e restituisce ciò che è stato tolto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cancellazione o la registrazione non
    /// riescono.
    pub fn apply_policy(
        &mut self,
        policy: RetentionPolicy,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<RetentionPreview> {
        let audit = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("conservazione_applicata")?,
            entity: AuditEntity::try_new("retention")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&descrizione(policy))?),
            recorded_at: now,
        };
        let tolto = self
            .database
            .apply_retention(policy, now.as_millis(), &audit)?;

        // Cancellare non basta. SQLite segna le pagine come libere e le riusa:
        // il file pesa uguale, e i byte di cio' che e' stato «cancellato»
        // restano leggibili con strumenti forensi finche' qualcosa non li
        // riscrive. `compact()` ricostruisce il file e risolve entrambe le
        // cose.
        //
        // Solo se qualcosa e' stato tolto: ricostruire un archivio intatto
        // costa tempo e spazio senza restituire nulla.
        //
        // Un fallimento NON rende guasta la conservazione: le righe sono
        // sparite davvero. Si annota, perche' un archivio che non si compatta
        // mai e' una cosa che chi legge la diagnostica deve poter scoprire.
        if !tolto.is_empty()
            && let Err(errore) = self.database.compact()
        {
            tracing::warn!(
                errore = %errore,
                "archivio non compattato dopo la conservazione: lo spazio non è stato \
                 restituito e le pagine liberate non sono state riscritte"
            );
        }

        Ok(tolto)
    }
}

impl RetentionService {
    /// Verifica che l'archivio sia ancora sano, e riferisce l'esito.
    ///
    /// # Perche' un errore e' un esito e non un imprevisto
    ///
    /// Il danneggiamento reale — verificato rovinando un file vero — non
    /// arriva come un rapporto con un elenco di problemi: arriva come
    /// **errore** di SQLite, «database disk image is malformed», mentre il file
    /// si e' aperto benissimo.
    ///
    /// Un servizio che lo riferisse come «controllo non riuscito» direbbe
    /// all'operatore di riprovare, quando la cosa da fare e' fermarsi. Percio'
    /// qui l'errore diventa un rapporto danneggiato, e il messaggio e' quello
    /// che dice di non produrre documenti.
    ///
    /// # Errori
    ///
    /// Non ne restituisce: **ogni** esito e' un rapporto. Questa e' la firma
    /// giusta proprio perche' non esiste un caso in cui «non si sa» sia una
    /// risposta utile per chi deve decidere se fidarsi dell'archivio.
    #[must_use]
    pub fn verify_integrity(&self) -> IntegrityReport {
        match self.database.verify_integrity() {
            Ok(rapporto) => rapporto,
            Err(errore) => {
                tracing::warn!(
                    errore = %errore,
                    "verifica dell'archivio non completata: trattata come danneggiamento"
                );
                IntegrityReport {
                    structural: vec![errore.to_string()],
                    broken_links: 0,
                    size_bytes: None,
                }
            }
        }
    }
}

/// La politica come la legge chi rilegge l'audit.
///
/// Chi apre il registro fra due anni deve poter sapere **quale** politica fu
/// scelta, non soltanto che qualcuno ne scelse una.
fn descrizione(policy: RetentionPolicy) -> String {
    match policy.days() {
        None => String::from("si conserva tutto"),
        Some(days) => format!("{days} giorni"),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::retention::{RetentionDays, RetentionPolicy};
    use lisi_core::text::Actor;

    use super::RetentionService;
    use crate::sources::open_in_memory_database;

    fn operator() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn service() -> RetentionService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database di prova deve potersi aprire");
        };
        RetentionService::new(database)
    }

    fn politica(giorni: u32) -> RetentionPolicy {
        let Ok(giorni) = RetentionDays::try_new(giorni) else {
            panic!("i giorni di prova devono essere ammessi");
        };
        RetentionPolicy::Days(giorni)
    }

    #[test]
    fn un_ufficio_nuovo_conserva_tutto() {
        let Ok(policy) = service().policy() else {
            panic!("la politica deve potersi leggere");
        };
        assert_eq!(policy, RetentionPolicy::Unlimited);
    }

    #[test]
    fn salvare_la_politica_non_cancella_nulla() {
        // Sono due gesti distinti proprio perche' chi sceglie «90 giorni» deve
        // poter vedere l'anteprima e cambiare idea prima che qualcosa sparisca.
        let service = service();
        let now = Timestamp::from_millis(1_700_000_000_000);

        service
            .save_policy(politica(90), &operator(), now)
            .expect("la politica deve potersi salvare");

        let Ok(riletta) = service.policy() else {
            panic!("la politica deve potersi rileggere");
        };
        assert_eq!(riletta, politica(90));

        let Ok(anteprima) = service.preview_current(now) else {
            panic!("l'anteprima deve riuscire");
        };
        assert!(
            anteprima.is_empty(),
            "in un archivio vuoto non c'e' nulla da togliere"
        );
    }

    #[test]
    fn la_scelta_lascia_traccia_e_la_traccia_dice_quale() {
        // Chi rilegge l'audit deve poter sapere QUALE politica fu scelta, non
        // soltanto che qualcuno ne scelse una.
        let service = service();
        let now = Timestamp::from_millis(1_700_000_000_000);

        service
            .save_policy(politica(365), &operator(), now)
            .expect("la politica deve potersi salvare");

        let Ok(voci) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == "conservazione_impostata")
        else {
            panic!("la scelta deve lasciare traccia");
        };
        let Some(dettaglio) = voce.detail.as_ref() else {
            panic!("la traccia deve dire quale politica");
        };
        assert!(
            dettaglio.as_str().contains("365"),
            "la traccia non dice quale politica: «{}»",
            dettaglio.as_str()
        );
    }

    #[test]
    fn un_archivio_sano_risulta_sano() {
        assert!(service().verify_integrity().is_healthy());
    }

    /// **Un archivio che non si lascia verificare e' un archivio danneggiato.**
    ///
    /// E' la strada che il danneggiamento reale prende: SQLite risponde con un
    /// errore mentre il file si e' aperto benissimo. Un servizio che lo
    /// riferisse come «controllo non riuscito» direbbe di riprovare, quando la
    /// cosa da fare e' fermarsi.
    #[test]
    fn un_archivio_rovinato_arriva_all_operatore_come_danneggiato() {
        use std::io::{Seek, SeekFrom, Write};

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("archivio.sqlite3");

        {
            let Ok(database) = lisi_storage::Database::open(&percorso) else {
                panic!("l'archivio di prova deve potersi aprire");
            };
            drop(database);
        }
        // Chiudendo l'ultima connessione SQLite assorbe da se' il giornale WAL:
        // il danno colpisce cosi' il file principale e non pagine che
        // verrebbero riscritte comunque.
        {
            let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&percorso) else {
                panic!("il file deve potersi aprire in scrittura");
            };
            let Ok(_) = file.seek(SeekFrom::Start(4_096)) else {
                panic!("il posizionamento deve riuscire");
            };
            let Ok(()) = file.write_all(&vec![0x5A_u8; 3_000]) else {
                panic!("la scrittura del danno deve riuscire");
            };
        }

        let Ok(database) = lisi_storage::Database::open(&percorso) else {
            panic!("il file si apre: e' la verifica che deve accorgersi del danno");
        };
        let rapporto = RetentionService::new(database).verify_integrity();

        assert!(
            !rapporto.is_healthy(),
            "il prodotto ha dichiarato integro un archivio rovinato"
        );
        let messaggio = rapporto.operator_message();
        assert!(
            messaggio.contains("Non produrre documenti"),
            "l'operatore deve sapere la cosa piu' importante da NON fare: «{messaggio}»"
        );
    }

    #[test]
    fn conservare_tutto_si_puo_scegliere_e_si_rilegge() {
        // Tornare indietro deve essere possibile: chi ha scelto una politica
        // severa e si e' pentito non deve restare incastrato.
        let service = service();
        let now = Timestamp::from_millis(1_700_000_000_000);

        service
            .save_policy(politica(30), &operator(), now)
            .expect("la politica deve potersi salvare");
        service
            .save_policy(RetentionPolicy::Unlimited, &operator(), now)
            .expect("si deve poter tornare a «tutto»");

        let Ok(riletta) = service.policy() else {
            panic!("la politica deve potersi rileggere");
        };
        assert_eq!(riletta, RetentionPolicy::Unlimited);
    }

    /// **`VACUUM` solo quando è stato tolto qualcosa** (DEC-206, ADR-0133).
    ///
    /// Trattenere non libera spazio: ricostruire un archivio intatto costa
    /// tempo e spazio senza restituire nulla. La condizione è una sola, nel
    /// servizio, e la guardia la legge lì.
    #[test]
    fn si_compatta_solo_se_qualcosa_e_stato_tolto() {
        const QUESTO_MODULO: &str = include_str!("retention.rs");
        let Some((produzione, _)) = QUESTO_MODULO.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere una parte di produzione");
        };
        let Some((prima, _)) = produzione.split_once("self.database.compact()") else {
            panic!("la compattazione deve esistere");
        };
        let condizione = prima.rsplit("if ").next().unwrap_or_default();
        assert!(
            condizione.trim_start().starts_with("!tolto.is_empty()"),
            "la compattazione non dipende da ciò che è stato tolto: «{condizione}»"
        );
    }
}

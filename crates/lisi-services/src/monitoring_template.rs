//! Creare, applicare e cancellare un modello di monitoraggio (TEMPLATE-01).
//!
//! # UN MODELLO PROPONE, NON APPLICA
//!
//! È la decisione da cui discende tutto, e nasce da un fatto dello schema: la
//! soglia di notifica e la conservazione sono **impostazioni di postazione** —
//! tabelle a riga unica. Non appartengono a una sessione.
//!
//! Un modello che le scrivesse riconfigurerebbe la postazione intera, comprese
//! le sessioni già concluse, con un gesto che sembra «preparare un
//! monitoraggio». E la conservazione **cancella**: abbassarla in silenzio
//! distruggerebbe materiale che qualcuno si aspettava di ritrovare.
//!
//! Perciò [`MonitoringTemplateService::apply`] **non scrive nulla**. Restituisce
//! che cosa il modello prepara e che cosa differisce, e chi guarda decide.
//!
//! Il modo di garantirlo non è ricordarsene: questo servizio **non ha alcun modo
//! di scrivere quelle impostazioni**. Non nomina `save_retention_policy` né
//! `save_notification_settings`, e una guardia lo verifica cercando quelle
//! parole nel sorgente — la stessa forma con cui CTX-06 impedisce che il
//! conservare osservi.
//!
//! # Le versioni dei dizionari si risolvono adesso
//!
//! Un modello nomina un **profilo**, e un profilo nomina i dizionari per
//! identità. La versione si risolve quando il modello si applica, con
//! [`crate::dictionaries::DictionaryService`] — la regola che c'era già, non una
//! seconda.
//!
//! Applicare lo stesso modello due volte può risolvere diversamente, ed è
//! **voluto**: un modello che fissasse le versioni smetterebbe in silenzio di
//! raccogliere le correzioni dei dizionari.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::dictionary::NewDictionaryProfile;
use lisi_core::model::monitoring_template::{
    MonitoringTemplate, NewMonitoringTemplate, Prescribed, PrescribedRetention, SettingComparison,
    compare_notification_level, compare_retention,
};
use lisi_core::model::retention::RetentionPolicy;
use lisi_core::text::{
    Actor, AuditAction, AuditDetail, AuditEntity, DictionaryDescription, DisplayName, Note,
    ProfileName,
};
use lisi_core::{DictionaryId, DictionaryProfileId, MonitoringTemplateId, SourceId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Che cosa una fonte del modello raggiunge, adesso.
///
/// # Perché non è una `Option`
///
/// Perché `None` si legge come «non c'è», e qui il fatto è un altro: **c'era, e
/// non c'è più**. Un elenco che lasciasse sparire la riga direbbe che quella
/// fonte non è mai stata nel modello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSource {
    /// Quale.
    pub id: SourceId,
    /// Come si chiama adesso, oppure niente se non è più nell'archivio.
    pub label: Option<String>,
}

impl ResolvedSource {
    /// Se la fonte è ancora nell'archivio.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.label.is_some()
    }

    /// Che cosa si è trovato, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.label.as_ref() {
            Some(nome) => nome.clone(),
            None => String::from(
                "non \u{e8} pi\u{f9} nell'archivio. Il modello la nominava, e preparando il \
                 monitoraggio non ci sar\u{e0}.",
            ),
        }
    }
}

/// Un dizionario del modello, con ciò che è adesso (OPERATOR-E2E-REMEDIATION-01,
/// F-07).
///
/// # Perché la versione si legge qui, e non si conserva nel modello
///
/// Il modello nomina i dizionari per identità: la versione si risolve quando
/// lo si applica, con la regola che c'era già — l'ultima versione pubblicata
/// (migrazione 0030). Mostrarla qui dice a chi applica **quale** contenuto
/// userà oggi, senza fissarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTemplateDictionary {
    /// Quale.
    pub id: DictionaryId,
    /// Come si chiama adesso, se è ancora nell'archivio.
    pub name: Option<String>,
    /// La versione che oggi si userebbe, se il dizionario è utilizzabile.
    pub version: Option<u32>,
}

impl ResolvedTemplateDictionary {
    /// Se il dizionario si può scegliere per un monitoraggio, adesso.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.version.is_some()
    }

    /// Che cosa si è trovato, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match (self.name.as_ref(), self.version) {
            (Some(nome), Some(versione)) => {
                format!("{nome} — oggi si userebbe la versione {versione}")
            }
            (Some(nome), None) => format!(
                "{nome} — oggi non è utilizzabile: non ha una versione pubblicata, oppure è \
                 archiviato. Preparando il monitoraggio non ci sarà."
            ),
            (None, _) => String::from(
                "un dizionario che non è più nell'archivio. Il modello lo nominava, e \
                 preparando il monitoraggio non ci sarà.",
            ),
        }
    }
}

/// Che cosa chi crea un modello ha scelto (F-07).
///
/// I dizionari si danno per identità; il servizio li raccoglie in un profilo,
/// che è il modo in cui l'archivio li lega a un modello (migrazione 0030).
#[derive(Debug, Clone)]
pub struct TemplateProposal {
    /// Il nome con cui lo si ritrova.
    pub name: DisplayName,
    /// A che cosa serve.
    pub description: Option<Note>,
    /// Le fonti, almeno una.
    pub sources: Vec<SourceId>,
    /// I dizionari, anche nessuno.
    pub dictionaries: Vec<DictionaryId>,
    /// La soglia di notifica che il modello prevede.
    pub notification_level: Prescribed<u8>,
    /// La conservazione che il modello prevede.
    pub retention: PrescribedRetention,
    /// Chi lo crea.
    pub created_by: Actor,
}

/// Che cosa applicare un modello preparerebbe, e che cosa non toccherebbe.
///
/// # Perché i tre pezzi stanno insieme
///
/// Perché mostrarne uno senza gli altri sarebbe una mezza verità. Le fonti e i
/// dizionari **si preparano**; le impostazioni di postazione **no**, e chi
/// guarda deve vedere le due cose nella stessa schermata o crederà che il
/// modello faccia tutto.
#[derive(Debug, Clone)]
pub struct TemplatePreparation {
    /// Il modello applicato.
    pub template: MonitoringTemplate,
    /// Le fonti, con ciò che raggiungono adesso.
    pub sources: Vec<ResolvedSource>,
    /// I dizionari, con la versione che oggi si userebbe.
    pub dictionaries: Vec<ResolvedTemplateDictionary>,
    /// Che cosa il modello prevede per la soglia di notifica, confrontato con
    /// ciò che è in vigore.
    pub notification: SettingComparison,
    /// Che cosa il modello prevede per la conservazione, confrontato con ciò
    /// che è in vigore.
    pub retention: SettingComparison,
}

impl TemplatePreparation {
    /// Le fonti che si possono davvero preparare.
    #[must_use]
    pub fn usable_sources(&self) -> Vec<SourceId> {
        self.sources
            .iter()
            .filter(|fonte| fonte.is_present())
            .map(|fonte| fonte.id)
            .collect()
    }

    /// Quante fonti il modello nominava e non ci sono più.
    #[must_use]
    pub fn missing_sources(&self) -> usize {
        self.sources.iter().filter(|f| !f.is_present()).count()
    }

    /// I dizionari che si possono davvero preparare.
    #[must_use]
    pub fn usable_dictionaries(&self) -> Vec<DictionaryId> {
        self.dictionaries
            .iter()
            .filter(|dizionario| dizionario.is_usable())
            .map(|dizionario| dizionario.id)
            .collect()
    }

    /// Quanti dizionari il modello nominava e oggi non sono utilizzabili.
    #[must_use]
    pub fn unusable_dictionaries(&self) -> usize {
        self.dictionaries.iter().filter(|d| !d.is_usable()).count()
    }

    /// Se qualcuna delle impostazioni di postazione differisce.
    #[must_use]
    pub fn settings_differ(&self) -> bool {
        self.notification.differs() || self.retention.differs()
    }

    /// Se adottare ciò che il modello prevede **cancellerebbe** materiale.
    ///
    /// # Perché una domanda e non un confronto scritto altrove
    ///
    /// Perché è l'unica differenza che, adottata senza leggerla,
    /// **distruggerebbe qualcosa**.
    #[must_use]
    pub fn would_delete(&self) -> bool {
        self.notification.deletes() || self.retention.deletes()
    }
}

/// Servizio dei modelli di monitoraggio.
#[derive(Debug)]
pub struct MonitoringTemplateService {
    database: Database,
}

impl MonitoringTemplateService {
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

    /// Crea un modello.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::TemplateNameTaken`] se un modello con quel
    /// nome esiste già.
    pub fn create(
        &mut self,
        template: &NewMonitoringTemplate,
        now: Timestamp,
    ) -> ServiceResult<MonitoringTemplateId> {
        let id = self
            .database
            .insert_monitoring_template(template, now)
            .map_err(|errore| Self::nome_gia_preso(errore, template))?;

        self.database.append_audit(&NewAuditEntry {
            actor: template.created_by().clone(),
            action: AuditAction::try_new("modello_creato")?,
            entity: AuditEntity::try_new("monitoring_template")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(template.name().as_str())?),
            recorded_at: now,
        })?;

        Ok(id)
    }

    /// Traduce il rifiuto del nome duplicato.
    fn nome_gia_preso(
        errore: lisi_storage::StorageError,
        template: &NewMonitoringTemplate,
    ) -> ServiceError {
        if matches!(errore, lisi_storage::StorageError::Sqlite(_)) {
            return ServiceError::TemplateNameTaken {
                name: template.name().as_str().to_owned(),
            };
        }
        ServiceError::Storage(errore)
    }

    /// Crea un modello dalle scelte di una persona, dizionari compresi
    /// (OPERATOR-E2E-REMEDIATION-01, F-07).
    ///
    /// # Perché passa da un profilo
    ///
    /// Perché è così che l'archivio lega dei dizionari a un modello: per
    /// identità, attraverso un profilo (migrazione 0030). Il profilo nasce qui,
    /// con un nome di servizio che nessuno vede, e se ne va con il modello.
    /// Non c'è un secondo modo di legare dizionari a un modello da tenere
    /// allineato al primo.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::TemplateNameTaken`] se il nome è già usato,
    /// un errore di dominio se mancano le fonti o la soglia è fuori scala, e un
    /// errore se un dizionario non esiste o la scrittura non riesce. Se il
    /// modello non si crea, il profilo appena creato si toglie.
    pub fn create_from(
        &mut self,
        proposal: &TemplateProposal,
        now: Timestamp,
    ) -> ServiceResult<MonitoringTemplateId> {
        // Il dominio si controlla PRIMA di scrivere il profilo: fonti assenti o
        // soglia fuori scala non devono lasciare un profilo orfano.
        NewMonitoringTemplate::of(
            proposal.name.clone(),
            proposal.description.clone(),
            proposal.sources.clone(),
            None,
            proposal.notification_level,
            proposal.retention,
            proposal.created_by.clone(),
        )?;

        let profilo = if proposal.dictionaries.is_empty() {
            None
        } else {
            Some(self.create_profile(proposal, now)?)
        };

        let modello = NewMonitoringTemplate::of(
            proposal.name.clone(),
            proposal.description.clone(),
            proposal.sources.clone(),
            profilo,
            proposal.notification_level,
            proposal.retention,
            proposal.created_by.clone(),
        )?;

        match self.create(&modello, now) {
            Ok(id) => Ok(id),
            Err(errore) => {
                if let Some(profilo) = profilo
                    && let Err(pulizia) = self.database.delete_dictionary_profile(profilo)
                {
                    tracing::warn!(
                        errore = %pulizia,
                        "profilo dei dizionari di un modello non creato rimasto nell'archivio"
                    );
                }
                Err(errore)
            }
        }
    }

    /// Il profilo dei dizionari di un modello che sta per nascere.
    ///
    /// Il nome porta l'istante: due modelli dello stesso autore non si
    /// contendono il nome del profilo, nemmeno se uno è stato cancellato e
    /// ricreato con lo stesso nome.
    fn create_profile(
        &mut self,
        proposal: &TemplateProposal,
        now: Timestamp,
    ) -> ServiceResult<DictionaryProfileId> {
        let nome = ProfileName::try_new(&format!("Modello {}", now.as_millis()))?;
        let titolo: String = proposal.name.as_str().chars().take(200).collect();
        let descrizione =
            DictionaryDescription::try_new(&format!("Dizionari del modello «{titolo}»"))?;
        Ok(self.database.insert_dictionary_profile(
            &NewDictionaryProfile {
                name: nome,
                description: descrizione,
                dictionary_ids: proposal.dictionaries.clone(),
                created_by: proposal.created_by.clone(),
                shared: false,
            },
            now,
        )?)
    }

    /// I modelli, in ordine di nome.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn all(&self) -> ServiceResult<Vec<MonitoringTemplate>> {
        Ok(self.database.monitoring_templates()?)
    }

    /// Cancella un modello.
    ///
    /// # Che cosa NON tocca
    ///
    /// Le sessioni che quel modello ha preparato: le loro fonti e i loro
    /// dizionari stanno sulla sessione, e restano.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se non c'era.
    pub fn delete(
        &self,
        id: MonitoringTemplateId,
        removed_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let profilo = self.database.monitoring_template(id)?.dictionary_profile;
        self.database.delete_monitoring_template(id)?;

        self.database.append_audit(&NewAuditEntry {
            actor: removed_by.clone(),
            action: AuditAction::try_new("modello_cancellato")?,
            entity: AuditEntity::try_new("monitoring_template")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;

        // IL PROFILO DEI DIZIONARI SE NE VA CON IL MODELLO (F-07), se nessun
        // altro modello lo usa. Le sessioni non lo nominano: conservano la
        // propria fotografia dei termini, e non perdono nulla.
        if let Some(profilo) = profilo {
            let usato = self
                .database
                .monitoring_templates()?
                .iter()
                .any(|altro| altro.dictionary_profile == Some(profilo));
            if !usato && let Err(errore) = self.database.delete_dictionary_profile(profilo) {
                tracing::warn!(
                    errore = %errore,
                    "profilo dei dizionari di un modello cancellato rimasto nell'archivio"
                );
            }
        }

        Ok(())
    }

    /// Che cosa applicare un modello preparerebbe.
    ///
    /// # QUESTA FUNZIONE NON SCRIVE NULLA
    ///
    /// Non prepara la sessione e non cambia le impostazioni: **dice** che cosa
    /// il modello prevede, che cosa delle sue fonti è ancora raggiungibile, e in
    /// che cosa le impostazioni di postazione differiscono.
    ///
    /// Chi guarda decide. Le impostazioni di postazione si cambiano dove si
    /// cambiano, e questo servizio **non ha modo** di toccarle.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il modello non esiste o se la lettura non
    /// riesce.
    pub fn apply(&self, id: MonitoringTemplateId) -> ServiceResult<TemplatePreparation> {
        let template = self.database.monitoring_template(id)?;

        // LE FONTI CHE NON CI SONO PIU' NON SI FILTRANO VIA.
        //
        // Un elenco che le nascondesse direbbe che il modello non le ha mai
        // nominate, e chi lo rilegge non avrebbe modo di accorgersene.
        let mut sources = Vec::with_capacity(template.sources.len());
        for source_id in &template.sources {
            let label = self
                .database
                .source(*source_id)
                .ok()
                .map(|fonte| fonte.display_name.as_str().to_owned());
            sources.push(ResolvedSource {
                id: *source_id,
                label,
            });
        }

        // I DIZIONARI SI RISOLVONO ADESSO (F-07): l'ultima versione pubblicata,
        // la regola che c'era già. Un dizionario che non è più utilizzabile
        // resta nell'elenco e lo dice, come una fonte che non c'è più.
        let mut dictionaries = Vec::new();
        if let Some(profilo) = template.dictionary_profile {
            for dictionary_id in self.database.dictionary_profile(profilo)?.dictionary_ids {
                let dizionario = self.database.dictionary(dictionary_id).ok();
                let versione = match dizionario.as_ref() {
                    Some(d) if d.is_selectable() => self
                        .database
                        .latest_published_version(dictionary_id)?
                        .map(|v| v.number),
                    _ => None,
                };
                dictionaries.push(ResolvedTemplateDictionary {
                    id: dictionary_id,
                    name: dizionario.map(|d| d.name.as_str().to_owned()),
                    version: versione,
                });
            }
        }

        let impostazioni = self.database.notification_settings()?;
        let conservazione = self.database.retention_policy()?;
        let giorni = match conservazione {
            RetentionPolicy::Unlimited => None,
            RetentionPolicy::Days(giorni) => Some(giorni.get()),
        };

        Ok(TemplatePreparation {
            notification: compare_notification_level(
                template.notification_level,
                impostazioni.minimum_level,
            ),
            retention: compare_retention(template.retention, giorni),
            template,
            sources,
            dictionaries,
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::monitoring_template::{
        NewMonitoringTemplate, Prescribed, PrescribedRetention,
    };
    use lisi_core::text::{Actor, DisplayName};
    use lisi_core::{MonitoringTemplateId, SourceId, Timestamp};

    use super::MonitoringTemplateService;
    use crate::error::ServiceError;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("monitoring_template.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn servizio() -> MonitoringTemplateService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        MonitoringTemplateService::new(database)
    }

    fn modello(
        etichetta: &str,
        soglia: Prescribed<u8>,
        conservazione: PrescribedRetention,
    ) -> NewMonitoringTemplate {
        let Ok(nome) = DisplayName::try_new(etichetta) else {
            panic!("il nome di prova deve essere valido");
        };
        let Ok(modello) = NewMonitoringTemplate::of(
            nome,
            None,
            vec![SourceId::new(1)],
            None,
            soglia,
            conservazione,
            attore(),
        ) else {
            panic!("il modello di prova deve essere valido");
        };
        modello
    }

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Applicare un modello non ha modo di cambiare le impostazioni.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il solo che questa milestone esisteva per impedire. La soglia di
    /// notifica e la conservazione sono **della postazione**: un gesto che
    /// sembra «preparare un monitoraggio» le cambierebbe anche per i
    /// monitoraggi già conclusi, e la conservazione, abbassata, **cancella**.
    ///
    /// # Perché la guardia guarda il sorgente
    ///
    /// Perché la garanzia è **l'assenza di una capacità**, e l'assenza si
    /// sorveglia cercandola. È la stessa forma con cui CTX-06 impedisce che il
    /// conservare osservi.
    #[test]
    fn applicare_non_ha_modo_di_cambiare_le_impostazioni() {
        let codice = codice_senza_commenti();
        for scrittura in [
            "save_retention_policy",
            "save_notification_settings",
            "set_retention",
            "update_settings",
        ] {
            assert!(
                !codice.contains(scrittura),
                "il servizio nomina «{scrittura}»: applicare un modello riconfigurerebbe la \
                 postazione con un gesto che sembra preparare un monitoraggio"
            );
        }

        // E LA FUNZIONE CHE APPLICA NON PRENDE L'ARCHIVIO MUTABILE.
        //
        // Non e' una convenzione: senza `&mut` non puo' scrivere, e il
        // compilatore lo impone.
        assert!(
            codice.contains("pub fn apply(&self, id: MonitoringTemplateId)"),
            "applicare legge soltanto: senza `&mut` non puo' scrivere"
        );
    }

    /// **Si crea, si rilegge, si cancella.**
    #[test]
    fn si_crea_si_rilegge_e_si_cancella() {
        let mut servizio = servizio();
        let Ok(id) = servizio.create(
            &modello("Marzo", Prescribed::Silent, PrescribedRetention::Silent),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };

        let Ok(elenco) = servizio.all() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenco.len(), 1);

        let Ok(()) = servizio.delete(id, &attore(), istante(ORA + 100)) else {
            panic!("la cancellazione deve riuscire");
        };
        let Ok(dopo) = servizio.all() else {
            panic!("la lettura deve riuscire");
        };
        assert!(dopo.is_empty());
    }

    /// **Due modelli omonimi producono una frase che nomina.**
    #[test]
    fn due_modelli_omonimi_producono_una_frase_che_nomina() {
        let mut servizio = servizio();
        let Ok(_) = servizio.create(
            &modello("Marzo", Prescribed::Silent, PrescribedRetention::Silent),
            istante(ORA),
        ) else {
            panic!("il primo deve potersi creare");
        };

        let esito = servizio.create(
            &modello("Marzo", Prescribed::Silent, PrescribedRetention::Silent),
            istante(ORA + 1),
        );
        let Err(ServiceError::TemplateNameTaken { name }) = esito else {
            panic!("il secondo deve essere rifiutato");
        };
        assert_eq!(name, "Marzo");
    }

    /// **Una fonte che non c'è più si dichiara, e non si filtra via.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un modello che, applicato, prepara silenziosamente meno fonti di quelle
    /// che nominava. Chi lo usa crede di guardare ciò che guardava, e non se ne
    /// accorge.
    #[test]
    fn una_fonte_che_non_c_e_piu_si_dichiara() {
        let mut servizio = servizio();
        let Ok(id) = servizio.create(
            &modello("Marzo", Prescribed::Silent, PrescribedRetention::Silent),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };

        let Ok(preparazione) = servizio.apply(id) else {
            panic!("l'applicazione deve riuscire");
        };
        // La fonte 1 non esiste in questo archivio vuoto: la riga resta e lo
        // dichiara.
        assert_eq!(preparazione.sources.len(), 1);
        assert!(!preparazione.sources[0].is_present());
        assert_eq!(preparazione.missing_sources(), 1);
        assert!(preparazione.usable_sources().is_empty());
        assert!(
            preparazione.sources[0]
                .as_sentence()
                .contains("non \u{e8} pi\u{f9} nell'archivio")
        );
    }

    /// **Il confronto delle impostazioni arriva insieme alla preparazione.**
    ///
    /// # Perché conta
    ///
    /// Perché mostrare le fonti senza il confronto sarebbe una mezza verità:
    /// chi guarda crederebbe che il modello faccia tutto.
    #[test]
    fn il_confronto_arriva_insieme_alla_preparazione() {
        let mut servizio = servizio();
        let Ok(id) = servizio.create(
            &modello(
                "Marzo",
                Prescribed::Value(4),
                PrescribedRetention::KeepDays(7),
            ),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };

        let Ok(preparazione) = servizio.apply(id) else {
            panic!("l'applicazione deve riuscire");
        };
        assert!(
            preparazione.settings_differ(),
            "il modello prevede valori diversi da quelli di una postazione nuova"
        );
        // Da «conserva tutto» — il predefinito — a sette giorni: cancella.
        assert!(
            preparazione.would_delete(),
            "adottare sette giorni su una conservazione illimitata cancellerebbe"
        );
    }

    /// **Ogni atto lascia traccia nell'audit, e applicare non è un atto.**
    ///
    /// # Perché applicare non compare
    ///
    /// Perché non fa niente: legge, confronta e risponde. Registrarlo
    /// nell'audit direbbe che qualcosa è avvenuto, e l'audit di questo prodotto
    /// documenta **atti**.
    #[test]
    fn ogni_atto_lascia_traccia_e_applicare_non_e_un_atto() {
        let mut servizio = servizio();
        let Ok(id) = servizio.create(
            &modello("Marzo", Prescribed::Silent, PrescribedRetention::Silent),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };
        let Ok(_) = servizio.apply(id) else {
            panic!("l'applicazione deve riuscire");
        };
        let Ok(()) = servizio.delete(id, &attore(), istante(ORA + 100)) else {
            panic!("la cancellazione deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for azione in ["modello_creato", "modello_cancellato"] {
            assert!(
                voci.iter().any(|voce| voce.action.as_str() == azione),
                "l'azione «{azione}» deve comparire nell'audit"
            );
        }
        assert!(
            !voci
                .iter()
                .any(|voce| voce.action.as_str() == "modello_applicato"),
            "applicare non fa niente: registrarlo direbbe che qualcosa e' avvenuto"
        );
    }

    /// **Applicare un modello che non c'è lo dichiara.**
    #[test]
    fn applicare_un_modello_che_non_c_e_lo_dichiara() {
        let servizio = servizio();
        assert!(servizio.apply(MonitoringTemplateId::new(999)).is_err());
    }

    /// **Il servizio non tiene copie.**
    #[test]
    fn il_servizio_non_tiene_copie() {
        let codice = codice_senza_commenti();
        const INTESTAZIONE: &str = "pub struct MonitoringTemplateService {";
        let Some(inizio) = codice.find(INTESTAZIONE) else {
            panic!("il servizio deve esistere");
        };
        let campi = &codice[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        let dichiarati: Vec<&str> = campi[..fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.contains(':'))
            .collect();
        assert_eq!(
            dichiarati.len(),
            1,
            "il servizio ha un campo solo, l'archivio \u{2014} {dichiarati:?}"
        );
    }

    // ------------------------------------- creazione dall'interfaccia (F-07)

    /// Un archivio con un dizionario pubblicato, e il suo identificativo.
    fn archivio_con_un_dizionario() -> (lisi_storage::Database, lisi_core::DictionaryId) {
        use lisi_core::model::dictionary::{
            DictionaryScope, DictionaryVisibility, MatchMode, NewDictionaryTerm, SuggestedLevel,
        };
        use lisi_core::text::{
            DictionaryDescription, DictionaryName, LanguageTag, TermCategory, TermNote, TermText,
        };
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut dizionari = crate::dictionaries::DictionaryService::new(database);
        let (Ok(nome), Ok(descrizione)) = (
            DictionaryName::try_new("Incendi"),
            DictionaryDescription::try_new("prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok((id, versione)) = dizionari.create(
            &crate::dictionaries::DictionaryProposal {
                name: nome,
                description: descrizione,
                scope: DictionaryScope::Thematic,
                visibility: DictionaryVisibility::Personal,
            },
            &attore(),
            istante(ORA),
        ) else {
            panic!("il dizionario deve potersi creare");
        };
        let (Ok(text), Ok(category), Ok(language), Ok(suggested_level), Ok(note)) = (
            TermText::try_new("incendio"),
            TermCategory::try_new("azione"),
            LanguageTag::try_new("it"),
            SuggestedLevel::try_new(3),
            TermNote::try_new(""),
        ) else {
            panic!("il termine di prova deve essere valido");
        };
        let termine = NewDictionaryTerm {
            version_id: versione,
            text,
            category,
            language,
            match_mode: MatchMode::NormalizedWord,
            suggested_level,
            note,
        };
        let Ok(_) = dizionari.add_terms(versione, &[termine], &attore(), istante(ORA)) else {
            panic!("il termine deve potersi aggiungere");
        };
        let Ok(()) = dizionari.publish(versione, &attore(), istante(ORA)) else {
            panic!("la versione deve potersi pubblicare");
        };
        (dizionari.into_database(), id)
    }

    fn proposta(nome: &str, dizionari: Vec<lisi_core::DictionaryId>) -> super::TemplateProposal {
        let Ok(name) = DisplayName::try_new(nome) else {
            panic!("il nome di prova deve essere valido");
        };
        super::TemplateProposal {
            name,
            description: None,
            sources: vec![SourceId::new(1)],
            dictionaries: dizionari,
            notification_level: Prescribed::Value(2),
            retention: PrescribedRetention::Silent,
            created_by: attore(),
        }
    }

    /// **Un modello si crea con i suoi dizionari, e applicandolo si legge la
    /// versione che oggi si userebbe.**
    #[test]
    fn un_modello_si_crea_con_i_dizionari_e_li_risolve_quando_si_applica() {
        let (database, dizionario) = archivio_con_un_dizionario();
        let mut servizio = MonitoringTemplateService::new(database);
        let Ok(id) = servizio.create_from(&proposta("Marzo", vec![dizionario]), istante(ORA + 1))
        else {
            panic!("il modello deve potersi creare");
        };
        let Ok(preparazione) = servizio.apply(id) else {
            panic!("applicare deve riuscire");
        };
        assert_eq!(preparazione.dictionaries.len(), 1);
        assert!(preparazione.dictionaries[0].is_usable());
        assert_eq!(preparazione.dictionaries[0].version, Some(1));
        assert_eq!(preparazione.usable_dictionaries(), vec![dizionario]);
        assert!(
            preparazione.dictionaries[0]
                .as_sentence()
                .contains("oggi si userebbe la versione 1")
        );
    }

    /// **Un nome già usato non lascia un profilo orfano.**
    #[test]
    fn un_nome_gia_usato_non_lascia_un_profilo_orfano() {
        let (database, dizionario) = archivio_con_un_dizionario();
        let mut servizio = MonitoringTemplateService::new(database);
        let Ok(_) = servizio.create_from(&proposta("Marzo", vec![dizionario]), istante(ORA + 1))
        else {
            panic!("il primo deve potersi creare");
        };
        let esito = servizio.create_from(&proposta("Marzo", vec![dizionario]), istante(ORA + 2));
        assert!(
            matches!(esito, Err(ServiceError::TemplateNameTaken { .. })),
            "{esito:?}"
        );
        let Ok(profili) = servizio.database().dictionary_profiles_for(&attore()) else {
            panic!("i profili devono leggersi");
        };
        assert_eq!(profili.len(), 1, "il secondo profilo non deve restare");
    }

    /// **Senza fonti il modello non si crea, e non si scrive nulla.**
    #[test]
    fn senza_fonti_non_si_scrive_nulla() {
        let (database, dizionario) = archivio_con_un_dizionario();
        let mut servizio = MonitoringTemplateService::new(database);
        let mut senza = proposta("Vuoto", vec![dizionario]);
        senza.sources.clear();
        assert!(servizio.create_from(&senza, istante(ORA + 1)).is_err());
        let Ok(profili) = servizio.database().dictionary_profiles_for(&attore()) else {
            panic!("i profili devono leggersi");
        };
        assert!(
            profili.is_empty(),
            "nessun profilo per un modello che non nasce"
        );
        let Ok(modelli) = servizio.all() else {
            panic!("i modelli devono leggersi");
        };
        assert!(modelli.is_empty());
    }

    /// **Cancellato il modello, il suo profilo se ne va**, e lo stesso nome si
    /// può riusare.
    #[test]
    fn cancellato_il_modello_il_profilo_se_ne_va() {
        let (database, dizionario) = archivio_con_un_dizionario();
        let mut servizio = MonitoringTemplateService::new(database);
        let Ok(id) = servizio.create_from(&proposta("Marzo", vec![dizionario]), istante(ORA + 1))
        else {
            panic!("il modello deve potersi creare");
        };
        let Ok(()) = servizio.delete(id, &attore(), istante(ORA + 2)) else {
            panic!("la cancellazione deve riuscire");
        };
        let Ok(profili) = servizio.database().dictionary_profiles_for(&attore()) else {
            panic!("i profili devono leggersi");
        };
        assert!(profili.is_empty());
        assert!(
            servizio
                .create_from(&proposta("Marzo", vec![dizionario]), istante(ORA + 3))
                .is_ok()
        );
    }

    /// **Un modello senza dizionari si crea, e non prepara dizionari.**
    #[test]
    fn un_modello_senza_dizionari_si_crea() {
        let mut servizio = servizio();
        let Ok(id) = servizio.create_from(&proposta("Solo fonti", Vec::new()), istante(ORA)) else {
            panic!("il modello deve potersi creare");
        };
        let Ok(preparazione) = servizio.apply(id) else {
            panic!("applicare deve riuscire");
        };
        assert!(preparazione.dictionaries.is_empty());
        assert!(preparazione.template.dictionary_profile.is_none());
    }
}

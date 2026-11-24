//! La cronologia di chi è stato osservato (PERS-04).
//!
//! # Serve la stessa ragione degli elenchi di persone
//!
//! Una cronologia **è** un elenco di persone guardato nel tempo: dice che una
//! certa persona ha scritto certe cose in certi momenti. Chi la tira fuori
//! risponde di averlo fatto.
//!
//! Vale la ragione di ADR-0024, e **la stessa**, per il motivo già scritto in
//! PERS-02 e PERS-03: registrarne una specifica farebbe credere che esistano più
//! autorizzazioni dove ce n'è una.
//!
//! # Le finestre si leggono dai monitoraggi, non dai contenuti
//!
//! È la decisione che rende questa milestone utile invece che pericolosa.
//!
//! Un monitoraggio che **non ha raccolto niente ha comunque guardato**. Dedurre
//! il periodo di osservazione dai contenuti perderebbe esattamente quel caso —
//! cioè il caso in cui un vuoto nella cronologia va spiegato, ed è l'unico in cui
//! la spiegazione serve davvero.
//!
//! Perciò le finestre arrivano dalla tabella dei monitoraggi, con il loro istante
//! di avvio e di conclusione, e un monitoraggio senza conclusione **non diventa
//! «fino a oggi»**.
//!
//! # Che cosa non costruisce
//!
//! Una tabella. La cronologia si **ricava** da fatti che l'archivio ha già e che
//! non cambiano. **PERS-04 non ha una migrazione.**
//!
//! E non collega niente a un fascicolo: quello è PERS-06, manuale.

use lisi_core::model::person_timeline::{
    ObservationWindow, PersonTimeline, TimelineFact, timelines_for,
};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Servizio della cronologia osservata.
#[derive(Debug)]
pub struct PersonTimelineService {
    database: Database,
}

impl PersonTimelineService {
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

    /// Le cronologie osservate durante una sessione, con le loro finestre.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::MissingParticipantBasis`] se nessuna ragione è
    /// stata registrata: una cronologia **non si produce** prima, per la stessa
    /// ragione per cui non si produce un elenco di persone.
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn for_session(
        &self,
        session_id: lisi_core::SessionId,
    ) -> ServiceResult<Vec<PersonTimeline>> {
        // LA RAGIONE E' QUELLA DEGLI ELENCHI DI PERSONE, non una seconda.
        if !self.basis_recorded()? {
            return Err(ServiceError::MissingParticipantBasis);
        }

        let finestre = self.windows_for(session_id)?;
        let contents = self.database.session_contents(session_id)?;

        let mut fatti: Vec<TimelineFact> = Vec::new();
        for content in &contents {
            // I MESSAGGI DI CANALE NON HANNO UN AUTORE INDIVIDUALE.
            //
            // Attribuirli a qualcuno significherebbe mettere sulla cronologia di
            // una persona un atto che quella persona non ha compiuto.
            let Some(identifier) = content.author_identifier.clone() else {
                continue;
            };

            // SI RACCOLGONO I FATTI, NON IL CONTENUTO: alla composizione non
            // serve il testo del messaggio.
            let alert = self.database.content_alert(content.id)?.map(|a| a.id);

            fatti.push(TimelineFact {
                content: content.id,
                identifier,
                source: content.source_id,
                at: content.published_at,
                alert,
                display_name: content.author.as_ref().map(|a| a.as_str().to_owned()),
                username: content.author_username.clone(),
            });
        }

        Ok(timelines_for(&fatti, &finestre))
    }

    /// Le finestre in cui si stava guardando, per una sessione.
    ///
    /// # Perché legge la sessione e non i contenuti
    ///
    /// Perché un monitoraggio che non ha raccolto niente **ha comunque
    /// guardato**, e una finestra dedotta dai contenuti perderebbe proprio il
    /// caso in cui un vuoto va spiegato.
    ///
    /// # Perché un monitoraggio mai avviato non produce una finestra
    ///
    /// Perché non ha guardato. Una finestra che partisse dalla **creazione**
    /// dichiarerebbe un'osservazione che non c'è stata: è la confusione fra «non
    /// aver potuto verificare» e «aver verificato» che ADR-0053 vieta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn windows_for(
        &self,
        session_id: lisi_core::SessionId,
    ) -> ServiceResult<Vec<ObservationWindow>> {
        let sessione = self.database.session(session_id)?;

        // MAI AVVIATA: nessuna finestra, perche' non si e' guardato.
        let Some(from) = sessione.started_at else {
            return Ok(Vec::new());
        };

        Ok(vec![ObservationWindow {
            session: sessione.id,
            from,
            // NON CONCLUSA RESTA NON CONCLUSA.
            //
            // Sostituirla con «adesso» dichiarerebbe una copertura che nessuno
            // ha verificato.
            to: sessione.ended_at,
        }])
    }

    /// Se una ragione è già stata registrata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'audit non è leggibile.
    pub fn basis_recorded(&self) -> ServiceResult<bool> {
        Ok(self.database.operational_basis_recorded()?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::person_timeline::TimelineEvent;
    use lisi_core::model::{
        AcquisitionOrigin, AnalysisLevel, NewAuditEntry, NewContent, NewSession, NewSource,
        SessionDuration, SourceKind,
    };
    use lisi_core::text::{
        Actor, AuditAction, AuditDetail, AuditEntity, ContentBody, DisplayName, RemoteMessageId,
        SourceIdentifier,
    };
    use lisi_core::{SessionId, Timestamp};
    use lisi_storage::Database;

    use super::PersonTimelineService;
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    const ORA: i64 = 1_760_000_000_000;

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore deve essere valido");
        };
        attore
    }

    /// Un servizio con una sessione **avviata** e un contenuto scritto.
    fn servizio() -> (PersonTimelineService, SessionId) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut database: Database = database;
        let ora = Timestamp::from_millis(ORA);

        let (Ok(identificativo), Ok(titolo), Ok(etichetta)) = (
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: titolo,
                authorized_by: operatore(),
                active: true,
            },
            ora,
        ) else {
            panic!("la fonte deve potersi registrare");
        };

        let Ok(session_id) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            ora,
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let (Ok(remoto), Ok(corpo), Ok(livello)) = (
            RemoteMessageId::try_new("900"),
            ContentBody::try_new("un testo qualunque"),
            AnalysisLevel::try_new(1),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };

        let Ok(_) = database.insert_content(&NewContent {
            session_id,
            source_id,
            remote_message_id: remoto,
            author: None,
            author_identifier: Some("111".to_owned()),
            author_username: None,
            body: corpo,
            url: None,
            published_at: ora,
            acquired_at: ora,
            origin: AcquisitionOrigin::Observed,
            analysis_level: livello,
        }) else {
            panic!("il contenuto deve potersi registrare");
        };

        (PersonTimelineService::new(database), session_id)
    }

    fn registra_la_ragione(servizio: &PersonTimelineService) {
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new("elenco_persone_motivato"),
            AuditEntity::try_new("session"),
            AuditDetail::try_new("verifica autorizzata di una fonte d'ufficio"),
        ) else {
            panic!("i valori dell'audit devono essere validi");
        };
        let Ok(_) = servizio.database().append_audit(&NewAuditEntry {
            actor: operatore(),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: Timestamp::from_millis(ORA),
        }) else {
            panic!("la ragione deve potersi registrare");
        };
    }

    /// **Una cronologia non si produce senza una ragione registrata.**
    #[test]
    fn una_cronologia_non_si_produce_senza_una_ragione() {
        let (servizio, session_id) = servizio();

        let esito = servizio.for_session(session_id);
        assert!(
            matches!(esito, Err(ServiceError::MissingParticipantBasis)),
            "senza ragione registrata non si produce nulla"
        );

        registra_la_ragione(&servizio);
        assert!(
            servizio.for_session(session_id).is_ok(),
            "con la ragione registrata deve riuscire"
        );
    }

    /// **Un monitoraggio mai avviato non produce una finestra.**
    ///
    /// # Perché conta
    ///
    /// Perché non ha guardato. Una finestra che partisse dalla **creazione**
    /// dichiarerebbe un'osservazione che non c'è stata — la confusione fra «non
    /// aver potuto verificare» e «aver verificato» che ADR-0053 vieta.
    #[test]
    fn un_monitoraggio_mai_avviato_non_produce_una_finestra() {
        let (servizio, session_id) = servizio();
        registra_la_ragione(&servizio);

        // La sessione di prova e' stata creata ma mai avviata.
        let Ok(finestre) = servizio.windows_for(session_id) else {
            panic!("la lettura deve riuscire");
        };
        assert!(
            finestre.is_empty(),
            "creata non e' avviata: non si e' guardato"
        );

        // E la cronologia lo DICHIARA, invece di sembrare vuota.
        let Ok(cronologie) = servizio.for_session(session_id) else {
            panic!("deve riuscire");
        };
        assert!(!cronologie.is_empty(), "la persona c'e'");
        let frase = cronologie[0].caveat();
        assert!(
            frase.contains("non dice nulla"),
            "senza finestre la cronologia lo dichiara: {frase}"
        );
    }

    /// **Il servizio non collega una cronologia a un soggetto, e non scrive.**
    #[test]
    fn il_servizio_non_collega_a_un_soggetto_e_non_scrive() {
        let codice = codice_senza_commenti();
        // IDENTIFICATORI VERI, NON FRAMMENTI.
        //
        // «model::person» senza i due punti finali sarebbe rosso su
        // `model::person_timeline`, che e' QUESTO modulo: una guardia rossa
        // sulla cosa sbagliata viene tolta al primo fastidio, ed e' il modo in
        // cui una guardia vera smette di esistere.
        for collegamento in ["PersonId", "PersonService", "NewPerson", "model::person::"] {
            assert!(
                !codice.contains(collegamento),
                "il servizio nomina «{collegamento}»: il collegamento a un fascicolo e' PERS-06"
            );
        }
        for scrittura in ["insert_", "update_", "delete_", "append_audit", "&mut self"] {
            assert!(
                !codice.contains(scrittura),
                "il servizio nomina «{scrittura}»: comporre una cronologia e' una lettura"
            );
        }
    }

    /// **È la stessa ragione degli elenchi di persone, non una seconda.**
    #[test]
    fn e_la_stessa_ragione_degli_elenchi_di_persone() {
        let codice = codice_senza_commenti();
        // LA DOMANDA SI PONE ATTRAVERSO L'UNICA DEFINIZIONE.
        //
        // Prima di HARDEN-04 questa guardia verificava che il modulo
        // NOMINASSE la voce d'audit condivisa: era giusto finche' ciascuno
        // se la scriveva, e i moduli che lo facevano erano sei.
        //
        // Ora la voce ha un nome solo, e chiederla significa chiamare
        // `operational_basis_recorded`. La guardia e' stata VISTA ROSSA e
        // ristretta: verificare la chiamata e' piu' forte che verificare la
        // stringa, perche' chi chiama non puo' nominare una voce diversa
        // nemmeno per distrazione (ADR-0113).
        assert!(
            codice.contains("operational_basis_recorded"),
            "la domanda deve passare per l'unica definizione"
        );
        for seconda in ["cronologia_motivata", "elenco_cronologie_motivato"] {
            assert!(
                !codice.contains(seconda),
                "«{seconda}» sarebbe una seconda autorizzazione dove ce n'e' una"
            );
        }
    }

    /// **Un monitoraggio non concluso non diventa «adesso».**
    #[test]
    fn un_monitoraggio_non_concluso_non_diventa_adesso() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("to: sessione.ended_at"),
            "la conclusione si legge dall'archivio, com'e'"
        );
        for sostituzione in ["Timestamp::now", "unwrap_or_else", "unwrap_or("] {
            assert!(
                !codice.contains(sostituzione),
                "«{sostituzione}»: sostituire una conclusione assente dichiarerebbe una copertura \
                 che nessuno ha verificato"
            );
        }
    }

    /// **La cronologia composta porta il contenuto scritto e l'alert come sua
    /// proprietà.**
    #[test]
    fn la_cronologia_composta_porta_i_fatti() {
        let (servizio, session_id) = servizio();
        registra_la_ragione(&servizio);

        let Ok(cronologie) = servizio.for_session(session_id) else {
            panic!("deve riuscire");
        };
        assert_eq!(cronologie.len(), 1, "una persona ha scritto");
        assert_eq!(cronologie[0].identifier(), "111");

        let righe = cronologie[0].entries();
        assert_eq!(righe.len(), 1, "un contenuto, una riga");
        assert!(
            matches!(righe[0].event, TimelineEvent::WroteContent { .. }),
            "la riga e' il contenuto scritto"
        );
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("person_timeline.rs");
        let Some(taglio) = sorgente.find("#[cfg(test)]") else {
            panic!("il modulo deve avere una sezione di prove");
        };
        sorgente[..taglio]
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

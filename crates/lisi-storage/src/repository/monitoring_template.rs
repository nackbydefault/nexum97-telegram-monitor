//! Modelli di monitoraggio riusabili (TEMPLATE-01).
//!
//! # Che cosa questo modulo non conserva
//!
//! Le versioni dei dizionari. Un modello nomina un **profilo**, e un profilo
//! nomina i dizionari per identità: la versione si risolve quando il modello si
//! applica, con la regola che c'era già.
//!
//! E non conserva ciò che un modello ha prodotto: le fonti e i dizionari di una
//! sessione stanno **sulla sessione**, dove già stanno, e non se ne vanno se il
//! modello viene cancellato.
//!
//! # Che cosa non si può fare, e chi lo impedisce
//!
//! Modificare un modello, o le sue fonti: li rifiutano due trigger. E togliere
//! l'ultima fonte a un modello che resta: un modello senza fonti non
//! preparerebbe nulla, e chi lo ha salvato crederebbe di avere una
//! configurazione.

use lisi_core::model::monitoring_template::{
    MonitoringTemplate, NewMonitoringTemplate, Prescribed, PrescribedRetention,
};
use lisi_core::text::{Actor, DisplayName, Note};
use lisi_core::{DictionaryProfileId, MonitoringTemplateId, SourceId, Timestamp};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

impl Database {
    /// Crea un modello, con le sue fonti.
    ///
    /// # Perché in una transazione
    ///
    /// Perché un modello senza fonti non preparerebbe nulla: se l'inserimento
    /// delle fonti fallisse a metà, resterebbe una riga che si legge come una
    /// configurazione e non lo è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un modello con quel nome esiste già, se una
    /// fonte non esiste, o se la scrittura non riesce.
    pub fn insert_monitoring_template(
        &mut self,
        template: &NewMonitoringTemplate,
        created_at: Timestamp,
    ) -> StorageResult<MonitoringTemplateId> {
        let transaction = self.connection.transaction()?;

        // IL «CONSERVA TUTTO» PRESCRITTO SI SCRIVE CON LO ZERO.
        //
        // La politica esprime «conserva tutto» con il proprio NULL, e qui NULL
        // significa gia' «il modello non si esprime». Lo zero e' un valore che
        // la politica non ammette — il suo vincolo pretende almeno uno — quindi
        // non si confonde con nessuno.
        let giorni: Option<i64> = match template.retention() {
            PrescribedRetention::Silent => None,
            PrescribedRetention::KeepEverything => Some(0),
            PrescribedRetention::KeepDays(giorni) => Some(i64::from(giorni)),
        };
        let soglia: Option<i64> = match template.notification_level() {
            Prescribed::Silent => None,
            Prescribed::Value(livello) => Some(i64::from(livello)),
        };

        transaction.execute(
            "INSERT INTO monitoring_templates
                (name, description, dictionary_profile_id,
                 prescribed_notification_level, prescribed_keep_days,
                 created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                template.name().as_str(),
                template.description().map(Note::as_str),
                template.dictionary_profile().map(DictionaryProfileId::get),
                soglia,
                giorni,
                template.created_by().as_str(),
                millis(created_at),
            ],
        )?;
        let id = MonitoringTemplateId::new(transaction.last_insert_rowid());

        {
            let mut statement = transaction.prepare(
                "INSERT INTO monitoring_template_sources (template_id, source_id)
                 VALUES (?1, ?2)",
            )?;
            for source in template.sources() {
                statement.execute(rusqlite::params![id.get(), source.get()])?;
            }
        }

        transaction.commit()?;
        Ok(id)
    }

    /// I modelli, in ordine di nome, con le loro fonti.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn monitoring_templates(&self) -> StorageResult<Vec<MonitoringTemplate>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, description, dictionary_profile_id,
                    prescribed_notification_level, prescribed_keep_days,
                    created_by, created_at
             FROM monitoring_templates
             ORDER BY name ASC",
        )?;
        let righe: Vec<TemplateRow> = statement
            .query_map([], TemplateRow::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut modelli = Vec::with_capacity(righe.len());
        for riga in righe {
            let id = MonitoringTemplateId::new(riga.id);
            modelli.push(riga.into_template(self.template_sources(id)?)?);
        }
        Ok(modelli)
    }

    /// Un modello, con le sue fonti.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se non esiste.
    pub fn monitoring_template(
        &self,
        id: MonitoringTemplateId,
    ) -> StorageResult<MonitoringTemplate> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, description, dictionary_profile_id,
                    prescribed_notification_level, prescribed_keep_days,
                    created_by, created_at
             FROM monitoring_templates
             WHERE id = ?1",
        )?;
        let mut righe = statement.query_map([id.get()], TemplateRow::from_row)?;
        match righe.next() {
            Some(riga) => {
                let riga = riga?;
                let fonti = self.template_sources(id)?;
                riga.into_template(fonti)
            }
            None => Err(StorageError::NotFound {
                entity: "modello di monitoraggio",
                id: id.get(),
            }),
        }
    }

    /// Cancella un modello.
    ///
    /// # Che cosa NON tocca
    ///
    /// Le sessioni che quel modello ha preparato. Le loro fonti e i loro
    /// dizionari stanno sulla sessione, e restano: un modello è uno
    /// **strumento**, e cancellarlo non riscrive che cosa è stato fatto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se non c'era.
    pub fn delete_monitoring_template(&self, id: MonitoringTemplateId) -> StorageResult<()> {
        // LE FONTI SE NE VANNO CON IL MODELLO, per la cascata dichiarata nello
        // schema. Il trigger che pretende almeno una fonte non scatta, perche'
        // controlla che il modello esista ancora — e in questa cancellazione non
        // esiste piu'.
        let toccate = self
            .connection
            .execute("DELETE FROM monitoring_templates WHERE id = ?1", [id.get()])?;
        if toccate == 0 {
            return Err(StorageError::NotFound {
                entity: "modello di monitoraggio",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Le fonti di un modello.
    fn template_sources(&self, id: MonitoringTemplateId) -> StorageResult<Vec<SourceId>> {
        let mut statement = self.connection.prepare(
            "SELECT source_id FROM monitoring_template_sources
             WHERE template_id = ?1
             ORDER BY source_id ASC",
        )?;
        let fonti: Vec<i64> = statement
            .query_map([id.get()], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(fonti.into_iter().map(SourceId::new).collect())
    }
}

/// Riga grezza della tabella `monitoring_templates`.
struct TemplateRow {
    id: i64,
    name: String,
    description: Option<String>,
    dictionary_profile_id: Option<i64>,
    prescribed_notification_level: Option<i64>,
    prescribed_keep_days: Option<i64>,
    created_by: String,
    created_at: i64,
}

impl TemplateRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            description: row.get(2)?,
            dictionary_profile_id: row.get(3)?,
            prescribed_notification_level: row.get(4)?,
            prescribed_keep_days: row.get(5)?,
            created_by: row.get(6)?,
            created_at: row.get(7)?,
        })
    }

    fn into_template(self, sources: Vec<SourceId>) -> StorageResult<MonitoringTemplate> {
        let description = match self.description {
            None => None,
            Some(testo) => Some(Note::try_new(&testo)?),
        };

        // LO ZERO E' «CONSERVA TUTTO», e NULL e' «non si esprime».
        //
        // La distinzione la fa lo schema, e leggerla al contrario farebbe
        // prescrivere la conservazione illimitata a ogni modello che tace.
        let retention = match self.prescribed_keep_days {
            None => PrescribedRetention::Silent,
            Some(0) => PrescribedRetention::KeepEverything,
            Some(giorni) => PrescribedRetention::KeepDays(u32::try_from(giorni).unwrap_or(1)),
        };

        let notification_level = match self.prescribed_notification_level {
            None => Prescribed::Silent,
            // Il vincolo dell'archivio garantisce l'intervallo 1-4; una
            // conversione che fallisse qui vorrebbe dire un archivio manomesso,
            // e allora il valore prudente e' il piu' basso: si viene avvisati
            // di piu', e questo si vede.
            Some(livello) => Prescribed::Value(u8::try_from(livello).unwrap_or(1)),
        };

        Ok(MonitoringTemplate {
            id: MonitoringTemplateId::new(self.id),
            name: DisplayName::try_new(&self.name)?,
            description,
            sources,
            dictionary_profile: self.dictionary_profile_id.map(DictionaryProfileId::new),
            notification_level,
            retention,
            created_by: Actor::try_new(&self.created_by)?,
            created_at: instant(self.created_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::monitoring_template::{
        NewMonitoringTemplate, Prescribed, PrescribedRetention,
    };
    use lisi_core::text::DisplayName;
    use lisi_core::{MonitoringTemplateId, SourceId, Timestamp};

    use crate::test_support::{actor, database_with_session};

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(nome) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        nome
    }

    fn modello(
        etichetta: &str,
        fonti: Vec<SourceId>,
        soglia: Prescribed<u8>,
        conservazione: PrescribedRetention,
    ) -> NewMonitoringTemplate {
        let Ok(modello) = NewMonitoringTemplate::of(
            nome(etichetta),
            None,
            fonti,
            None,
            soglia,
            conservazione,
            actor("operatore.prova"),
        ) else {
            panic!("il modello di prova deve essere valido");
        };
        modello
    }

    /// **Un modello si crea e si rilegge identico.**
    #[test]
    fn un_modello_si_crea_e_si_rilegge_identico() {
        let (mut database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_monitoring_template(
            &modello(
                "Marzo",
                vec![source_id],
                Prescribed::Value(3),
                PrescribedRetention::KeepDays(90),
            ),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };

        let Ok(letto) = database.monitoring_template(id) else {
            panic!("il modello deve potersi rileggere");
        };
        assert_eq!(letto.name.as_str(), "Marzo");
        assert_eq!(letto.sources, vec![source_id]);
        assert_eq!(letto.notification_level, Prescribed::Value(3));
        assert_eq!(letto.retention, PrescribedRetention::KeepDays(90));
        assert_eq!(letto.created_by.as_str(), "operatore.prova");
    }

    /// **«Conserva tutto» e «non si esprime» si rileggono diversi.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I due `NULL` confusi. Se «conserva tutto» si scrivesse con `NULL`, ogni
    /// modello che tace prescriverebbe la conservazione illimitata — e chi
    /// leggesse il confronto vedrebbe una differenza che nessuno ha deciso.
    #[test]
    fn conserva_tutto_e_non_si_esprime_si_rileggono_diversi() {
        let (mut database, source_id, _) = database_with_session();

        let Ok(tutto) = database.insert_monitoring_template(
            &modello(
                "Conserva tutto",
                vec![source_id],
                Prescribed::Silent,
                PrescribedRetention::KeepEverything,
            ),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };
        let Ok(muto) = database.insert_monitoring_template(
            &modello(
                "Non si esprime",
                vec![source_id],
                Prescribed::Silent,
                PrescribedRetention::Silent,
            ),
            istante(ORA + 1),
        ) else {
            panic!("il modello deve potersi creare");
        };

        let (Ok(tutto), Ok(muto)) = (
            database.monitoring_template(tutto),
            database.monitoring_template(muto),
        ) else {
            panic!("i modelli devono potersi rileggere");
        };
        assert_eq!(tutto.retention, PrescribedRetention::KeepEverything);
        assert_eq!(muto.retention, PrescribedRetention::Silent);
        assert_ne!(tutto.retention, muto.retention);
    }

    /// **Due modelli non hanno lo stesso nome.**
    #[test]
    fn due_modelli_non_hanno_lo_stesso_nome() {
        let (mut database, source_id, _) = database_with_session();
        let Ok(_) = database.insert_monitoring_template(
            &modello(
                "Marzo",
                vec![source_id],
                Prescribed::Silent,
                PrescribedRetention::Silent,
            ),
            istante(ORA),
        ) else {
            panic!("il primo deve potersi creare");
        };
        assert!(
            database
                .insert_monitoring_template(
                    &modello(
                        "Marzo",
                        vec![source_id],
                        Prescribed::Silent,
                        PrescribedRetention::Silent,
                    ),
                    istante(ORA + 1),
                )
                .is_err(),
            "due modelli omonimi sono una trappola"
        );
    }

    /// **Un modello non si modifica, né nelle sue fonti.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un modello che porta «creato da Tizio il 3 marzo» e fonti che qualcuno
    /// ha cambiato ieri. Senza il secondo trigger il modello sarebbe immutabile
    /// e il suo contenuto no.
    #[test]
    fn un_modello_non_si_modifica_ne_nelle_sue_fonti() {
        let (mut database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_monitoring_template(
            &modello(
                "Marzo",
                vec![source_id],
                Prescribed::Silent,
                PrescribedRetention::Silent,
            ),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };

        for istruzione in [
            "UPDATE monitoring_templates SET name = 'Aprile' WHERE id = ?1",
            "UPDATE monitoring_templates SET prescribed_keep_days = 7 WHERE id = ?1",
        ] {
            assert!(
                database.connection.execute(istruzione, [id.get()]).is_err(),
                "«{istruzione}» deve essere rifiutata"
            );
        }
        assert!(
            database
                .connection
                .execute(
                    "UPDATE monitoring_template_sources SET source_id = 999 WHERE template_id = ?1",
                    [id.get()],
                )
                .is_err(),
            "le fonti di un modello non si modificano"
        );
    }

    /// **Un modello non resta senza fonti.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un modello svuotato a una fonte per volta. Applicarlo non preparerebbe
    /// nulla, e chi lo ha salvato crederebbe di avere una configurazione.
    #[test]
    fn un_modello_non_resta_senza_fonti() {
        let (mut database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_monitoring_template(
            &modello(
                "Marzo",
                vec![source_id],
                Prescribed::Silent,
                PrescribedRetention::Silent,
            ),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };

        assert!(
            database
                .connection
                .execute(
                    "DELETE FROM monitoring_template_sources WHERE template_id = ?1",
                    [id.get()],
                )
                .is_err(),
            "togliere l'ultima fonte lascerebbe un modello che non prepara nulla"
        );
    }

    /// **Un modello si cancella, con le sue fonti.**
    #[test]
    fn un_modello_si_cancella_con_le_sue_fonti() {
        let (mut database, source_id, _) = database_with_session();
        let Ok(id) = database.insert_monitoring_template(
            &modello(
                "Marzo",
                vec![source_id],
                Prescribed::Silent,
                PrescribedRetention::Silent,
            ),
            istante(ORA),
        ) else {
            panic!("il modello deve potersi creare");
        };

        let Ok(()) = database.delete_monitoring_template(id) else {
            panic!("la cancellazione deve riuscire");
        };
        let Ok(elenco) = database.monitoring_templates() else {
            panic!("la lettura deve riuscire");
        };
        assert!(elenco.is_empty());

        let rimaste: Result<i64, _> = database.connection.query_row(
            "SELECT COUNT(*) FROM monitoring_template_sources WHERE template_id = ?1",
            [id.get()],
            |row| row.get(0),
        );
        assert_eq!(rimaste, Ok(0), "le fonti se ne vanno con il modello");

        assert!(
            database.delete_monitoring_template(id).is_err(),
            "non c'e' nulla da cancellare due volte"
        );
    }

    /// **Leggere un modello che non c'è lo dichiara.**
    #[test]
    fn leggere_un_modello_che_non_c_e_lo_dichiara() {
        let (database, _, _) = database_with_session();
        assert!(
            database
                .monitoring_template(MonitoringTemplateId::new(999))
                .is_err()
        );
    }

    /// **L'archivio rifiuta una soglia che non esiste.**
    #[test]
    fn l_archivio_rifiuta_una_soglia_che_non_esiste() {
        let (database, _, _) = database_with_session();
        let esito = database.connection.execute(
            "INSERT INTO monitoring_templates
                (name, prescribed_notification_level, created_by, created_at)
             VALUES ('Impossibile', 9, 'operatore.prova', 0)",
            [],
        );
        assert!(
            esito.is_err(),
            "i livelli sono cinque, e la soglia va da 1 a 4"
        );
    }
}

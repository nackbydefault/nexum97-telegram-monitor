//! Registro di audit, append-only.

use lisi_core::model::{AuditEntry, NewAuditEntry};
use lisi_core::role::OperatingMode;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{AuditId, Timestamp};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `audit`.
struct AuditRow {
    id: i64,
    actor: String,
    action: String,
    entity: String,
    entity_id: Option<i64>,
    actor_mode: Option<String>,
    detail: Option<String>,
    recorded_at: i64,
}

impl AuditRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            actor: row.get(1)?,
            action: row.get(2)?,
            entity: row.get(3)?,
            entity_id: row.get(4)?,
            actor_mode: row.get(5)?,
            detail: row.get(6)?,
            recorded_at: row.get(7)?,
        })
    }

    fn into_domain(self) -> StorageResult<AuditEntry> {
        let detail = match self.detail {
            Some(ref raw) => Some(AuditDetail::try_new(raw)?),
            None => None,
        };

        // Un valore diverso da NULL ma non riconoscibile e' una riga corrotta,
        // non una modalita' da indovinare.
        let actor_mode = match self.actor_mode {
            Some(ref raw) => {
                Some(
                    OperatingMode::parse(raw).map_err(|_| StorageError::CorruptedRow {
                        detail: "modalità operativa non riconoscibile in una voce di audit",
                    })?,
                )
            }
            None => None,
        };

        Ok(AuditEntry {
            id: AuditId::new(self.id),
            actor: Actor::try_new(&self.actor)?,
            action: AuditAction::try_new(&self.action)?,
            entity: AuditEntity::try_new(&self.entity)?,
            entity_id: self.entity_id,
            actor_mode,
            detail,
            recorded_at: instant(self.recorded_at),
        })
    }
}

/// L'azione con cui l'ufficio registra la ragione operativa.
///
/// # Perché sta qui, e una volta sola
///
/// Perché fino a HARDEN-04 questa stringa era scritta in **sei moduli diversi**,
/// e sei copie della stessa domanda sono sei cose da tenere allineate: il giorno
/// in cui una cambiasse, cinque percorsi continuerebbero a chiedere la vecchia e
/// nessuno se ne accorgerebbe leggendo.
pub const RAGIONE_OPERATIVA: &str = "elenco_persone_motivato";

impl Database {
    /// Se la ragione operativa che autorizza il lavoro investigativo è
    /// registrata.
    ///
    /// # Perché non si conta e non si carica
    ///
    /// Perché la domanda non chiede righe: chiede **se ne esiste una**. Fino a
    /// HARDEN-04 sei percorsi la ponevano caricando **ogni voce** del registro e
    /// cercando fra quelle — su un registro in sola aggiunta, che cresce per
    /// tutta la vita dell'installazione, la risposta costava quanto tutto ciò
    /// che l'ufficio aveva fatto dal primo giorno.
    ///
    /// Con `EXISTS` e l'indice della migrazione 0051 costa quanto una ricerca.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn operational_basis_recorded(&self) -> StorageResult<bool> {
        let esiste: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM audit WHERE action = ?1)",
            rusqlite::params![RAGIONE_OPERATIVA],
            |row| row.get(0),
        )?;
        Ok(esiste != 0)
    }
}

impl Database {
    /// Aggiunge una voce al registro di audit.
    ///
    /// Il registro non ha altre operazioni di scrittura: modifica e
    /// cancellazione sono rifiutate dal motore tramite trigger, non da una
    /// convenzione di questo modulo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn append_audit(&self, entry: &NewAuditEntry) -> StorageResult<AuditId> {
        let id: i64 = self.connection.query_row(
            "INSERT INTO audit (actor, action, entity, entity_id, actor_mode, detail, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             RETURNING id",
            rusqlite::params![
                entry.actor.as_str(),
                entry.action.as_str(),
                entry.entity.as_str(),
                entry.entity_id,
                entry.actor_mode.map(OperatingMode::as_str),
                entry.detail.as_ref().map(AuditDetail::as_str),
                millis(entry.recorded_at),
            ],
            |row| row.get(0),
        )?;

        Ok(AuditId::new(id))
    }

    /// Voci di audit, dalla più antica.
    ///
    /// L'ordine cronologico crescente è quello in cui il registro va letto: è la
    /// sequenza delle azioni compiute.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn audit_entries(&self) -> StorageResult<Vec<AuditEntry>> {
        let mut statement = self.connection.prepare(
            "SELECT id, actor, action, entity, entity_id, actor_mode, detail, recorded_at
             FROM audit
             ORDER BY recorded_at, id",
        )?;

        let rows = statement.query_map([], AuditRow::read)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?.into_domain()?);
        }
        Ok(entries)
    }

    /// **Quando** un'azione è stata compiuta l'ultima volta.
    ///
    /// # Perché restituisce solo l'istante
    ///
    /// Perché serve alla diagnostica, che è **esportabile** — e il dettaglio di
    /// alcune azioni contiene un percorso. Un percorso reale su Windows
    /// contiene il nome dell'account con cui si è entrati, che è un dato
    /// personale: restituire la riga intera renderebbe possibile portarlo fuori
    /// dalla postazione per distrazione, in un file scritto per essere spedito.
    ///
    /// Non restituendolo, la distrazione non è possibile: chi chiama non ha il
    /// dettaglio da mostrare nemmeno volendo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_audit_at(&self, action: &str) -> StorageResult<Option<Timestamp>> {
        let millis: Option<i64> = self
            .connection
            .query_row(
                "SELECT MAX(recorded_at) FROM audit WHERE action = ?1",
                rusqlite::params![action],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        Ok(millis.map(Timestamp::from_millis))
    }

    /// **Quando** è stato registrato l'ultimo fatto dell'archivio, di qualunque
    /// azione.
    ///
    /// Serve al controllo di avvio (PR-04): un orologio che dice un istante
    /// precedente a questo è tornato indietro. Come [`Self::last_audit_at`],
    /// restituisce soltanto l'istante, mai la riga.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest_audit_at(&self) -> StorageResult<Option<Timestamp>> {
        let millis: Option<i64> = self
            .connection
            .query_row("SELECT MAX(recorded_at) FROM audit", [], |row| row.get(0))
            .optional()?
            .flatten();

        Ok(millis.map(Timestamp::from_millis))
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::RAGIONE_OPERATIVA;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};

    use crate::test_support::{actor, database, later};

    fn new_entry(action: &str, recorded_at: Timestamp) -> NewAuditEntry {
        let (Ok(action), Ok(entity), Ok(detail)) = (
            AuditAction::try_new(action),
            AuditEntity::try_new("session"),
            AuditDetail::try_new("Avvio richiesto dall'operatore"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        NewAuditEntry {
            actor: actor("operatore.prova"),
            action,
            entity,
            entity_id: Some(1),
            actor_mode: None,
            detail: Some(detail),
            recorded_at,
        }
    }

    /// I sorgenti di produzione delle crate che interrogano l'archivio.
    fn produzione_dei_servizi() -> Vec<(String, String)> {
        let Some(crate_dir) = option_env!("CARGO_MANIFEST_DIR") else {
            panic!("la guardia legge i sorgenti: serve la cartella della crate");
        };
        let Some(crates) = std::path::Path::new(crate_dir).parent() else {
            panic!("la cartella delle crate non si trova");
        };

        let mut trovati = Vec::new();
        for crate_nome in ["lisi-services", "lisi-app"] {
            let sorgenti = crates.join(crate_nome).join("src");
            let Ok(voci) = std::fs::read_dir(&sorgenti) else {
                panic!(
                    "i sorgenti di «{crate_nome}» non si leggono: la guardia non ha guardato nulla"
                );
            };
            for voce in voci.flatten() {
                let percorso = voce.path();
                if percorso.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let Some(nome) = percorso.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Ok(testo) = std::fs::read_to_string(&percorso) else {
                    panic!("il modulo «{nome}» non si legge");
                };
                // SOLO LA PRODUZIONE: le prove leggono il registro intero per
                // contarlo, ed e' il loro mestiere.
                let produzione = testo
                    .split_once("\n#[cfg(test)]\nmod ")
                    .map_or(testo.clone(), |(prima, _)| prima.to_owned());
                trovati.push((format!("{crate_nome}/{nome}"), produzione));
            }
        }
        trovati
    }

    /// **Nessun percorso di produzione risponde a un sì o no leggendo tutto il
    /// registro.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il registro d'audit è **in sola aggiunta** e cresce per tutta la vita
    /// dell'installazione: nessuno lo pota, ed è giusto così. Prima di
    /// HARDEN-04 **sei** percorsi di produzione gli ponevano la stessa domanda
    /// — «qualcuno ha mai registrato la ragione operativa?» — caricando **ogni
    /// riga** e cercando fra quelle.
    ///
    /// Su un archivio giovane non si vede. Su uno vecchio, quella domanda costa
    /// quanto tutto ciò che l'ufficio ha fatto dal primo giorno, e la si pone
    /// mentre si compone una schermata o un documento.
    ///
    /// La domanda non chiede righe: chiede **se ne esiste una** (ADR-0113).
    #[test]
    fn nessun_percorso_risponde_a_un_si_o_no_leggendo_tutto_il_registro() {
        let moduli = produzione_dei_servizi();
        assert!(
            moduli.len() > 50,
            "solo {} moduli letti: se la cartella dei sorgenti e' cambiata, questa guardia \
             va aggiornata insieme al percorso",
            moduli.len()
        );

        for (nome, produzione) in moduli {
            let Some((_, dopo)) = produzione.split_once("audit_entries()") else {
                continue;
            };
            // Si guarda cio' che segue immediatamente la lettura: un `any` o un
            // `find` subito dopo significa che si cercava UNA voce.
            let subito = dopo.chars().take(120).collect::<String>();
            for forma in [".any(", ".find(", ".position("] {
                assert!(
                    !subito.contains(forma),
                    "«{nome}» cerca una voce caricando tutto il registro d'audit con \
                     «{forma}»: la domanda non chiede righe, chiede se ne esiste una. \
                     Si usa una lettura che chiede `EXISTS` (ADR-0113)"
                );
            }
        }
    }

    /// **La ragione operativa ha un nome solo, e chi la legge non lo scrive.**
    ///
    /// # Perché sei copie erano sei cose da tenere allineate
    ///
    /// Perché il giorno in cui una cambiasse, cinque percorsi continuerebbero a
    /// chiedere la vecchia — e nessuno se ne accorgerebbe leggendo, perché
    /// ciascuno resterebbe coerente con sé stesso.
    #[test]
    fn la_ragione_operativa_ha_un_nome_solo() {
        for (nome, produzione) in produzione_dei_servizi() {
            if !produzione.contains(RAGIONE_OPERATIVA) {
                continue;
            }
            // CHI LA SCRIVE PUO' NOMINARLA: registrare la ragione e' l'atto che
            // la fa esistere, e l'atto ha un modulo suo. Chi la LEGGE no.
            assert!(
                produzione.contains("append_audit"),
                "«{nome}» nomina la ragione operativa senza registrarla: chi la legge deve \
                 chiederla con `operational_basis_recorded`, non riscriverne il nome \
                 (ADR-0113)"
            );
        }
    }

    /// **L'indice sull'azione esiste dopo le migrazioni.**
    ///
    /// Senza, `EXISTS` costa comunque una scansione: la lettura che non carica
    /// le righe continuerebbe a leggerle tutte, e la correzione sarebbe solo
    /// più elegante da guardare.
    #[test]
    fn l_indice_sull_azione_dell_audit_esiste() {
        let Ok(database) = crate::database::Database::open_in_memory() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };

        let indice: Result<String, _> = database.connection.query_row(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'audit_by_action'",
            [],
            |row| row.get(0),
        );
        assert_eq!(
            indice.ok().as_deref(),
            Some("audit_by_action"),
            "l'indice sull'azione dell'audit non esiste: la domanda «esiste questa voce?» \
             tornerebbe a costare quanto il registro"
        );
    }

    #[test]
    fn an_entry_is_written_and_read_back_unchanged() {
        let database = database();

        let Ok(id) = database.append_audit(&new_entry("sessione_avviata", later(5))) else {
            panic!("la voce deve potersi registrare");
        };

        let Ok(entries) = database.audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert_eq!(entries[0].action.as_str(), "sessione_avviata");
        assert_eq!(entries[0].entity.as_str(), "session");
        assert_eq!(entries[0].entity_id, Some(1));
        assert_eq!(entries[0].recorded_at, later(5));
    }

    #[test]
    fn the_operating_mode_survives_the_round_trip_and_absence_stays_absent() {
        use lisi_core::role::OperatingMode;

        let database = database();
        let mut with_mode = new_entry("versione_pubblicata", later(5));
        with_mode.actor_mode = Some(OperatingMode::Administrator);
        let without = new_entry("fonte_aggiunta", later(6));

        let (Ok(_), Ok(_)) = (
            database.append_audit(&with_mode),
            database.append_audit(&without),
        ) else {
            panic!("le voci devono potersi registrare");
        };

        let Ok(entries) = database.audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        assert_eq!(entries[0].actor_mode, Some(OperatingMode::Administrator));
        assert_eq!(entries[1].actor_mode, None, "l'assenza resta assenza");
    }

    #[test]
    fn the_schema_refuses_an_unknown_mode_at_write_time() {
        // La lettura si difende comunque da un valore non riconoscibile, ma il
        // CHECK dello schema e' la prima difesa: un valore fuori dai due
        // ammessi non entra affatto. E' cio' che rende irraggiungibile, per le
        // vie ordinarie, il ramo di errore della rilettura.
        let database = database();
        let refused = database.connection.execute(
            "INSERT INTO audit (actor, action, entity, actor_mode, recorded_at)
             VALUES ('x', 'y', 'z', 'root', 1)",
            [],
        );
        assert!(
            refused.is_err(),
            "una modalita' fuori dai due valori ammessi non deve potersi scrivere"
        );
    }

    #[test]
    fn entries_are_read_in_chronological_order() {
        let database = database();
        for (action, seconds) in [("terza", 30), ("prima", 10), ("seconda", 20)] {
            let Ok(_) = database.append_audit(&new_entry(action, later(seconds))) else {
                panic!("la voce deve potersi registrare");
            };
        }

        let Ok(entries) = database.audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
        assert_eq!(actions, ["prima", "seconda", "terza"]);
    }

    #[test]
    fn an_entry_cannot_be_modified() {
        let database = database();
        let Ok(_) = database.append_audit(&new_entry("sessione_avviata", later(5))) else {
            panic!("la voce deve potersi registrare");
        };

        // La verifica passa dalla connessione perché l'API pubblica non espone
        // alcuna scrittura oltre all'aggiunta: si sta verificando che il divieto
        // regga anche a un'istruzione SQL diretta, non che manchi un metodo.
        let refused = database
            .connection
            .execute("UPDATE audit SET actor = 'altro' WHERE id = 1", []);
        assert!(
            refused.is_err(),
            "la modifica di una voce di audit doveva essere rifiutata dal motore"
        );

        let Ok(entries) = database.audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        assert_eq!(entries[0].actor.as_str(), "operatore.prova");
    }

    #[test]
    fn an_entry_cannot_be_deleted() {
        let database = database();
        let Ok(_) = database.append_audit(&new_entry("sessione_avviata", later(5))) else {
            panic!("la voce deve potersi registrare");
        };

        let refused = database
            .connection
            .execute("DELETE FROM audit WHERE id = 1", []);
        assert!(
            refused.is_err(),
            "la cancellazione di una voce di audit doveva essere rifiutata dal motore"
        );

        assert_eq!(database.audit_entries().map(|e| e.len()).ok(), Some(1));
    }

    #[test]
    fn the_whole_register_cannot_be_emptied() {
        let database = database();
        for seconds in [5, 10, 15] {
            let Ok(_) = database.append_audit(&new_entry("azione", later(seconds))) else {
                panic!("la voce deve potersi registrare");
            };
        }

        let refused = database.connection.execute("DELETE FROM audit", []);
        assert!(
            refused.is_err(),
            "lo svuotamento del registro doveva essere rifiutato dal motore"
        );
        assert_eq!(database.audit_entries().map(|e| e.len()).ok(), Some(3));
    }

    #[test]
    fn a_refused_modification_reports_the_trigger_as_the_cause() {
        let database = database();
        let Ok(_) = database.append_audit(&new_entry("azione", later(5))) else {
            panic!("la voce deve potersi registrare");
        };

        let Err(error) = database
            .connection
            .execute("UPDATE audit SET detail = NULL WHERE id = 1", [])
        else {
            panic!("la modifica doveva essere rifiutata");
        };

        assert_eq!(
            crate::error::constraint_kind(&error),
            Some(crate::error::ConstraintKind::Trigger)
        );
    }

    /// L'ultima volta di un'azione è l'istante più recente, non il primo.
    #[test]
    fn the_last_time_an_action_happened_is_the_most_recent_one() {
        let database = database();
        for istante in [later(5), later(50), later(20)] {
            let Ok(_) = database.append_audit(&new_entry("copia_prodotta", istante)) else {
                panic!("la voce deve potersi registrare");
            };
        }
        let Ok(_) = database.append_audit(&new_entry("altra_azione", later(90))) else {
            panic!("la voce deve potersi registrare");
        };

        assert_eq!(
            database.last_audit_at("copia_prodotta").ok().flatten(),
            Some(later(50)),
            "va restituito l'istante più recente di QUELL'azione"
        );
    }

    /// Un'azione mai compiuta non ha un'ultima volta.
    ///
    /// **Non è l'epoca, ed è la differenza che conta**: una diagnostica che
    /// leggesse zero al posto di «mai» direbbe che una copia di sicurezza c'è
    /// stata, il primo gennaio 1970.
    #[test]
    fn an_action_never_taken_has_no_last_time() {
        let database = database();
        let Ok(_) = database.append_audit(&new_entry("azione", later(5))) else {
            panic!("la voce deve potersi registrare");
        };

        assert_eq!(database.last_audit_at("mai_avvenuta").ok().flatten(), None);
    }

    /// La lettura non restituisce il dettaglio, e non deve poterlo fare.
    ///
    /// Il dettaglio di alcune azioni contiene un percorso, e un percorso reale
    /// su Windows contiene il nome dell'account Windows. Questa funzione serve
    /// alla diagnostica, che è esportabile: il tipo di ritorno è la guardia,
    /// perché chi chiama non ha il dettaglio nemmeno volendo.
    #[test]
    fn the_last_time_carries_no_detail_at_all() {
        let database = database();
        let Ok(_) = database.append_audit(&new_entry("azione", later(5))) else {
            panic!("la voce deve potersi registrare");
        };

        let esito = database.last_audit_at("azione");
        // Il valore è un istante, e un istante non può contenere un percorso.
        // Se un giorno questa funzione restituisse una riga, questa asserzione
        // smetterebbe di compilare — ed è esattamente ciò che deve fare.
        let Ok(Some(istante)) = esito else {
            panic!("l'azione registrata deve avere un'ultima volta");
        };
        let _: Timestamp = istante;
    }

    /// L'ultimo fatto dell'archivio è il più recente fra **tutte** le azioni, e
    /// un archivio vuoto non ne ha.
    #[test]
    fn the_latest_fact_is_the_most_recent_of_any_action() {
        let database = database();
        assert_eq!(database.latest_audit_at().ok().flatten(), None);

        for (azione, secondi) in [("prima", 5), ("seconda", 9), ("terza", 7)] {
            let Ok(_) = database.append_audit(&new_entry(azione, later(secondi))) else {
                panic!("la voce deve potersi registrare");
            };
        }
        assert_eq!(database.latest_audit_at().ok().flatten(), Some(later(9)));
    }

    /// Il contatore delle scritture cresce di una riga per voce, e leggere non
    /// lo muove.
    #[test]
    fn the_change_counter_counts_writes_and_not_reads() {
        let database = database();
        let prima = database.total_changes();
        let _ = database.latest_audit_at();
        let _ = database.audit_entries();
        assert_eq!(database.total_changes(), prima);

        let Ok(_) = database.append_audit(&new_entry("azione", later(5))) else {
            panic!("la voce deve potersi registrare");
        };
        assert_eq!(database.total_changes(), prima + 1);
    }
}

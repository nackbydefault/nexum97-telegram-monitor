//! I monitoraggi interrotti, in archivio.
//!
//! # La domanda per cui questa tabella esiste
//!
//! «All'avvio, c'era un monitoraggio che risultava in corso e che questo
//! processo non ha avviato?»
//!
//! Se c'era, **nessuno lo ha fermato**: è stato interrotto. Lo stato della
//! sessione non si tocca — resta in corso, che è vero — e il fatto vive qui
//! accanto (ADR-0064).

use lisi_core::SessionId;
use lisi_core::Timestamp;
use lisi_core::model::interruption::{GapStart, Interruption};

use crate::Database;
use crate::error::{StorageError, StorageResult};

/// Come si scrive in archivio la provenienza dell'inizio del buco.
const ORIGIN_LAST_CONTENT: &str = "ultimo_contenuto";
/// Come si scrive in archivio l'altra provenienza.
const ORIGIN_MONITORING_START: &str = "avvio";

/// La chiusura ordinata del programma (ADR-0195, migrazione 0089).
const ORIGIN_ORDERLY_CLOSE: &str = "chiusura";

/// Un'interruzione come sta in archivio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredInterruption {
    /// La sessione interrotta.
    pub session_id: SessionId,
    /// Il fatto.
    pub interruption: Interruption,
    /// Quando l'operatore l'ha presa in carico, se l'ha fatto.
    pub acknowledged_at: Option<Timestamp>,
}

impl Database {
    /// L'interruzione di un monitoraggio come tratto: dall'inizio del buco al
    /// riavvio in cui ce ne si è accorti (PR-05, ADR-0121).
    ///
    /// Presa in carico o no, il fatto resta: la copertura lo legge comunque.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn interruption_span(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Option<(Timestamp, Timestamp)>> {
        use rusqlite::OptionalExtension;

        let riga: Option<(i64, i64)> = self
            .connection
            .query_row(
                "SELECT gap_start_at, noticed_at FROM session_interruptions WHERE session_id = ?1",
                [session_id.get()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(riga.map(|(da, a)| (Timestamp::from_millis(da), Timestamp::from_millis(a))))
    }

    /// Registra che una sessione risultava in corso all'avvio.
    ///
    /// # Perché non sovrascrive
    ///
    /// Perché **il fatto è uno solo**: riaprire dieci volte una postazione con
    /// una sessione interrotta non produce dieci interruzioni, e la seconda
    /// riapertura non deve poter cambiare l'istante in cui ci si è accorti la
    /// prima volta. Una riga che c'è già resta com'è, e la funzione lo dice
    /// restituendo `false`.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn record_interruption(
        &mut self,
        session_id: SessionId,
        interruption: &Interruption,
    ) -> StorageResult<bool> {
        let origin = match interruption.gap_start() {
            GapStart::LastContent(_) => ORIGIN_LAST_CONTENT,
            GapStart::MonitoringStart(_) => ORIGIN_MONITORING_START,
            GapStart::OrderlyClose(_) => ORIGIN_ORDERLY_CLOSE,
        };

        let scritte = self.connection.execute(
            "INSERT OR IGNORE INTO session_interruptions (
                 session_id, noticed_at, gap_start_at, gap_start_origin, acknowledged_at
             ) VALUES (?1, ?2, ?3, ?4, NULL)",
            rusqlite::params![
                session_id.get(),
                interruption.noticed_at().as_millis(),
                interruption.gap_start().instant().as_millis(),
                origin,
            ],
        )?;

        Ok(scritte > 0)
    }

    /// L'interruzione **aperta** più recente, se ce n'è una.
    ///
    /// «Aperta» significa non ancora presa in carico. Ciò che è stato visto
    /// resta in archivio: sparisce l'avviso, non il fatto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è più
    /// interpretabile.
    pub fn open_interruption(&self) -> StorageResult<Option<StoredInterruption>> {
        Ok(self.open_interruptions()?.into_iter().next())
    }

    /// **Tutte** le interruzioni aperte, dalla più recente.
    ///
    /// # Perché servono tutte
    ///
    /// Perché con più monitoraggi (ADR-0065) un arresto anomalo ne interrompe
    /// **più d'uno**, e ciascuno porta il proprio fatto. Mostrarne uno solo
    /// lascerebbe gli altri senza che nessuno sappia di doverli guardare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga non è più
    /// interpretabile.
    pub fn open_interruptions(&self) -> StorageResult<Vec<StoredInterruption>> {
        let mut statement = self.connection.prepare(
            "SELECT session_id, noticed_at, gap_start_at, gap_start_origin
             FROM session_interruptions
             WHERE acknowledged_at IS NULL
             ORDER BY noticed_at DESC, session_id DESC",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (session_id, noticed_at, gap_start_at, origin) = riga?;

            let gap_start = match origin.as_str() {
                ORIGIN_LAST_CONTENT => GapStart::LastContent(Timestamp::from_millis(gap_start_at)),
                ORIGIN_MONITORING_START => {
                    GapStart::MonitoringStart(Timestamp::from_millis(gap_start_at))
                }
                ORIGIN_ORDERLY_CLOSE => {
                    GapStart::OrderlyClose(Timestamp::from_millis(gap_start_at))
                }
                _ => {
                    return Err(StorageError::CorruptedRow {
                        detail: "la provenienza dell'inizio del buco non è interpretabile",
                    });
                }
            };

            trovate.push(StoredInterruption {
                session_id: SessionId::new(session_id),
                interruption: Interruption::new(Timestamp::from_millis(noticed_at), gap_start),
                acknowledged_at: None,
            });
        }
        Ok(trovate)
    }

    /// I monitoraggi che risultano **acquisire** — in corso, oppure in corso
    /// con gli avvisi sospesi — con l'istante del loro avvio.
    ///
    /// # Perché anche gli avvisi sospesi
    ///
    /// Perché «Sospendi avvisi» tacita le notifiche e **non** l'acquisizione
    /// (ADR-0017, DEC-098). Fino al 2026-10-17 questa domanda chiedeva soltanto
    /// `running`: il ciclo di acquisizione, che la usa per sapere dove
    /// ingerire, smetteva di archiviare non appena l'operatore sospendeva gli
    /// avvisi, e un arresto anomalo in quello stato non veniva registrato come
    /// interruzione (MFX01-A, trovato correggendo E2E01-01).
    ///
    /// # Perché questa domanda vive qui
    ///
    /// Perché è la domanda dell'interruzione, e non quella della schermata del
    /// monitoraggio: chiede «quali righe dicono di essere in corso», senza
    /// comporre alcuna vista e senza contare nulla. Chiederlo alla vista del
    /// monitoraggio costerebbe una lettura che all'avvio non serve.
    ///
    /// # Perché restituisce un elenco
    ///
    /// Perché i monitoraggi possono essere più di uno (ADR-0065), e ciascuno che
    /// risulti in corso all'avvio del processo è **una** interruzione: prenderne
    /// uno solo — come faceva la prima stesura, dichiarandolo — lascerebbe gli
    /// altri a dire «In corso» per sempre.
    ///
    /// L'ordine è per avvio, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn acquiring_sessions(&self) -> StorageResult<Vec<(SessionId, Timestamp)>> {
        let mut statement = self.connection.prepare(
            "SELECT id, started_at FROM sessions
             WHERE state IN ('running', 'paused') AND started_at IS NOT NULL
             ORDER BY started_at DESC, id DESC",
        )?;
        let righe =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;

        let mut trovate = Vec::new();
        for riga in righe {
            let (id, started_at) = riga?;
            trovate.push((SessionId::new(id), Timestamp::from_millis(started_at)));
        }
        Ok(trovate)
    }

    /// L'istante dell'ultimo contenuto acquisito da una sessione.
    ///
    /// `None` quando quella sessione non ha acquisito nulla: **non si inventa un
    /// istante**, e chi chiama dichiara da dove viene quello che usa al suo
    /// posto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn last_acquired_at(&self, session_id: SessionId) -> StorageResult<Option<Timestamp>> {
        let trovato: Option<i64> = self.connection.query_row(
            "SELECT MAX(acquired_at) FROM contents WHERE session_id = ?1",
            rusqlite::params![session_id.get()],
            |row| row.get(0),
        )?;

        Ok(trovato.map(Timestamp::from_millis))
    }

    /// Registra che l'operatore ha preso in carico un'interruzione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce o se l'interruzione era
    /// già stata presa in carico: riprenderla toglierebbe alla riga l'istante in
    /// cui qualcuno l'ha davvero letta.
    pub fn acknowledge_interruption(
        &mut self,
        session_id: SessionId,
        now: Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE session_interruptions SET acknowledged_at = ?2 WHERE session_id = ?1",
            rusqlite::params![session_id.get(), now.as_millis()],
        )?;
        Ok(())
    }

    /// Prende in carico l'interruzione della sessione **se ce n'è una aperta**,
    /// e dice se l'ha fatto.
    ///
    /// Serve all'arresto (ADR-0146): chi arresta un monitoraggio interrotto ha
    /// deciso che cosa farne, e l'avviso non deve tornare alla prossima
    /// apertura. Una sessione senza interruzione, o con una già presa in
    /// carico, non è un errore: non c'è nulla da fare, e la riga di chi l'ha
    /// letta prima conserva il proprio istante.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn acknowledge_open_interruption(
        &mut self,
        session_id: SessionId,
        now: Timestamp,
    ) -> StorageResult<bool> {
        let cambiate = self.connection.execute(
            "UPDATE session_interruptions SET acknowledged_at = ?2
             WHERE session_id = ?1 AND acknowledged_at IS NULL",
            rusqlite::params![session_id.get(), now.as_millis()],
        )?;
        Ok(cambiate > 0)
    }

    /// **Quanti** monitoraggi ricevono contenuti adesso: `in corso` o con gli
    /// avvisi sospesi, e **senza** un'interruzione in attesa di decisione.
    ///
    /// Distinto da [`Database::acquiring_session_count`], che conta lo stato
    /// scritto nell'archivio. Un monitoraggio interrotto resta «in corso»
    /// nell'archivio (ADR-0064) ma non riceve nulla finché l'operatore non
    /// decide (ADR-0146): tenere sveglia la postazione o dire «in corso» per lui
    /// sarebbe affermare un'acquisizione che non c'è (E2E01-22).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn receiving_session_count(&self) -> StorageResult<usize> {
        let quanti: i64 = self.connection.query_row(
            "SELECT count(*) FROM sessions AS s
             WHERE s.state IN ('running', 'paused')
               AND NOT EXISTS (
                   SELECT 1 FROM session_interruptions AS i
                   WHERE i.session_id = s.id AND i.acknowledged_at IS NULL
               )",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(quanti).unwrap_or(0))
    }
}

impl Database {
    /// Registra la chiusura ordinata: l'istante e lo stato della finestra
    /// (ADR-0195, migrazione 0089).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn record_orderly_closure(
        &self,
        closed_at: Timestamp,
        window_maximized: bool,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE orderly_closure SET closed_at = ?1, window_maximized = ?2 WHERE id = 1",
            rusqlite::params![closed_at.as_millis(), i64::from(window_maximized)],
        )?;
        Ok(())
    }

    /// Legge e svuota l'istante dell'ultima chiusura ordinata.
    ///
    /// # Perché la svuota
    ///
    /// Una chiusura vale soltanto per l'avvio che la segue. Se restasse, un
    /// arresto anomalo successivo farebbe cominciare il buco da una chiusura
    /// di prima, e la postazione risulterebbe cieca quando guardava.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o la scrittura non riescono.
    pub fn take_orderly_closure(&mut self) -> StorageResult<Option<Timestamp>> {
        let chiusura: Option<i64> = self.connection.query_row(
            "SELECT closed_at FROM orderly_closure WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        self.connection.execute(
            "UPDATE orderly_closure SET closed_at = NULL WHERE id = 1",
            [],
        )?;
        Ok(chiusura.map(Timestamp::from_millis))
    }

    /// Se la finestra era ingrandita all'ultima chiusura ordinata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn window_was_maximized(&self) -> StorageResult<bool> {
        let ingrandita: i64 = self.connection.query_row(
            "SELECT window_maximized FROM orderly_closure WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(ingrandita == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::database;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Una sessione vera, perché la tabella la riferisce.
    fn sessione(database: &mut Database) -> SessionId {
        use lisi_core::model::session::{NewSession, SessionDuration};
        use lisi_core::text::Actor;

        let (Ok(etichetta), Ok(attore)) = (
            lisi_core::text::DisplayName::try_new("monitoraggio di prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let Ok(id) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: attore,
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: Vec::new(),
            },
            istante(1_000),
        ) else {
            panic!("la sessione di prova deve potersi registrare");
        };
        id
    }

    /// **La chiusura come inizio del buco si registra e si rilegge**
    /// (ADR-0195): la migrazione 0089 la ammette.
    #[test]
    fn la_chiusura_come_inizio_del_buco_si_rilegge() {
        let mut database = database();
        let id = sessione(&mut database);
        let fatto = Interruption::new(istante(5_000), GapStart::OrderlyClose(istante(4_000)));
        let Ok(true) = database.record_interruption(id, &fatto) else {
            panic!("l'interruzione deve potersi registrare");
        };
        let Ok(Some(letta)) = database.open_interruption() else {
            panic!("l'interruzione aperta deve potersi rileggere");
        };
        assert_eq!(letta.interruption, fatto);
    }

    /// **La chiusura ordinata vale per un avvio solo, e la finestra resta
    /// ricordata** (ADR-0195).
    #[test]
    fn la_chiusura_si_legge_una_volta_e_la_finestra_resta() {
        let mut database = database();
        assert_eq!(database.take_orderly_closure().ok(), Some(None));
        assert_eq!(database.window_was_maximized().ok(), Some(false));

        let Ok(()) = database.record_orderly_closure(istante(7_000), true) else {
            panic!("la chiusura deve potersi registrare");
        };
        assert_eq!(
            database.take_orderly_closure().ok(),
            Some(Some(istante(7_000)))
        );
        assert_eq!(database.take_orderly_closure().ok(), Some(None));
        assert_eq!(database.window_was_maximized().ok(), Some(true));
    }

    /// **Il fatto si registra, e si rilegge.**
    #[test]
    fn un_interruzione_si_registra_e_si_rilegge() {
        let mut database = database();
        let id = sessione(&mut database);

        let fatto = Interruption::new(istante(5_000), GapStart::LastContent(istante(2_000)));
        let Ok(scritta) = database.record_interruption(id, &fatto) else {
            panic!("l'interruzione deve potersi registrare");
        };
        assert!(scritta);

        let Ok(Some(letta)) = database.open_interruption() else {
            panic!("l'interruzione aperta deve potersi rileggere");
        };
        assert_eq!(letta.session_id, id);
        assert_eq!(letta.interruption, fatto);
        assert_eq!(letta.acknowledged_at, None);
    }

    /// **Riaprire dieci volte non produce dieci interruzioni.**
    ///
    /// Il fatto è uno solo, e la seconda riapertura non deve poter cambiare
    /// l'istante in cui ci si è accorti la prima volta.
    #[test]
    fn riaprire_non_moltiplica_il_fatto() {
        let mut database = database();
        let id = sessione(&mut database);

        let prima = Interruption::new(istante(5_000), GapStart::LastContent(istante(2_000)));
        let Ok(true) = database.record_interruption(id, &prima) else {
            panic!("la prima registrazione deve riuscire e scrivere");
        };

        let seconda = Interruption::new(istante(9_000), GapStart::LastContent(istante(2_000)));
        let Ok(scritta) = database.record_interruption(id, &seconda) else {
            panic!("la seconda registrazione deve riuscire");
        };
        assert!(!scritta, "la seconda non scrive, e lo dice");

        let Ok(Some(letta)) = database.open_interruption() else {
            panic!("l'interruzione deve potersi rileggere");
        };
        assert_eq!(
            letta.interruption.noticed_at().as_millis(),
            5_000,
            "resta l'istante della prima volta"
        );
    }

    /// **Presa in carico, sparisce l'avviso e resta il fatto.**
    #[test]
    fn presa_in_carico_sparisce_l_avviso_e_resta_il_fatto() {
        let mut database = database();
        let id = sessione(&mut database);
        let fatto = Interruption::new(istante(5_000), GapStart::MonitoringStart(istante(1_000)));
        let Ok(_) = database.record_interruption(id, &fatto) else {
            panic!("l'interruzione deve potersi registrare");
        };

        let Ok(()) = database.acknowledge_interruption(id, istante(6_000)) else {
            panic!("la presa in carico deve riuscire");
        };

        let Ok(aperta) = database.open_interruption() else {
            panic!("la lettura deve riuscire");
        };
        assert!(aperta.is_none(), "l'avviso non si mostra più");

        let quante: i64 = database
            .connection
            .query_row("SELECT count(*) FROM session_interruptions", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        assert_eq!(quante, 1, "il fatto resta in archivio");
    }

    /// **Una presa in carico non si riprende.**
    #[test]
    fn una_presa_in_carico_non_si_riprende() {
        let mut database = database();
        let id = sessione(&mut database);
        let fatto = Interruption::new(istante(5_000), GapStart::LastContent(istante(2_000)));
        let Ok(_) = database.record_interruption(id, &fatto) else {
            panic!("l'interruzione deve potersi registrare");
        };
        let Ok(()) = database.acknowledge_interruption(id, istante(6_000)) else {
            panic!("la prima presa in carico deve riuscire");
        };

        assert!(
            database
                .acknowledge_interruption(id, istante(7_000))
                .is_err(),
            "riprenderla toglierebbe l'istante in cui qualcuno l'ha davvero letta"
        );
    }

    /// **L'arresto prende in carico solo un'interruzione aperta** (ADR-0146):
    /// senza interruzione non c'è nulla da fare, e una già letta conserva
    /// l'istante di chi l'ha letta.
    #[test]
    fn l_arresto_prende_in_carico_solo_un_interruzione_aperta() {
        let mut database = database();
        let id = sessione(&mut database);
        assert!(matches!(
            database.acknowledge_open_interruption(id, istante(4_000)),
            Ok(false)
        ));

        let fatto = Interruption::new(istante(5_000), GapStart::LastContent(istante(2_000)));
        let Ok(_) = database.record_interruption(id, &fatto) else {
            panic!("l'interruzione deve potersi registrare");
        };
        assert!(matches!(
            database.acknowledge_open_interruption(id, istante(6_000)),
            Ok(true)
        ));
        assert!(database.open_interruption().is_ok_and(|a| a.is_none()));
        assert!(matches!(
            database.acknowledge_open_interruption(id, istante(7_000)),
            Ok(false)
        ));
        let letta: Option<i64> = database
            .connection
            .query_row(
                "SELECT acknowledged_at FROM session_interruptions WHERE session_id = ?1",
                [id.get()],
                |row| row.get(0),
            )
            .unwrap_or(None);
        assert_eq!(letta, Some(6_000), "resta l'istante della prima lettura");
    }

    /// **Chi aspetta una decisione non riceve, e non si conta** (E2E01-22):
    /// la veglia e la Dashboard leggono questo numero, non lo stato scritto.
    #[test]
    fn un_monitoraggio_interrotto_non_conta_fra_chi_riceve() {
        use lisi_core::model::session::SessionState;

        let mut database = database();
        let interrotto = sessione(&mut database);
        let sano = sessione(&mut database);
        for id in [interrotto, sano] {
            let Ok(()) = database.update_session_state(id, SessionState::Running, istante(2_000))
            else {
                panic!("la sessione di prova deve potersi avviare");
            };
        }
        assert!(matches!(database.receiving_session_count(), Ok(2)));

        let fatto = Interruption::new(istante(5_000), GapStart::LastContent(istante(2_000)));
        let Ok(_) = database.record_interruption(interrotto, &fatto) else {
            panic!("l'interruzione deve potersi registrare");
        };
        assert!(matches!(database.acquiring_session_count(), Ok(2)));
        assert!(
            matches!(database.receiving_session_count(), Ok(1)),
            "il monitoraggio interrotto resta «in corso» nell'archivio, ma non riceve"
        );

        let Ok(true) = database.acknowledge_open_interruption(interrotto, istante(6_000)) else {
            panic!("la presa in carico deve riuscire");
        };
        assert!(matches!(database.receiving_session_count(), Ok(2)));
    }

    /// **Il fatto non si riscrive e non si cancella.**
    #[test]
    fn il_fatto_non_si_riscrive_ne_si_cancella() {
        let mut database = database();
        let id = sessione(&mut database);
        let fatto = Interruption::new(istante(5_000), GapStart::LastContent(istante(2_000)));
        let Ok(_) = database.record_interruption(id, &fatto) else {
            panic!("l'interruzione deve potersi registrare");
        };

        for sql in [
            "UPDATE session_interruptions SET noticed_at = 1",
            "UPDATE session_interruptions SET gap_start_at = 1",
            "UPDATE session_interruptions SET gap_start_origin = 'avvio'",
            "DELETE FROM session_interruptions",
        ] {
            assert!(
                database.connection.execute(sql, []).is_err(),
                "«{sql}» non doveva essere ammesso"
            );
        }
    }

    /// **Lo schema rifiuta una provenienza che non esiste.**
    #[test]
    fn lo_schema_rifiuta_una_provenienza_sconosciuta() {
        let mut database = database();
        let id = sessione(&mut database);

        assert!(
            database
                .connection
                .execute(
                    "INSERT INTO session_interruptions (
                         session_id, noticed_at, gap_start_at, gap_start_origin
                     ) VALUES (?1, 1, 1, 'indovinato')",
                    rusqlite::params![id.get()],
                )
                .is_err(),
            "una provenienza inventata non doveva essere ammessa"
        );
    }
}

//! Accorgersi, all'avvio, che un monitoraggio è stato interrotto.
//!
//! # Perché all'avvio, e una volta sola
//!
//! Perché l'osservazione avviene **dentro il processo**: una sessione che
//! risulta in corso quando il processo è appena partito è una sessione che
//! questo processo non sta osservando, e non ha mai osservato.
//!
//! Il rilevamento sta **prima** che l'interfaccia mostri qualunque cosa:
//! scoprirlo dopo significherebbe mostrare «In corso» per un istante, e un
//! istante basta a essere letto.
//!
//! # Che cosa questo modulo NON fa
//!
//! **Non tocca lo stato della sessione.** Portarla ad arrestata scriverebbe
//! «arrestata dall'operatore» su un atto che l'operatore non ha compiuto.
//!
//! **Non riprende il monitoraggio.** Una sessione decisa per due ore
//! diventerebbe una sessione che dura quanto la macchina resta accesa.
//!
//! **Non recupera nulla.** Recuperare archivia, e l'ufficio ha chiesto di dire
//! quanti ne mancano e chiedere conferma prima di partire.
//!
//! Le due strade esistono già entrambe, con le protezioni che hanno. Ciò che
//! mancava non era una funzione: era che qualcuno **sapesse di doverle usare**.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0064-UN-MONITORAGGIO-INTERROTTO-NON-E-UN-MONITORAGGIO-FERMATO.md`.

use lisi_core::model::interruption::{GapStart, Interruption};
use lisi_core::{SessionId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::interruption::StoredInterruption;

use crate::error::ServiceResult;

/// Cerca un monitoraggio interrotto e, se lo trova, lo registra.
///
/// Restituisce l'interruzione **aperta**, cioè non ancora presa in carico, che
/// può essere quella appena registrata o una di una riapertura precedente.
///
/// # Errori
///
/// Restituisce un errore se la lettura o la scrittura non riescono.
pub fn detect_on_startup(
    database: &mut Database,
    now: Timestamp,
) -> ServiceResult<Option<StoredInterruption>> {
    Ok(detect_all_on_startup(database, now)?.into_iter().next())
}

/// Cerca **tutti** i monitoraggi interrotti e li registra.
///
/// # Perché tutti, e non il più recente
///
/// Perché i monitoraggi possono essere più di uno (ADR-0065), e un arresto
/// anomalo ne interrompe **ciascuno**: registrarne uno solo lascerebbe gli altri
/// a dire «In corso» per sempre, che è esattamente il difetto che ADR-0064 ha
/// chiuso — moltiplicato.
///
/// Restituisce le interruzioni **aperte**, cioè non ancora prese in carico, che
/// possono essere quelle appena registrate o quelle di riaperture precedenti.
///
/// # Errori
///
/// Restituisce un errore se la lettura o la scrittura non riescono.
pub fn detect_all_on_startup(
    database: &mut Database,
    now: Timestamp,
) -> ServiceResult<Vec<StoredInterruption>> {
    // `record_interruption` non sovrascrive: una sessione che ha gia' il proprio
    // fatto lo conserva, con l'istante della prima volta. Non serve saltarla, e
    // saltarla richiederebbe una lettura in piu' per sessione.
    // LA CHIUSURA ORDINATA, SE C'E' STATA (ADR-0195). Si legge e si svuota una
    // volta sola, anche senza monitoraggi da guardare: vale per questo avvio e
    // per nessun altro.
    let chiusura = database.take_orderly_closure()?;
    for (session_id, started_at) in database.acquiring_sessions()? {
        // L'INIZIO DEL BUCO VIENE DALL'ARCHIVIO, NON DA UN OROLOGIO.
        //
        // Se la sessione non aveva acquisito nulla non si inventa un istante: si
        // usa l'avvio del monitoraggio, e si dichiara che viene da li'. Una
        // chiusura ordinata successiva a entrambi dice di piu': fino a li' la
        // postazione guardava (OBS-RST-1).
        let ultimo = database.last_acquired_at(session_id)?;
        let gap_start = match (chiusura, ultimo) {
            (Some(chiusa), _)
                if chiusa.as_millis() >= started_at.as_millis()
                    && ultimo.is_none_or(|l| chiusa.as_millis() >= l.as_millis()) =>
            {
                GapStart::OrderlyClose(chiusa)
            }
            (_, Some(last)) => GapStart::LastContent(last),
            (_, None) => GapStart::MonitoringStart(started_at),
        };

        database.record_interruption(session_id, &Interruption::new(now, gap_start))?;
    }

    Ok(database.open_interruptions()?)
}

/// Registra che l'operatore ha preso in carico l'interruzione.
///
/// **Sparisce l'avviso, non il fatto**: ciò che è stato visto resta in archivio.
///
/// # Errori
///
/// Restituisce un errore se la scrittura non riesce, o se l'interruzione era già
/// stata presa in carico.
pub fn acknowledge(
    database: &mut Database,
    session_id: SessionId,
    now: Timestamp,
) -> ServiceResult<()> {
    database.acknowledge_interruption(session_id, now)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::open_in_memory_database;

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("interruption.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| {
                let trimmed = riga.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn archivio() -> Database {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        database
    }

    /// Una sessione **in corso**, come la lascerebbe un arresto anomalo.
    fn sessione_in_corso(database: &mut Database) -> SessionId {
        use lisi_core::model::session::{NewSession, SessionDuration, SessionState};
        use lisi_core::text::{Actor, DisplayName};

        let (Ok(etichetta), Ok(attore)) = (
            DisplayName::try_new("monitoraggio di prova"),
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
        let Ok(()) = database.update_session_state(id, SessionState::Running, istante(2_000))
        else {
            panic!("l'avvio deve riuscire");
        };
        id
    }

    /// **Senza monitoraggi in corso non c'è nulla da dire.**
    #[test]
    fn senza_monitoraggi_in_corso_non_c_e_nulla_da_dire() {
        let mut database = archivio();
        let Ok(esito) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("il rilevamento deve riuscire");
        };
        assert!(esito.is_none());
    }

    /// **Una sessione in corso all'avvio è una sessione interrotta.**
    ///
    /// L'osservazione avviene dentro il processo: se il processo è appena
    /// partito, nessuno la stava osservando.
    #[test]
    fn una_sessione_in_corso_all_avvio_e_interrotta() {
        let mut database = archivio();
        let id = sessione_in_corso(&mut database);

        let Ok(Some(trovata)) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("l'interruzione doveva essere rilevata");
        };
        assert_eq!(trovata.session_id, id);
        assert_eq!(trovata.interruption.noticed_at().as_millis(), 9_000);
    }

    /// **Con gli avvisi sospesi il monitoraggio acquisisce, dunque può essere
    /// interrotto** (MFX01-A). Fino al 2026-10-17 la domanda chiedeva soltanto
    /// `running`, e un arresto anomalo in questo stato passava sotto silenzio.
    #[test]
    fn una_sessione_con_gli_avvisi_sospesi_all_avvio_e_interrotta() {
        use lisi_core::model::session::SessionState;

        let mut database = archivio();
        let id = sessione_in_corso(&mut database);
        let Ok(()) = database.update_session_state(id, SessionState::Paused, istante(3_000)) else {
            panic!("la sospensione degli avvisi deve riuscire");
        };

        let Ok(Some(trovata)) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("l'interruzione doveva essere rilevata anche con gli avvisi sospesi");
        };
        assert_eq!(trovata.session_id, id);
    }

    /// **Lo stato della sessione non si tocca.**
    ///
    /// È la milestone: portarla ad «arrestata» scriverebbe «arrestata
    /// dall'operatore» su un atto che l'operatore non ha compiuto.
    #[test]
    fn lo_stato_della_sessione_non_si_tocca() {
        use lisi_core::model::session::SessionState;

        let mut database = archivio();
        let id = sessione_in_corso(&mut database);
        let Ok(_) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("il rilevamento deve riuscire");
        };

        let Ok(sessione) = database.session(id) else {
            panic!("la sessione deve potersi rileggere");
        };
        assert_eq!(
            sessione.state,
            SessionState::Running,
            "nessuno l'ha fermata, e l'archivio non deve dire il contrario"
        );
    }

    /// **Senza contenuti, l'inizio del buco è l'avvio del monitoraggio, e lo
    /// dichiara.**
    #[test]
    fn senza_contenuti_l_inizio_del_buco_e_l_avvio_e_lo_dichiara() {
        let mut database = archivio();
        let _ = sessione_in_corso(&mut database);

        let Ok(Some(trovata)) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("l'interruzione doveva essere rilevata");
        };
        assert!(matches!(
            trovata.interruption.gap_start(),
            GapStart::MonitoringStart(_)
        ));
        assert_eq!(
            trovata.interruption.gap_start().instant().as_millis(),
            2_000,
            "l'avvio del monitoraggio"
        );
    }

    /// **Dopo una chiusura ordinata il buco comincia dalla chiusura**
    /// (OBS-RST-1, ADR-0195), e la chiusura non vale per l'avvio successivo.
    #[test]
    fn dopo_una_chiusura_ordinata_il_buco_comincia_dalla_chiusura() {
        let mut database = archivio();
        let _ = sessione_in_corso(&mut database);
        let Ok(()) = database.record_orderly_closure(istante(6_000), false) else {
            panic!("la chiusura deve potersi registrare");
        };

        let Ok(Some(trovata)) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("l'interruzione doveva essere rilevata");
        };
        assert_eq!(
            trovata.interruption.gap_start(),
            GapStart::OrderlyClose(istante(6_000))
        );
        assert_eq!(database.take_orderly_closure().ok(), Some(None));
    }

    /// **Una chiusura precedente all'avvio del monitoraggio non conta**: non
    /// è la fine dell'osservazione di questo monitoraggio.
    #[test]
    fn una_chiusura_di_prima_dell_avvio_non_conta() {
        let mut database = archivio();
        let _ = sessione_in_corso(&mut database);
        let Ok(()) = database.record_orderly_closure(istante(1_500), false) else {
            panic!("la chiusura deve potersi registrare");
        };

        let Ok(Some(trovata)) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("l'interruzione doveva essere rilevata");
        };
        assert!(matches!(
            trovata.interruption.gap_start(),
            GapStart::MonitoringStart(_)
        ));
    }

    /// **Riaprire non moltiplica il fatto, e non ne cambia l'istante.**
    #[test]
    fn riaprire_non_cambia_l_istante_in_cui_ci_si_e_accorti() {
        let mut database = archivio();
        let _ = sessione_in_corso(&mut database);

        let Ok(_) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("il primo rilevamento deve riuscire");
        };
        let Ok(Some(seconda)) = detect_on_startup(&mut database, istante(20_000)) else {
            panic!("il secondo rilevamento deve riuscire");
        };
        assert_eq!(
            seconda.interruption.noticed_at().as_millis(),
            9_000,
            "resta l'istante della prima volta"
        );
    }

    /// **Due monitoraggi in corso all'avvio sono DUE interruzioni.**
    ///
    /// È la milestone MULTI-02 applicata qui: registrarne una sola lascerebbe
    /// l'altra a dire «In corso» per sempre — il difetto di ADR-0064,
    /// moltiplicato.
    #[test]
    fn due_monitoraggi_in_corso_sono_due_interruzioni() {
        let mut database = archivio();
        let primo = sessione_in_corso(&mut database);
        let secondo = sessione_in_corso(&mut database);
        assert_ne!(primo, secondo);

        let Ok(trovate) = detect_all_on_startup(&mut database, istante(9_000)) else {
            panic!("il rilevamento deve riuscire");
        };
        assert_eq!(
            trovate.len(),
            2,
            "ciascun monitoraggio porta il proprio fatto"
        );

        let sessioni: Vec<_> = trovate.iter().map(|fatto| fatto.session_id).collect();
        assert!(sessioni.contains(&primo));
        assert!(sessioni.contains(&secondo));
    }

    /// **Prenderne in carico una non fa sparire l'altra.**
    #[test]
    fn prendere_in_carico_una_non_fa_sparire_l_altra() {
        let mut database = archivio();
        let primo = sessione_in_corso(&mut database);
        let _secondo = sessione_in_corso(&mut database);
        let Ok(_) = detect_all_on_startup(&mut database, istante(9_000)) else {
            panic!("il rilevamento deve riuscire");
        };

        let Ok(()) = acknowledge(&mut database, primo, istante(10_000)) else {
            panic!("la presa in carico deve riuscire");
        };

        let Ok(restanti) = detect_all_on_startup(&mut database, istante(11_000)) else {
            panic!("il rilevamento deve riuscire");
        };
        assert_eq!(restanti.len(), 1, "l'altra resta da guardare");
        assert_ne!(restanti[0].session_id, primo);
    }

    /// **Presa in carico, l'avviso non torna.**
    #[test]
    fn presa_in_carico_l_avviso_non_torna() {
        let mut database = archivio();
        let id = sessione_in_corso(&mut database);
        let Ok(_) = detect_on_startup(&mut database, istante(9_000)) else {
            panic!("il rilevamento deve riuscire");
        };

        let Ok(()) = acknowledge(&mut database, id, istante(10_000)) else {
            panic!("la presa in carico deve riuscire");
        };

        let Ok(dopo) = detect_on_startup(&mut database, istante(30_000)) else {
            panic!("il rilevamento deve riuscire");
        };
        assert!(
            dopo.is_none(),
            "una volta letta, l'interruzione non si riannuncia"
        );
    }

    /// **Il rilevamento non riprende e non recupera.**
    ///
    /// Riprendere cambierebbe la durata decisa; recuperare archivierebbe senza
    /// che nessuno lo abbia chiesto.
    #[test]
    fn il_rilevamento_non_riprende_e_non_recupera() {
        let codice = codice_di_produzione();
        for vietato in [
            "update_session_state",
            "SessionState",
            "survey",
            "apply",
            "recovery::",
            "AcquisitionService",
        ] {
            assert!(
                !codice.contains(vietato),
                "accorgersi non è ripartire: il rilevamento non deve nominare «{vietato}»"
            );
        }
    }
}

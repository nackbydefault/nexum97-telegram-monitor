//! Atti di valutazione di un soggetto (PERS-05).
//!
//! # Che cosa questo modulo non fa
//!
//! Non propone un livello. Non legge i contenuti, non legge gli alert, non ha
//! alcuna funzione che guardi un dato e ne ricavi un giudizio: **il livello
//! arriva da chi lo ha deciso, o non arriva.**
//!
//! Una valutazione proposta dal programma sarebbe una valutazione automatica,
//! comunque la si chiamasse — «suggerimento», «bozza», «predefinito» — e il
//! congelamento la vieta.
//!
//! # Si aggiunge, non si cambia
//!
//! Non c'è una funzione che aggiorni una valutazione, e non c'è una funzione che
//! ne cancelli una: due trigger le rifiutano, e valgono anche per chi scrivesse
//! un secondo servizio domani.
//!
//! La valutazione corrente **si ricava** dall'atto più recente, e la storia non
//! si accorcia.

use core::str::FromStr;

use lisi_core::model::assessment::{AssessedLevel, AssessmentAct, AssessmentEntry, NewAssessment};
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::Actor;
use lisi_core::{AssessmentId, PersonId};

use crate::database::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// Traduce l'etichetta conservata nell'atto del dominio.
///
/// # Perché una funzione e non un `FromStr` sull'atto
///
/// Perché `AssessmentAct` porta un livello dentro una variante, e la
/// conversione inversa passa comunque da qui: tenerla in un posto solo evita che
/// due letture dello stesso testo divergano.
fn act_from_str(raw: &str) -> StorageResult<AssessmentAct> {
    if raw == "ritirata" {
        return Ok(AssessmentAct::Withdraw);
    }
    Ok(AssessmentAct::Assess(AssessedLevel::from_str(raw)?))
}

impl Database {
    /// Registra un atto di valutazione.
    ///
    /// # Perché non esiste un `update_assessment`
    ///
    /// Perché una valutazione non si cambia: se ne registra una nuova. Un
    /// aggiornamento cancellerebbe chi aveva valutato prima e perché, che è
    /// precisamente ciò che chi rilegge un fascicolo deve poter vedere.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il soggetto non esiste, se è **chiuso** — un
    /// trigger lo rifiuta — o se la scrittura non riesce.
    pub fn insert_assessment(&self, assessment: &NewAssessment) -> StorageResult<AssessmentId> {
        self.connection.execute(
            "INSERT INTO subject_assessments (person_id, act, reason, assessed_by, assessed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                assessment.person.get(),
                assessment.act.as_str(),
                assessment.reason.as_str(),
                assessment.by.as_str(),
                millis(assessment.at),
            ],
        )?;
        Ok(AssessmentId::new(self.connection.last_insert_rowid()))
    }

    /// La storia degli atti di valutazione di un soggetto, dal più antico.
    ///
    /// # Perché tutta la storia e non solo l'ultimo
    ///
    /// Perché la valutazione di oggi, da sola, non dice come ci si è arrivati.
    /// Un fascicolo alzato a «priorità alta» e poi ritirato racconta qualcosa che
    /// «NON VALUTATO» da solo non racconta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn assessment_history(&self, person: PersonId) -> StorageResult<Vec<AssessmentEntry>> {
        let mut statement = self.connection.prepare(
            "SELECT id, person_id, act, reason, assessed_by, assessed_at
             FROM subject_assessments
             WHERE person_id = ?1
             ORDER BY assessed_at ASC, id ASC",
        )?;
        // ORDINE ESPLICITO, con criterio secondario: due atti nello stesso
        // millisecondo darebbero altrimenti due storie diverse a due letture.
        let grezze: Vec<(i64, i64, String, String, String, i64)> = statement
            .query_map([person.get()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut voci = Vec::with_capacity(grezze.len());
        for (id, person_id, act, reason, by, at) in grezze {
            voci.push(AssessmentEntry {
                id: AssessmentId::new(id),
                person: PersonId::new(person_id),
                act: act_from_str(&act)?,
                reason: OperationalReason::try_new(&reason)?,
                by: Actor::try_new(&by)?,
                at: instant(at),
            });
        }
        Ok(voci)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::assessment::{
        AssessedLevel, AssessmentAct, NewAssessment, current_assessment,
    };
    use lisi_core::model::person::NewPerson;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::{Actor, DisplayName};
    use lisi_core::{PersonId, Timestamp};

    use crate::test_support::database_with_session;

    const ORA: i64 = 1_760_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn attore() -> Actor {
        let Ok(valore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore deve essere valido");
        };
        valore
    }

    fn ragione(testo: &str) -> OperationalReason {
        let Ok(valore) = OperationalReason::try_new(testo) else {
            panic!("la ragione di prova deve essere valida");
        };
        valore
    }

    /// Un archivio con un soggetto aperto.
    fn archivio_con_soggetto() -> (crate::Database, PersonId) {
        let (database, _, _) = database_with_session();
        let Ok(etichetta) = DisplayName::try_new("Soggetto di prova") else {
            panic!("l'etichetta deve essere valida");
        };
        let Ok(person_id) = database.insert_person(
            &NewPerson::open(
                etichetta,
                ragione("richiesta dell'autorita' procedente del 4 marzo"),
            ),
            &attore(),
            istante(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };
        (database, person_id)
    }

    /// **Un atto si registra, e la storia lo restituisce.**
    #[test]
    fn un_atto_si_registra_e_la_storia_lo_restituisce() {
        let (database, person) = archivio_con_soggetto();

        let Ok(_) = database.insert_assessment(&NewAssessment {
            person,
            act: AssessmentAct::Assess(AssessedLevel::OfInterest),
            reason: ragione("compare in tre fonti del procedimento in corso"),
            by: attore(),
            at: istante(ORA + 100),
        }) else {
            panic!("l'atto deve potersi registrare");
        };

        let Ok(storia) = database.assessment_history(person) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia.len(), 1);
        assert_eq!(
            storia[0].act,
            AssessmentAct::Assess(AssessedLevel::OfInterest)
        );

        let corrente = current_assessment(&storia);
        assert!(corrente.is_assessed());
        assert_eq!(corrente.as_label(), "DI INTERESSE");
    }

    /// **Un atto di valutazione non si riscrive.**
    ///
    /// # Perché conta
    ///
    /// Perché porta un nome, un motivo e un istante: cambiarne uno li farebbe
    /// mentire tutti e tre insieme.
    #[test]
    fn un_atto_non_si_riscrive() {
        let (database, person) = archivio_con_soggetto();
        let Ok(id) = database.insert_assessment(&NewAssessment {
            person,
            act: AssessmentAct::Assess(AssessedLevel::HighPriority),
            reason: ragione("richiesta esplicita dell'autorita' procedente"),
            by: attore(),
            at: istante(ORA + 100),
        }) else {
            panic!("l'atto deve potersi registrare");
        };

        let esito = database.connection.execute(
            "UPDATE subject_assessments SET act = 'da_approfondire' WHERE id = ?1",
            [id.get()],
        );
        assert!(esito.is_err(), "il trigger deve rifiutare la riscrittura");
    }

    /// **Un atto di valutazione non si cancella.**
    #[test]
    fn un_atto_non_si_cancella() {
        let (database, person) = archivio_con_soggetto();
        let Ok(id) = database.insert_assessment(&NewAssessment {
            person,
            act: AssessmentAct::Assess(AssessedLevel::HighPriority),
            reason: ragione("richiesta esplicita dell'autorita' procedente"),
            by: attore(),
            at: istante(ORA + 100),
        }) else {
            panic!("l'atto deve potersi registrare");
        };

        let esito = database
            .connection
            .execute("DELETE FROM subject_assessments WHERE id = ?1", [id.get()]);
        assert!(esito.is_err(), "il trigger deve rifiutare la cancellazione");
    }

    /// **Una ragione troppo corta non entra nell'archivio.**
    ///
    /// # Perché anche qui, e non solo nel dominio
    ///
    /// Perché il dominio protegge chi passa dal dominio, e il vincolo
    /// dell'archivio protegge da un secondo servizio scritto domani.
    #[test]
    fn una_ragione_troppo_corta_non_entra() {
        let (database, person) = archivio_con_soggetto();
        let esito = database.connection.execute(
            "INSERT INTO subject_assessments (person_id, act, reason, assessed_by, assessed_at)
             VALUES (?1, 'priorita_alta', 'boh', 'x', ?2)",
            rusqlite::params![person.get(), ORA],
        );
        assert!(esito.is_err(), "il CHECK deve rifiutare una ragione vuota");
    }

    /// **«non_valutato» non è un atto registrabile.**
    ///
    /// # Perché conta
    ///
    /// Perché non è un giudizio: ammetterlo permetterebbe di registrare un atto
    /// che non dice niente, e di far sembrare valutato un soggetto che non lo è.
    #[test]
    fn non_valutato_non_e_un_atto_registrabile() {
        let (database, person) = archivio_con_soggetto();
        let esito = database.connection.execute(
            "INSERT INTO subject_assessments (person_id, act, reason, assessed_by, assessed_at)
             VALUES (?1, 'non_valutato', 'una ragione lunga abbastanza per passare', 'x', ?2)",
            rusqlite::params![person.get(), ORA],
        );
        assert!(esito.is_err(), "il CHECK deve rifiutare un atto neutro");
    }

    /// **Un soggetto chiuso non si valuta.**
    #[test]
    fn un_soggetto_chiuso_non_si_valuta() {
        let (database, person) = archivio_con_soggetto();
        let Ok(()) = database.close_person(
            person,
            &attore(),
            &ragione("il procedimento si e' concluso senza rilievi"),
            istante(ORA + 50),
        ) else {
            panic!("il soggetto deve potersi chiudere");
        };

        let esito = database.insert_assessment(&NewAssessment {
            person,
            act: AssessmentAct::Assess(AssessedLevel::HighPriority),
            reason: ragione("richiesta esplicita dell'autorita' procedente"),
            by: attore(),
            at: istante(ORA + 100),
        });
        assert!(
            esito.is_err(),
            "il trigger deve rifiutare la valutazione di un soggetto chiuso"
        );
    }

    /// **La tabella non ha colonne numeriche oltre agli identificativi e
    /// all'istante.**
    ///
    /// # Perché la guardia legge lo schema
    ///
    /// Perché il congelamento vieta un punteggio «in nessuna forma e nemmeno
    /// spento»: una colonna aggiunta domani e mai riempita sarebbe comunque il
    /// posto in cui un punteggio può stare.
    #[test]
    fn la_tabella_non_ha_una_colonna_in_cui_un_punteggio_possa_stare() {
        const SCHEMA: &str = include_str!("../../migrations/0032_subject_assessments.sql");
        let Some(inizio) = SCHEMA.find("CREATE TABLE subject_assessments (") else {
            panic!("la tabella deve esistere");
        };
        let Some(fine) = SCHEMA[inizio..].find("\n);") else {
            panic!("la tabella deve chiudersi");
        };
        let corpo = &SCHEMA[inizio..inizio + fine];

        let numeriche: Vec<&str> = corpo
            .lines()
            .map(str::trim)
            .filter(|riga| !riga.starts_with("--"))
            .filter(|riga| riga.contains(" INTEGER") || riga.contains(" REAL"))
            .collect();

        // LE SOLE AMMESSE: l'identificativo della riga, quello del soggetto e
        // l'istante. Nessuna delle tre e' una misura di una persona.
        assert_eq!(
            numeriche.len(),
            3,
            "le colonne numeriche devono restare tre \u{2014} {numeriche:?}"
        );
        for attesa in ["id INTEGER", "person_id INTEGER", "assessed_at INTEGER"] {
            assert!(
                numeriche.iter().any(|riga| riga.starts_with(attesa)),
                "manca «{attesa}» fra le colonne numeriche ammesse"
            );
        }
        assert!(
            !corpo.contains(" REAL"),
            "una colonna REAL accanto a una persona e' una probabilita'"
        );
    }
}

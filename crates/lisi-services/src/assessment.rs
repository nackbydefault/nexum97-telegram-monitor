//! Valutazione umana di un soggetto (PERS-05).
//!
//! # Perché questo servizio scrive, a differenza degli altri della Fase 6
//!
//! Perché una valutazione **non si osserva: si decide**.
//!
//! I servizi di PERS-02, PERS-03 e PERS-04 ricavano ciò che l'archivio ha già
//! visto, e per questo non scrivono nulla. Qui c'è un atto umano, e un atto umano
//! va registrato con chi lo ha compiuto, quando e perché — altrimenti fra sei
//! mesi nessuno saprà di chi era quel giudizio.
//!
//! # La ragione è un'altra, e non è quella degli elenchi
//!
//! ADR-0024 autorizza a **guardare** un elenco di persone: vale una volta e
//! riguarda l'ufficio.
//!
//! Qui si **scrive un giudizio su una persona specifica**, e il motivo riguarda
//! quella persona, quel giorno, quel livello. Confonderle sarebbe il difetto
//! peggiore possibile: chi ha motivato una volta l'accesso agli elenchi si
//! troverebbe autorizzato a valutare chiunque senza scrivere altro.
//!
//! È la stessa distinzione che PERS-01 fa per la ragione di apertura di un
//! fascicolo, e qui vale a maggior ragione.
//!
//! # Che cosa questo servizio non fa, e non farà
//!
//! Non propone un livello. Non guarda i contenuti, non guarda gli alert, non ha
//! alcuna funzione che ricavi un giudizio da un dato: **il livello arriva da chi
//! lo ha deciso, o non arriva.**
//!
//! Una valutazione proposta dal programma sarebbe una valutazione automatica,
//! comunque la si chiamasse — «suggerimento», «bozza», «predefinito».

use lisi_core::model::assessment::{
    AssessmentAct, AssessmentEntry, NewAssessment, SubjectAssessment, current_assessment,
};
use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{AssessmentId, PersonId, Timestamp};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// L'azione di audit con cui si registra un atto di valutazione.
///
/// # Perché una sola azione per valutare e ritirare
///
/// Perché sono lo stesso genere di atto — qualcuno ha deciso qualcosa su un
/// fascicolo — e il **dettaglio** dice quale. Due azioni distinte
/// costringerebbero chi legge l'audit a cercarne due per ricostruire una storia
/// sola.
const AZIONE: &str = "soggetto_valutato";

/// Servizio della valutazione umana.
#[derive(Debug)]
pub struct AssessmentService {
    database: Database,
}

impl AssessmentService {
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

    /// Registra un atto di valutazione, con la sua voce di audit.
    ///
    /// # Perché prende l'atto e non un livello e un booleano
    ///
    /// Perché un livello più un «ritirato: sì/no» renderebbe esprimibile
    /// «priorità alta, ritirata», che non significa niente. L'atto è **uno dei
    /// due**, e il tipo lo dice.
    ///
    /// # Perché la ragione è un tipo e non una stringa
    ///
    /// Perché così **non si può chiamare senza**. Una convalida dentro la
    /// funzione si dimentica in un secondo servizio; un parametro che esiste
    /// solo se qualcuno ha scritto abbastanza, no. È la scelta di PERS-01.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il soggetto non esiste, se è **chiuso** — un
    /// trigger lo rifiuta — o se la scrittura non riesce.
    pub fn record(
        &self,
        person: PersonId,
        act: AssessmentAct,
        reason: &OperationalReason,
        by: &Actor,
        at: Timestamp,
    ) -> ServiceResult<AssessmentId> {
        let id = self.database.insert_assessment(&NewAssessment {
            person,
            act,
            reason: reason.clone(),
            by: by.clone(),
            at,
        })?;

        // L'AUDIT PORTA L'IDENTIFICATIVO E L'ATTO, NON LA RAGIONE.
        //
        // La ragione sta sulla riga della valutazione, dove chi rilegge il
        // fascicolo la trova accanto al giudizio che spiega. Duplicarla
        // nell'audit creerebbe due copie che il giorno in cui una si muovesse
        // divergerebbero — ed e' la scelta gia' fatta da PERS-01.
        self.database.append_audit(&NewAuditEntry {
            actor: by.clone(),
            action: AuditAction::try_new(AZIONE)?,
            entity: AuditEntity::try_new("person")?,
            entity_id: Some(person.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(act.as_str())?),
            recorded_at: at,
        })?;

        Ok(id)
    }

    /// La valutazione corrente di un soggetto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn current(&self, person: PersonId) -> ServiceResult<SubjectAssessment> {
        Ok(current_assessment(&self.history(person)?))
    }

    /// La storia degli atti di valutazione, dal più antico.
    ///
    /// # Perché la storia è pubblica quanto la valutazione
    ///
    /// Perché la valutazione di oggi, da sola, non dice come ci si è arrivati.
    /// Un fascicolo alzato a «priorità alta» e poi ritirato racconta qualcosa che
    /// «NON VALUTATO» da solo non racconta — e chi rilegge deve poterlo vedere.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn history(&self, person: PersonId) -> ServiceResult<Vec<AssessmentEntry>> {
        Ok(self.database.assessment_history(person)?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::assessment::{AssessedLevel, AssessmentAct};
    use lisi_core::model::person::NewPerson;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::{Actor, DisplayName};
    use lisi_core::{PersonId, Timestamp};
    use lisi_storage::Database;

    use super::AssessmentService;
    use crate::sources::open_in_memory_database;

    const ORA: i64 = 1_760_000_000_000;

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

    fn servizio() -> (AssessmentService, PersonId) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let database: Database = database;
        let Ok(etichetta) = DisplayName::try_new("Soggetto di prova") else {
            panic!("l'etichetta deve essere valida");
        };
        let Ok(person) = database.insert_person(
            &NewPerson::open(
                etichetta,
                ragione("richiesta dell'autorita' procedente del 4 marzo"),
            ),
            &attore(),
            Timestamp::from_millis(ORA),
        ) else {
            panic!("il soggetto deve potersi aprire");
        };
        (AssessmentService::new(database), person)
    }

    /// **Un atto di valutazione lascia una voce di audit.**
    ///
    /// # Perché conta
    ///
    /// Perché il congelamento chiede operatore, motivo, istante **e audit**: i
    /// primi tre stanno sulla riga, il quarto è ciò che permette di ritrovare
    /// l'atto partendo da chi lo ha compiuto invece che dal fascicolo.
    #[test]
    fn un_atto_lascia_una_voce_di_audit() {
        let (servizio, person) = servizio();

        let Ok(_) = servizio.record(
            person,
            AssessmentAct::Assess(AssessedLevel::OfInterest),
            &ragione("compare in tre fonti del procedimento in corso"),
            &attore(),
            Timestamp::from_millis(ORA + 100),
        ) else {
            panic!("l'atto deve potersi registrare");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            voci.iter()
                .any(|voce| voce.action.as_str() == "soggetto_valutato"),
            "l'azione deve comparire nell'audit"
        );
    }

    /// **La ragione sta sulla riga, non nell'audit.**
    ///
    /// # Perché conta
    ///
    /// Perché due copie della stessa frase divergono il giorno in cui una si
    /// muove senza l'altra. È la scelta già fatta da PERS-01.
    #[test]
    fn la_ragione_sta_sulla_riga_non_nell_audit() {
        let (servizio, person) = servizio();
        const RAGIONE: &str = "compare in tre fonti del procedimento in corso";

        let Ok(_) = servizio.record(
            person,
            AssessmentAct::Assess(AssessedLevel::OfInterest),
            &ragione(RAGIONE),
            &attore(),
            Timestamp::from_millis(ORA + 100),
        ) else {
            panic!("l'atto deve potersi registrare");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            !voci.iter().any(|voce| voce
                .detail
                .as_ref()
                .is_some_and(|d| d.as_str().contains("tre fonti"))),
            "la ragione non si duplica nell'audit"
        );

        let Ok(storia) = servizio.history(person) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia[0].reason.as_str(), RAGIONE, "sta sulla riga");
    }

    /// **Valutare non prende una stringa come ragione.**
    ///
    /// # Perché conta
    ///
    /// Perché una stringa si può passare vuota, e la convalida si può dimenticare
    /// in un secondo servizio. Il tipo esiste solo se qualcuno ha scritto
    /// abbastanza.
    #[test]
    fn valutare_non_prende_una_stringa_come_ragione() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("reason: &OperationalReason"),
            "la ragione deve essere il tipo del dominio"
        );
        assert!(
            !codice.contains("reason: &str"),
            "una ragione come stringa si puo' passare vuota"
        );
    }

    /// **La ragione di ADR-0024 non autorizza a valutare.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Chi ha motivato una volta l'accesso agli elenchi si troverebbe
    /// autorizzato a scrivere un giudizio su chiunque senza scrivere altro. Sono
    /// due autorizzazioni diverse, e questa milestone non deve accettare la
    /// prima al posto della seconda.
    #[test]
    fn la_ragione_degli_elenchi_non_autorizza_a_valutare() {
        let codice = codice_senza_commenti();
        assert!(
            !codice.contains("elenco_persone_motivato"),
            "il servizio legge la ragione degli elenchi: sono due autorizzazioni diverse"
        );
        assert!(
            !codice.contains("basis_recorded"),
            "valutare non passa dalla ragione degli elenchi"
        );
    }

    /// **Il servizio non propone e non calcola un livello.**
    ///
    /// # Perché è la guardia più importante di questa milestone
    ///
    /// Perché una valutazione proposta dal programma **è** una valutazione
    /// automatica, comunque la si chiami. Il congelamento la vieta, e qui non
    /// esiste la forma: l'unico modo di ottenere un livello è che qualcuno lo
    /// passi.
    #[test]
    fn il_servizio_non_propone_e_non_calcola_un_livello() {
        let codice = codice_senza_commenti();
        for automatismo in [
            "fn suggest",
            "fn propose",
            "fn suggerisci",
            "fn calcola",
            "fn infer",
            "session_contents",
            "content_alert",
            "AnalysisLevel",
            "AlertLevel",
        ] {
            assert!(
                !codice.contains(automatismo),
                "il servizio nomina «{automatismo}»: un livello proposto dal programma e' una \
                 valutazione automatica"
            );
        }
    }

    /// **Non esiste un modo di cambiare o cancellare un atto.**
    #[test]
    fn non_esiste_un_modo_di_cambiare_o_cancellare_un_atto() {
        let codice = codice_senza_commenti();
        for scrittura in [
            "update_assessment",
            "delete_assessment",
            "fn update",
            "fn delete",
        ] {
            assert!(
                !codice.contains(scrittura),
                "il servizio nomina «{scrittura}»: una valutazione non si cambia, se ne registra \
                 una nuova"
            );
        }
    }

    /// **Un soggetto chiuso non si valuta, e l'errore arriva al chiamante.**
    #[test]
    fn un_soggetto_chiuso_non_si_valuta() {
        let (servizio, person) = servizio();
        let Ok(()) = servizio.database().close_person(
            person,
            &attore(),
            &ragione("il procedimento si e' concluso senza rilievi"),
            Timestamp::from_millis(ORA + 50),
        ) else {
            panic!("il soggetto deve potersi chiudere");
        };

        let esito = servizio.record(
            person,
            AssessmentAct::Assess(AssessedLevel::HighPriority),
            &ragione("richiesta esplicita dell'autorita' procedente"),
            &attore(),
            Timestamp::from_millis(ORA + 100),
        );
        assert!(esito.is_err(), "un soggetto chiuso non si valuta");
    }

    /// **La storia racconta come ci si è arrivati.**
    #[test]
    fn la_storia_racconta_come_ci_si_e_arrivati() {
        let (servizio, person) = servizio();

        for (act, quando) in [
            (
                AssessmentAct::Assess(AssessedLevel::HighPriority),
                ORA + 100,
            ),
            (AssessmentAct::Withdraw, ORA + 200),
        ] {
            let Ok(_) = servizio.record(
                person,
                act,
                &ragione("rivalutazione dopo il riscontro con l'autorita' procedente"),
                &attore(),
                Timestamp::from_millis(quando),
            ) else {
                panic!("l'atto deve potersi registrare");
            };
        }

        let Ok(corrente) = servizio.current(person) else {
            panic!("la valutazione corrente deve potersi leggere");
        };
        assert!(!corrente.is_assessed(), "ritirata: torna a NON VALUTATO");

        let Ok(storia) = servizio.history(person) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia.len(), 2, "la storia NON si accorcia");
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("assessment.rs");
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

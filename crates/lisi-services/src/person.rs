//! Aprire e chiudere un soggetto investigativo (PERS-01).
//!
//! # La guardia della Fase 6, e dove sta
//!
//! «Nessun profilo creato automaticamente per ogni utente che compare in una
//! fonte monitorata.»
//!
//! Il modo di rispettarla non è ricordarsene: **questo servizio non ha alcun
//! modo di raggiungere le osservazioni**. Non nomina i contenuti, non nomina i
//! partecipanti, e non ha una funzione che prenda un autore osservato e ne apra
//! il fascicolo. Una guardia lo verifica cercando quelle parole nel sorgente —
//! la stessa forma con cui CTX-06 impedisce che il conservare osservi.
//!
//! # Una ragione per **questo** soggetto
//!
//! La ragione degli elenchi di persone (ADR-0024) vale una volta e riguarda
//! l'ufficio. Non autorizza ad aprire un fascicolo su un nome: trattarle come la
//! stessa cosa lascerebbe che una frase scritta un anno fa giustifichi ogni
//! soggetto aperto da allora.
//!
//! Il tipo lo impone: aprire prende una `NewPerson`, che **esiste solo** se
//! qualcuno ha scritto una ragione. Non c'è una convalida da dimenticare.
//!
//! # Che cosa questo servizio non farà mai
//!
//! Valutare. Non c'è un punteggio, non c'è un livello, e non c'è un campo in cui
//! possano stare. La valutazione umana arriva con PERS-05: quattro stati con un
//! nome, e un atto di un operatore con motivo, istante e audit.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::person::{NewPerson, Person};
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{PersonId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Servizio dei soggetti investigativi.
#[derive(Debug)]
pub struct PersonService {
    database: Database,
}

impl PersonService {
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

    /// Apre un soggetto.
    ///
    /// # Perché non c'è un parametro «ragione»
    ///
    /// Perché la ragione è **dentro** [`NewPerson`], che non si costruisce senza.
    /// Un parametro separato si potrebbe passare vuoto; un tipo che esiste solo
    /// se qualcuno ha scritto abbastanza no.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn open(
        &self,
        person: &NewPerson,
        opened_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<PersonId> {
        let id = self.database.insert_person(person, opened_by, now)?;

        // L'AUDIT DICE CHE UN FASCICOLO E' STATO APERTO, E SU CHI.
        //
        // La ragione NON si copia qui: sta sulla riga del soggetto, dove un
        // trigger la protegge, e due posti per lo stesso testo divergono —
        // salvo che qui non potrebbero, perche' entrambi sono immutabili. Il
        // motivo vero e' un altro: l'audit documenta le AZIONI, e ripetere la
        // ragione ne farebbe un archivio di motivazioni da rileggere.
        self.database.append_audit(&NewAuditEntry {
            actor: opened_by.clone(),
            action: AuditAction::try_new("soggetto_aperto")?,
            entity: AuditEntity::try_new("person")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(person.label().as_str())?),
            recorded_at: now,
        })?;

        Ok(id)
    }

    /// I soggetti, in ordine di etichetta, **chiusi compresi**.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn all(&self) -> ServiceResult<Vec<Person>> {
        Ok(self.database.persons()?)
    }

    /// Un soggetto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se non esiste o se la lettura non riesce.
    pub fn get(&self, id: PersonId) -> ServiceResult<Person> {
        Ok(self.database.person(id)?)
    }

    /// Chiude un soggetto.
    ///
    /// # Che cosa NON fa
    ///
    /// Non lo cancella. Un fascicolo chiuso resta leggibile: farlo sparire
    /// riscriverebbe che qualcuno era stato investigato.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::PersonAlreadyClosed`] se non c'è nulla da
    /// chiudere — perché il soggetto non esiste o era già chiuso.
    pub fn close(
        &self,
        id: PersonId,
        closed_by: &Actor,
        reason: &OperationalReason,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database
            .close_person(id, closed_by, reason, now)
            .map_err(Self::niente_da_chiudere)?;

        self.database.append_audit(&NewAuditEntry {
            actor: closed_by.clone(),
            action: AuditAction::try_new("soggetto_chiuso")?,
            entity: AuditEntity::try_new("person")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Traduce l'assenza in una frase che dice perché.
    fn niente_da_chiudere(errore: lisi_storage::StorageError) -> ServiceError {
        if matches!(errore, lisi_storage::StorageError::NotFound { .. }) {
            return ServiceError::PersonAlreadyClosed;
        }
        ServiceError::Storage(errore)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::person::NewPerson;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::text::{Actor, DisplayName};

    use super::PersonService;
    use crate::error::ServiceError;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("person.rs");

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

    fn ragione(testo: &str) -> OperationalReason {
        let Ok(ragione) = OperationalReason::try_new(testo) else {
            panic!("la ragione di prova deve essere valida");
        };
        ragione
    }

    fn servizio() -> PersonService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        PersonService::new(database)
    }

    fn soggetto(etichetta: &str) -> NewPerson {
        let Ok(nome) = DisplayName::try_new(etichetta) else {
            panic!("l'etichetta di prova deve essere valida");
        };
        NewPerson::open(
            nome,
            ragione("richiesta della procura del 3 marzo, fascicolo 123/2026"),
        )
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

    /// **Il servizio non ha modo di aprire un soggetto da un'osservazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Quello che la Fase 6 nomina nella propria intestazione: «non si crea un
    /// profilo per ogni utente Telegram solo perché compare in una fonte
    /// monitorata».
    ///
    /// Una funzione che prenda un partecipante osservato e ne apra il fascicolo
    /// sembrerebbe una comodità — «tanto il nome ce l'abbiamo» — e sarebbe
    /// l'esatto contrario di ciò che il prodotto promette.
    ///
    /// # Perché la guardia guarda il sorgente
    ///
    /// Perché la garanzia è **l'assenza di una capacità**, e l'assenza si
    /// sorveglia cercandola.
    #[test]
    fn il_servizio_non_ha_modo_di_aprire_da_una_osservazione() {
        let codice = codice_senza_commenti();
        for osservazione in [
            "Participant",
            "participants",
            "Content",
            "contents",
            "author",
            "SessionId",
        ] {
            assert!(
                !codice.contains(osservazione),
                "il servizio nomina «{osservazione}»: un soggetto si apre perche' qualcuno lo \
                 decide, non perche' qualcuno ha scritto in un gruppo"
            );
        }
    }

    /// **Il servizio non valuta, e non ha dove mettere una valutazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il congelamento lo nomina tre volte: mai una percentuale di
    /// pericolosità, nessuna attribuzione automatica di responsabilità, nessuna
    /// classificazione automatica.
    #[test]
    fn il_servizio_non_valuta() {
        let codice = codice_senza_commenti().to_lowercase();
        for valutazione in [
            "score",
            "punteggio",
            "risk",
            "rischio",
            "pericolosit",
            "threat",
            "probabilit",
            "classif",
        ] {
            assert!(
                !codice.contains(valutazione),
                "il servizio nomina «{valutazione}»: la valutazione e' un atto umano, arriva con \
                 PERS-05, e non e' un numero"
            );
        }
    }

    /// **Si apre, si rilegge, si chiude.**
    #[test]
    fn si_apre_si_rilegge_e_si_chiude() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&soggetto("Soggetto A"), &attore(), istante(ORA)) else {
            panic!("il soggetto deve potersi aprire");
        };

        let Ok(elenco) = servizio.all() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenco.len(), 1);
        assert!(elenco[0].is_open());

        let Ok(()) = servizio.close(
            id,
            &attore(),
            &ragione("archiviato: nessun elemento utile emerso dal monitoraggio"),
            istante(ORA + 100),
        ) else {
            panic!("la chiusura deve riuscire");
        };

        let Ok(dopo) = servizio.all() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(dopo.len(), 1, "il soggetto chiuso resta leggibile");
        assert!(!dopo[0].is_open());
    }

    /// **Chiudere due volte produce una frase che spiega.**
    #[test]
    fn chiudere_due_volte_produce_una_frase_che_spiega() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&soggetto("Soggetto A"), &attore(), istante(ORA)) else {
            panic!("il soggetto deve potersi aprire");
        };
        let Ok(()) = servizio.close(
            id,
            &attore(),
            &ragione("archiviato: nessun elemento utile emerso dal monitoraggio"),
            istante(ORA + 100),
        ) else {
            panic!("la prima chiusura deve riuscire");
        };

        let esito = servizio.close(
            id,
            &attore(),
            &ragione("un secondo motivo lungo abbastanza da essere accettato"),
            istante(ORA + 200),
        );
        assert!(matches!(esito, Err(ServiceError::PersonAlreadyClosed)));

        let frase = ServiceError::PersonAlreadyClosed.operator_message();
        assert!(frase.contains("chius"), "{frase}");
        assert!(
            frase.contains("non si riapre") || frase.contains("uno nuovo"),
            "la frase deve dire che cosa fare \u{2014} {frase}"
        );
    }

    /// **Ogni atto lascia traccia nell'audit, e la ragione non ci finisce.**
    ///
    /// # Perché la ragione non va nell'audit
    ///
    /// Perché sta già sulla riga del soggetto, dove un trigger la protegge.
    /// L'audit documenta le **azioni**, e ripetere la ragione ne farebbe un
    /// archivio di motivazioni da rileggere.
    #[test]
    fn ogni_atto_lascia_traccia_e_la_ragione_non_ci_finisce() {
        let servizio = servizio();
        let Ok(id) = servizio.open(&soggetto("Soggetto A"), &attore(), istante(ORA)) else {
            panic!("il soggetto deve potersi aprire");
        };
        let Ok(()) = servizio.close(
            id,
            &attore(),
            &ragione("archiviato: nessun elemento utile emerso dal monitoraggio"),
            istante(ORA + 100),
        ) else {
            panic!("la chiusura deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for azione in ["soggetto_aperto", "soggetto_chiuso"] {
            assert!(
                voci.iter().any(|voce| voce.action.as_str() == azione),
                "l'azione «{azione}» deve comparire nell'audit"
            );
        }
        assert!(
            !voci.iter().any(|voce| voce
                .detail
                .as_ref()
                .is_some_and(|d| d.as_str().contains("procura"))),
            "la ragione sta sulla riga del soggetto, non nell'audit"
        );
    }

    /// **Aprire non prende una stringa come ragione.**
    ///
    /// # Perché conta
    ///
    /// Perché una stringa si può passare vuota, e la convalida si può
    /// dimenticare in un secondo servizio. Il tipo esiste solo se qualcuno ha
    /// scritto abbastanza.
    #[test]
    fn aprire_non_prende_una_stringa_come_ragione() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("pub fn open(\n        &self,\n        person: &NewPerson,"),
            "aprire prende il tipo del dominio, che porta gia' la ragione"
        );
        assert!(
            !codice.contains("reason: &str"),
            "una ragione come stringa si puo' passare vuota"
        );
    }

    /// **Il servizio non tiene copie.**
    #[test]
    fn il_servizio_non_tiene_copie() {
        let codice = codice_senza_commenti();
        const INTESTAZIONE: &str = "pub struct PersonService {";
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
}

//! La storia degli alias di chi è stato osservato (PERS-02).
//!
//! # Serve la stessa ragione degli elenchi di persone
//!
//! Una storia degli alias **è** un elenco di persone, guardato da un'altra
//! angolazione: dice che una certa persona si è chiamata in modi diversi. Chi la
//! custodisce risponde di averla, e «l'ho tirata fuori perché il programma lo
//! permetteva» non è una risposta.
//!
//! Perciò vale la ragione di ADR-0024, e **la stessa**: registrarne una seconda,
//! specifica per gli alias, farebbe credere che due autorizzazioni diverse
//! esistano dove ce n'è una.
//!
//! È diversa dalla ragione di PERS-01, che riguarda **un singolo soggetto** e sta
//! sulla sua riga: questa riguarda l'ufficio, e vale una volta.
//!
//! # Che cosa non costruisce
//!
//! Una tabella. La storia si **ricava** dai contenuti, che non cambiano: una
//! copia potrebbe divergere da ciò che i contenuti dicono, e non aggiungerebbe
//! niente.
//!
//! E non collega niente a un soggetto. L'associazione fra un'identità osservata
//! e un fascicolo è **PERS-06**, ed è manuale, con operatore, motivo, istante e
//! audit: farla qui, anche solo per identificativo, sarebbe l'automatismo che il
//! congelamento vieta.

use lisi_core::SessionId;
use lisi_core::model::observed_identity::{
    IdentitySighting, ObservedIdentity, observed_identities,
};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Servizio della storia degli alias.
#[derive(Debug)]
pub struct ObservedIdentityService {
    database: Database,
}

impl ObservedIdentityService {
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

    /// Le identità osservate durante una sessione, con la loro storia.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::MissingParticipantBasis`] se nessuna ragione
    /// è stata registrata: una storia di alias **non si produce** prima, per la
    /// stessa ragione per cui non si produce un elenco di persone.
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn for_session(&self, session_id: SessionId) -> ServiceResult<Vec<ObservedIdentity>> {
        // LA RAGIONE E' QUELLA DEGLI ELENCHI DI PERSONE, non una seconda.
        //
        // Registrarne una specifica per gli alias farebbe credere che esistano
        // due autorizzazioni diverse dove ce n'e' una.
        if !self.basis_recorded()? {
            return Err(ServiceError::MissingParticipantBasis);
        }

        let contents = self.database.session_contents(session_id)?;

        // SI PASSA CINQUE VALORI, NON IL CONTENUTO.
        //
        // La derivazione non ha bisogno del testo del messaggio, e una funzione
        // che non lo riceve non puo' usarlo.
        let avvistamenti: Vec<IdentitySighting> = contents
            .iter()
            .filter_map(|content| {
                // I messaggi di canale non hanno un autore individuale:
                // attribuirli a qualcuno significherebbe attribuire a una
                // persona cio' che una persona non ha scritto.
                let identifier = content.author_identifier.clone()?;
                Some(IdentitySighting {
                    content: content.id,
                    identifier,
                    display_name: content.author.as_ref().map(|a| a.as_str().to_owned()),
                    username: content.author_username.clone(),
                    at: content.published_at,
                })
            })
            .collect();

        Ok(observed_identities(&avvistamenti))
    }

    /// Se una ragione è già stata registrata.
    ///
    /// # Perché legge l'audit e non un'impostazione
    ///
    /// Perché la ragione **è** una voce di audit: sta dove nessuno la può
    /// cambiare senza lasciare traccia, e non in un'impostazione che si
    /// riscrive. È la stessa lettura che fa il servizio dei partecipanti, e la
    /// stessa voce.
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
    use lisi_core::SessionId;

    use super::ObservedIdentityService;
    use crate::error::ServiceError;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("observed_identity.rs");

    /// Il servizio dei partecipanti, dove la ragione si registra.
    const PARTICIPANTS: &str = include_str!("participants.rs");

    fn servizio() -> ObservedIdentityService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        ObservedIdentityService::new(database)
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

    /// **Una storia di alias non si produce senza una ragione registrata.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un elenco di persone prodotto perché il programma lo permetteva. Una
    /// storia di alias **è** un elenco di persone visto da un'altra angolazione:
    /// dice che una certa persona si è chiamata in modi diversi.
    #[test]
    fn una_storia_non_si_produce_senza_una_ragione() {
        let servizio = servizio();
        let esito = servizio.for_session(SessionId::new(1));
        assert!(matches!(esito, Err(ServiceError::MissingParticipantBasis)));
    }

    /// **È la stessa ragione degli elenchi di persone, non una seconda.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Due autorizzazioni dove ce n'è una. Se questa milestone registrasse una
    /// ragione propria, chi la legge crederebbe che l'ufficio abbia motivato due
    /// cose diverse — e chi ne ha motivata una sola si troverebbe una funzione
    /// bloccata senza capire quale frase manchi.
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
        assert!(
            PARTICIPANTS.contains("elenco_persone_motivato"),
            "e i partecipanti devono scriverla davvero"
        );

        // E QUESTO MODULO NON NE SCRIVE UNA PROPRIA.
        assert!(
            !codice.contains("append_audit"),
            "questo servizio legge soltanto: registrare una seconda ragione farebbe credere che \
             ne servano due"
        );
    }

    /// **Il servizio non collega un'identità a un soggetto.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// L'automatismo che il congelamento vieta. L'associazione fra un'identità
    /// osservata e un fascicolo è **PERS-06**, ed è manuale, con operatore,
    /// motivo, istante e audit.
    ///
    /// Farla qui — anche solo per identificativo, che sembrerebbe innocuo perché
    /// non è per somiglianza di nome — significherebbe che chi apre un fascicolo
    /// si trova associate delle identità che nessuno ha deciso di associare.
    #[test]
    fn il_servizio_non_collega_una_identita_a_un_soggetto() {
        // IDENTIFICATORI VERI, NON FRAMMENTI.
        //
        // Un divieto sulla stringa «person» sarebbe rosso su
        // `elenco_persone_motivato`, che e' la voce di audit condivisa e non
        // c'entra nulla con i soggetti. Una guardia rossa sulla cosa sbagliata
        // viene tolta al primo fastidio.
        let codice = codice_senza_commenti();
        for collegamento in [
            "PersonId",
            "PersonService",
            "model::person",
            "persons",
            "NewPerson",
        ] {
            assert!(
                !codice.contains(collegamento),
                "il servizio nomina «{collegamento}»: l'associazione e' PERS-06, ed e' manuale"
            );
        }
    }

    /// **Il servizio non scrive niente.**
    ///
    /// # Perché conta
    ///
    /// Perché ricavare una storia è una **lettura**. Un servizio che scrivesse
    /// costruirebbe la copia che questa milestone esiste per non costruire.
    #[test]
    fn il_servizio_non_scrive_niente() {
        let codice = codice_senza_commenti();
        for scrittura in ["insert_", "update_", "delete_", "&mut self"] {
            assert!(
                !codice.contains(scrittura),
                "il servizio nomina «{scrittura}»: ricavare una storia e' una lettura, e una \
                 copia potrebbe divergere da cio' che i contenuti dicono"
            );
        }
    }

    /// **Il servizio non tiene copie.**
    #[test]
    fn il_servizio_non_tiene_copie() {
        let codice = codice_senza_commenti();
        const INTESTAZIONE: &str = "pub struct ObservedIdentityService {";
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

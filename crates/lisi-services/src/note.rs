//! Scrivere, rileggere, ritirare (NOTE-01).
//!
//! # Che cosa questo servizio garantisce, e che cosa garantisce l'archivio
//!
//! Le regole che **non si possono dimenticare** stanno nell'archivio: una nota
//! non si riscrive, un ritiro non si annulla, una nota non si cancella, una
//! nota vuota non si scrive, un segnalibro non si annota. Sono vincoli e
//! trigger, e valgono anche per chi scrivesse un secondo servizio domani.
//!
//! Qui sta ciò che un archivio non può fare: **tradurre il rifiuto in una frase
//! che dice perché**, e registrare nell'audit chi ha fatto che cosa.
//!
//! # LA NOTA NON TOCCA LA PROVA
//!
//! Il congelamento lo scrive con queste parole. Il modo di rispettarlo non è
//! ricordarsene: questo modulo **non ha alcun modo di raggiungere il
//! contenuto**. Non nomina `contents`, non nomina `content_versions`, non
//! chiama nulla che scriva sull'una o sull'altra. Una guardia lo verifica
//! cercando quelle parole nel sorgente di produzione — la stessa forma che
//! CTX-06 usa per impedire che il conservare osservi.
//!
//! # Che cosa NON registra nell'audit
//!
//! Le parole della nota. L'audit documenta le **azioni**, non i dati su cui
//! insistono: dice che è stata scritta una nota, su che cosa, e chi. Copiarne
//! il testo nell'audit darebbe due posti da cui leggerlo, e uno dei due — per
//! costruzione — non si può correggere.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::note::{NewOperatorNote, OperatorNote};
use lisi_core::model::reference::ArchiveRef;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{NoteId, Timestamp};
use lisi_storage::Database;

/// Riesportata perché l'interfaccia dipenda **soltanto** dai servizi
/// (ADR-0010): una schermata che nominasse `lisi_storage` avrebbe attraversato
/// il confine che quel documento tiene chiuso.
pub use lisi_storage::repository::note::ResolvedNote;

use crate::error::{ServiceError, ServiceResult};

/// Servizio delle note dell'operatore.
#[derive(Debug)]
pub struct NoteService {
    database: Database,
}

impl NoteService {
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

    /// Scrive una nota.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce. Il testo vuoto e il
    /// segnalibro li rifiuta già il dominio, prima di arrivare qui.
    pub fn write(
        &self,
        note: &NewOperatorNote,
        author: &Actor,
        now: Timestamp,
    ) -> ServiceResult<NoteId> {
        let id = self.database.insert_note(note, author, now)?;

        self.database.append_audit(&NewAuditEntry {
            actor: author.clone(),
            action: AuditAction::try_new("nota_scritta")?,
            entity: AuditEntity::try_new("note")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            // SU CHE COSA, NON CHE COSA DICEVA.
            detail: Some(AuditDetail::try_new(&format!(
                "{} {}",
                note.reference().kind().as_str(),
                note.reference().target_id()
            ))?),
            recorded_at: now,
        })?;

        Ok(id)
    }

    /// Ritira una nota.
    ///
    /// # Che cosa NON fa
    ///
    /// Non la cancella e non ne cambia il testo. Dopo il ritiro la nota **si
    /// legge ancora**: qualcuno può averci lavorato sopra.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::NoteAlreadyWithdrawn`] se non c'è nulla da
    /// ritirare — perché la nota non esiste o era già ritirata.
    pub fn withdraw(&self, id: NoteId, withdrawn_by: &Actor, now: Timestamp) -> ServiceResult<()> {
        self.database
            .withdraw_note(id, withdrawn_by, now)
            .map_err(Self::niente_da_ritirare)?;

        self.database.append_audit(&NewAuditEntry {
            actor: withdrawn_by.clone(),
            action: AuditAction::try_new("nota_ritirata")?,
            entity: AuditEntity::try_new("note")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Traduce l'assenza in una frase che dice perché.
    fn niente_da_ritirare(errore: lisi_storage::StorageError) -> ServiceError {
        if matches!(errore, lisi_storage::StorageError::NotFound { .. }) {
            return ServiceError::NoteAlreadyWithdrawn;
        }
        ServiceError::Storage(errore)
    }

    /// Le note su una cosa, dalla più recente, **ritirate comprese**.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn about(&self, reference: ArchiveRef) -> ServiceResult<Vec<OperatorNote>> {
        Ok(self.database.notes_about(reference)?)
    }

    /// Tutte le note, dalla più recente, con ciò che i riferimenti raggiungono.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn all(&self) -> ServiceResult<Vec<ResolvedNote>> {
        Ok(self.database.notes()?)
    }

    /// Quante note **valide** ci sono su una cosa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn standing_count(&self, reference: ArchiveRef) -> ServiceResult<usize> {
        Ok(self.database.standing_note_count(reference)?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::note::NewOperatorNote;
    use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
    use lisi_core::text::{Actor, Note};

    use super::NoteService;
    use crate::error::ServiceError;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("note.rs");

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

    fn servizio() -> NoteService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        NoteService::new(database)
    }

    fn nota(corpo: &str) -> NewOperatorNote {
        let Ok(testo) = Note::try_new(corpo) else {
            panic!("il testo di prova deve essere valido");
        };
        let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, 42) else {
            panic!("il riferimento di prova deve essere valido");
        };
        let Ok(nota) = NewOperatorNote::about(riferimento, &testo) else {
            panic!("la nota di prova deve essere valida");
        };
        nota
    }

    fn contenuto() -> ArchiveRef {
        let Ok(riferimento) = ArchiveRef::to(ArchiveRefKind::Content, 42) else {
            panic!("il riferimento di prova deve essere valido");
        };
        riferimento
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

    /// **Si scrive, si rilegge, si ritira.**
    #[test]
    fn si_scrive_si_rilegge_e_si_ritira() {
        let servizio = servizio();
        let Ok(id) = servizio.write(&nota("ripubblicato tre volte"), &attore(), istante(ORA))
        else {
            panic!("la nota deve potersi scrivere");
        };

        let Ok(elenco) = servizio.about(contenuto()) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenco.len(), 1);
        assert!(elenco[0].stands());

        let Ok(()) = servizio.withdraw(id, &attore(), istante(ORA + 100)) else {
            panic!("il ritiro deve riuscire");
        };
        let Ok(dopo) = servizio.about(contenuto()) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(dopo.len(), 1, "la nota ritirata resta visibile");
        assert!(!dopo[0].stands());
    }

    /// **Ritirare due volte produce una frase che spiega.**
    #[test]
    fn ritirare_due_volte_produce_una_frase_che_spiega() {
        let servizio = servizio();
        let Ok(id) = servizio.write(&nota("qualcosa"), &attore(), istante(ORA)) else {
            panic!("la nota deve potersi scrivere");
        };
        let Ok(()) = servizio.withdraw(id, &attore(), istante(ORA + 100)) else {
            panic!("il primo ritiro deve riuscire");
        };

        let esito = servizio.withdraw(id, &attore(), istante(ORA + 200));
        assert!(matches!(esito, Err(ServiceError::NoteAlreadyWithdrawn)));

        let frase = ServiceError::NoteAlreadyWithdrawn.operator_message();
        assert!(frase.contains("ritirat"), "{frase}");
        assert!(
            frase.contains("non si riscrive") || frase.contains("scriverne"),
            "la frase deve dire che cosa fare \u{2014} {frase}"
        );
    }

    /// **Il conteggio dice le note valide.**
    #[test]
    fn il_conteggio_dice_le_note_valide() {
        let servizio = servizio();
        let Ok(id) = servizio.write(&nota("una"), &attore(), istante(ORA)) else {
            panic!("la nota deve potersi scrivere");
        };
        let Ok(quante) = servizio.standing_count(contenuto()) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quante, 1);

        let Ok(()) = servizio.withdraw(id, &attore(), istante(ORA + 100)) else {
            panic!("il ritiro deve riuscire");
        };
        let Ok(dopo) = servizio.standing_count(contenuto()) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(dopo, 0, "la ritirata non conta");
    }

    /// **Ogni atto lascia traccia nell'audit.**
    #[test]
    fn ogni_atto_lascia_traccia() {
        let servizio = servizio();
        let Ok(id) = servizio.write(&nota("qualcosa"), &attore(), istante(ORA)) else {
            panic!("la nota deve potersi scrivere");
        };
        let Ok(()) = servizio.withdraw(id, &attore(), istante(ORA + 100)) else {
            panic!("il ritiro deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for azione in ["nota_scritta", "nota_ritirata"] {
            assert!(
                voci.iter().any(|voce| voce.action.as_str() == azione),
                "l'azione «{azione}» deve comparire nell'audit"
            );
        }
    }

    /// **Scrivere una nota non ha modo di toccare la prova.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il solo che il congelamento nomina per esteso: «non modificano mai la
    /// prova originale». Una nota che, per comodità, aggiornasse anche il
    /// contenuto — un marcatore «annotato», un contatore — renderebbe la prova
    /// diversa da com'era stata acquisita.
    ///
    /// # Perché la guardia guarda il sorgente
    ///
    /// Perché la garanzia è **l'assenza di una capacità**, e l'assenza si
    /// sorveglia cercandola. È la stessa forma con cui CTX-06 impedisce che il
    /// conservare osservi.
    #[test]
    fn una_nota_non_ha_modo_di_toccare_la_prova() {
        let codice = codice_senza_commenti();
        for prova in [
            "contents",
            "content_versions",
            "insert_content",
            "update_content",
            "ContentId",
            "delete_content",
        ] {
            assert!(
                !codice.contains(prova),
                "il servizio nomina «{prova}»: una nota non modifica mai la prova originale"
            );
        }
    }

    /// **L'audit non porta le parole della nota.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Due posti da cui leggere lo stesso testo — e uno dei due, l'audit, per
    /// costruzione **non si può correggere**. Una nota ritirata resterebbe
    /// scritta per sempre nell'audit, e il ritiro non varrebbe niente.
    #[test]
    fn l_audit_non_porta_le_parole() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("pub fn write(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n    }\n") else {
            panic!("la funzione deve chiudersi");
        };
        assert!(
            !codice[inizio..inizio + fine].contains("body()"),
            "l'audit porta le parole della nota: sarebbe una copia che il ritiro non raggiunge"
        );
    }

    /// **Il servizio non tiene copie: non ha nulla con cui farlo.**
    #[test]
    fn il_servizio_non_tiene_copie() {
        let codice = codice_senza_commenti();
        const INTESTAZIONE: &str = "pub struct NoteService {";
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

//! Ciò che l'ufficio scrive insieme, dal lato dell'Hub (TEAM-WS-01,
//! ADR-0099).
//!
//! # LA NOTA NON TOCCA LA PROVA
//!
//! Il congelamento lo scrive con queste parole, e NOTE-01 lo ha realizzato in
//! un modo che non richiede di ricordarsene: il modulo **non ha alcun modo di
//! raggiungere il contenuto**. Lo stesso vale qui — non nomina `contents`, non
//! nomina `content_versions`, non chiama nulla che scriva sull'una o
//! sull'altra — e una guardia lo verifica cercando quelle parole nel sorgente
//! di produzione.
//!
//! # Che cosa NON registra nell'audit
//!
//! **Le parole della nota.** L'audit documenta le azioni, non i dati su cui
//! insistono: dice che è stata scritta una nota, su che cosa e da chi.
//! Copiarne il testo darebbe due posti da cui leggerlo, e uno dei due — per
//! costruzione — non si può correggere.
//!
//! # Serve una persona
//!
//! Scrivere richiede che qualcuno si sia **dimostrato** (ADR-0097). Una
//! revisione poteva essere attribuita alla postazione quando le persone non
//! esistevano; una nota è **parole di qualcuno**, e senza un autore verificato
//! è un foglietto anonimo lasciato sulla scrivania di tutti.
//!
//! # Niente versione attesa
//!
//! Scrivere una nota non entra in conflitto con la nota di nessun altro: si
//! aggiunge, e ciò che c'era resta. La concorrenza ottimistica serve dove due
//! persone scrivono **lo stesso** fatto (ADR-0089), e qui non succede.

use lisi_core::NoteId;
use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::hub_access::HubAction;
use lisi_core::model::hub_notes::{
    MAX_SHARED_NOTES_PAGE, MAX_SHARED_WORKSPACES_PAGE, MAX_WORKSPACE_ITEMS_PAGE, SharedNote,
    SharedWorkspace, SharedWorkspaceItem,
};
use lisi_core::model::reference::ArchiveRef;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, Note};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_people::AuthenticatedOperator;

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "scritto_insieme";

const AUDIT_NOTE_WRITTEN: &str = "nota_condivisa_scritta";
const AUDIT_NOTE_WITHDRAWN: &str = "nota_condivisa_ritirata";
const AUDIT_WORKSPACE_OPENED: &str = "raccoglitore_aperto";
const AUDIT_WORKSPACE_CLOSED: &str = "raccoglitore_chiuso";
const AUDIT_ITEM_ADDED: &str = "raccoglitore_elemento_aggiunto";
const AUDIT_ITEM_REMOVED: &str = "raccoglitore_elemento_tolto";

/// Ciò che l'ufficio scrive insieme, servito dall'Hub.
#[derive(Debug)]
pub struct HubNotesService {
    database: Database,
}

impl HubNotesService {
    /// Costruisce il servizio sull'archivio dell'Hub.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// L'archivio dell'Hub.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Scrive una nota dell'ufficio.
    ///
    /// # Errori
    ///
    /// Un errore se la persona non è autorizzata, o se la scrittura non
    /// riesce.
    pub fn write(
        &self,
        operator: &AuthenticatedOperator,
        about: ArchiveRef,
        body: &Note,
        now: Timestamp,
    ) -> ServiceResult<NoteId> {
        self.autorizza(operator)?;
        let id =
            self.database
                .insert_hub_note(&lisi_storage::repository::hub_notes::NewSharedNote {
                    about,
                    body,
                    author: operator.person(),
                    written_at: now,
                })?;

        // SU CHE COSA, NON CHE COSA DICEVA.
        self.registra(
            operator,
            AUDIT_NOTE_WRITTEN,
            Some(id.get()),
            &format!("{} {}", about.kind().as_str(), about.target_id()),
            now,
        )?;
        Ok(id)
    }

    /// Ritira una nota dell'ufficio.
    ///
    /// **Non la cancella e non ne cambia il testo**: la nota resta, e dice chi
    /// l'ha ritirata e quando.
    ///
    /// # Errori
    ///
    /// Un errore se la persona non è autorizzata, se la nota non esiste, se
    /// **non è sua** e non amministra, o se la scrittura non riesce.
    pub fn withdraw(
        &self,
        operator: &AuthenticatedOperator,
        id: NoteId,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.autorizza(operator)?;
        let Some(nota) = self.database.hub_note(id)? else {
            return Err(ServiceError::HubServer {
                reason: String::from("questa nota non esiste più su questo Hub"),
            });
        };
        // LE PAROLE DI UN ALTRO NON SI RITIRANO (ADR-0099, decisione 3): un
        // terzo che potesse farlo potrebbe far sparire un'obiezione.
        if !nota.may_withdraw(
            operator.person(),
            operator.permits(HubAction::AdministerPeople),
        ) {
            return Err(ServiceError::HubForbidden {
                reason: String::from(
                    "una nota la ritira chi l'ha scritta, o chi amministra l'ufficio",
                ),
            });
        }

        self.database
            .withdraw_hub_note(id, operator.person(), now)?;
        self.registra(
            operator,
            AUDIT_NOTE_WITHDRAWN,
            Some(id.get()),
            &format!("{} {}", nota.about.kind().as_str(), nota.about.target_id()),
            now,
        )
    }

    /// Le note dell'ufficio su qualcosa, comprese quelle ritirate.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn notes_about(&self, about: ArchiveRef, limit: usize) -> ServiceResult<Vec<SharedNote>> {
        Ok(self
            .database
            .hub_notes_about(about, limit.clamp(1, MAX_SHARED_NOTES_PAGE))?)
    }

    /// Apre un raccoglitore dell'ufficio.
    ///
    /// # Errori
    ///
    /// Un errore se la persona non è autorizzata, se un raccoglitore
    /// **aperto** ha già quel nome, o se la scrittura non riesce.
    pub fn open_workspace(
        &self,
        operator: &AuthenticatedOperator,
        name: &DisplayName,
        description: Option<&Note>,
        now: Timestamp,
    ) -> ServiceResult<i64> {
        self.autorizza(operator)?;
        // IL NOME DUPLICATO LO RIFIUTA L'ARCHIVIO, con un indice unico
        // parziale: fra un controllo e la scrittura ci sarebbe una fessura, e
        // due postazioni potrebbero passarci entrambe.
        let id = self
            .database
            .insert_hub_workspace(name, description, operator.person(), now)
            .map_err(|errore| match errore {
                lisi_storage::StorageError::Sqlite(_) => ServiceError::WorkspaceNameTaken {
                    name: String::from(name.as_str()),
                },
                altro => ServiceError::Storage(altro),
            })?;

        self.registra(
            operator,
            AUDIT_WORKSPACE_OPENED,
            Some(id),
            name.as_str(),
            now,
        )?;
        Ok(id)
    }

    /// Chiude un raccoglitore. **Non cancella niente.**
    ///
    /// # Errori
    ///
    /// Un errore se la persona non è autorizzata, se il raccoglitore non
    /// esiste o era già chiuso, o se la scrittura non riesce.
    pub fn close_workspace(
        &self,
        operator: &AuthenticatedOperator,
        id: i64,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.autorizza(operator)?;
        self.database
            .close_hub_workspace(id, operator.person(), now)?;
        self.registra(operator, AUDIT_WORKSPACE_CLOSED, Some(id), "", now)
    }

    /// Raccoglie un riferimento in un raccoglitore.
    ///
    /// # Errori
    ///
    /// Un errore se la persona non è autorizzata, se il raccoglitore è chiuso,
    /// o se la scrittura non riesce.
    pub fn collect(
        &self,
        operator: &AuthenticatedOperator,
        workspace_id: i64,
        item: ArchiveRef,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.autorizza(operator)?;
        // SE E' CHIUSO LO DICE PRIMA, per poterlo dire con parole utili. Il
        // rifiuto vero resta dell'archivio, e se i due divergessero
        // vincerebbe il trigger.
        if !self.database.hub_workspace_accepts_items(workspace_id)? {
            return Err(ServiceError::HubServer {
                reason: String::from(
                    "questo raccoglitore è chiuso: non accetta più elementi, e ciò che ha \
                     raccolto resta",
                ),
            });
        }

        self.database
            .add_hub_workspace_item(workspace_id, item, operator.person(), now)?;
        self.registra(
            operator,
            AUDIT_ITEM_ADDED,
            Some(workspace_id),
            &format!("{} {}", item.kind().as_str(), item.target_id()),
            now,
        )
    }

    /// Toglie un riferimento da un raccoglitore.
    ///
    /// # Errori
    ///
    /// Un errore se la persona non è autorizzata, se il raccoglitore è chiuso,
    /// o se la scrittura non riesce.
    pub fn drop_item(
        &self,
        operator: &AuthenticatedOperator,
        workspace_id: i64,
        item: ArchiveRef,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.autorizza(operator)?;
        if !self.database.hub_workspace_accepts_items(workspace_id)? {
            return Err(ServiceError::HubServer {
                reason: String::from(
                    "questo raccoglitore è chiuso: ciò che ha raccolto non si tocca più",
                ),
            });
        }

        self.database
            .remove_hub_workspace_item(workspace_id, item)?;
        self.registra(
            operator,
            AUDIT_ITEM_REMOVED,
            Some(workspace_id),
            &format!("{} {}", item.kind().as_str(), item.target_id()),
            now,
        )
    }

    /// I raccoglitori dell'ufficio.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn workspaces(&self, limit: usize) -> ServiceResult<Vec<SharedWorkspace>> {
        Ok(self
            .database
            .hub_workspaces(limit.clamp(1, MAX_SHARED_WORKSPACES_PAGE))?)
    }

    /// Ciò che un raccoglitore ha raccolto.
    ///
    /// # Errori
    ///
    /// Un errore di lettura.
    pub fn items(
        &self,
        workspace_id: i64,
        limit: usize,
    ) -> ServiceResult<Vec<SharedWorkspaceItem>> {
        Ok(self
            .database
            .hub_workspace_items(workspace_id, limit.clamp(1, MAX_WORKSPACE_ITEMS_PAGE))?)
    }

    /// Che la persona possa scrivere insieme agli altri.
    fn autorizza(&self, operator: &AuthenticatedOperator) -> ServiceResult<()> {
        if operator.permits(HubAction::ShareNotes) {
            return Ok(());
        }
        Err(ServiceError::HubForbidden {
            reason: String::from(HubAction::ShareNotes.reason()),
        })
    }

    /// Registra l'atto. **Mai le parole.**
    fn registra(
        &self,
        operator: &AuthenticatedOperator,
        azione: &str,
        entity_id: Option<i64>,
        dettaglio: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let voce = NewAuditEntry {
            actor: Actor::try_new(&operator.actor())?,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id,
            actor_mode: None,
            detail: if dettaglio.is_empty() {
                None
            } else {
                Some(AuditDetail::try_new(dettaglio)?)
            },
            recorded_at: now,
        };
        self.database.append_audit(&voce)?;
        Ok(())
    }
}

#[cfg(test)]
mod guardie {
    /// Il sorgente di questo modulo, per la guardia.
    const QUESTO_MODULO: &str = include_str!("hub_notes.rs");

    /// **La nota non ha alcun modo di raggiungere la prova.**
    ///
    /// La guardia non verifica che nessuno lo faccia: verifica che **non si
    /// possa**, cercando nel codice di produzione le parole con cui si
    /// raggiungerebbe. È la stessa forma che NOTE-01 usa.
    #[test]
    fn la_nota_non_tocca_la_prova() {
        let Some((produzione, _)) = QUESTO_MODULO.split_once("#[cfg(test)]\nmod guardie {") else {
            panic!("il modulo deve avere un blocco di guardie riconoscibile");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| {
                let pulita = riga.trim_start();
                !pulita.starts_with("//") && !pulita.starts_with("///")
            })
            .collect::<Vec<_>>()
            .join("\n");

        for vietato in [
            "contents",
            "content_versions",
            "insert_content",
            "content_body",
        ] {
            assert!(
                !codice.contains(vietato),
                "il modulo delle note condivise nomina «{vietato}»: una nota non tocca la prova"
            );
        }
    }

    /// **Il testo di una nota non entra nell'audit.**
    ///
    /// La guardia legge la funzione che scrive, e verifica che il corpo della
    /// nota non compaia fra ciò che viene registrato.
    #[test]
    fn le_parole_di_una_nota_non_entrano_nell_audit() {
        let Some(inizio) = QUESTO_MODULO.find("pub fn write(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = QUESTO_MODULO[inizio..].find("\n    }\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &QUESTO_MODULO[inizio..inizio + fine];
        assert!(
            !corpo.contains("body.as_str()"),
            "le parole della nota finiscono nell'audit: l'audit documenta le azioni, non i dati"
        );
    }
}

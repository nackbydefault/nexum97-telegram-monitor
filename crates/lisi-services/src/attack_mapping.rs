//! «Termine associato alla tecnica X»: dichiarare, ritirare, leggere.
//!
//! # Che cosa questo servizio fa
//!
//! Registra **atti di una persona** — una dichiarazione, un ritiro — e legge ciò
//! che ne risulta. Non cerca tecniche, non ne propone, non ne ordina per
//! verosimiglianza: l'identificativo lo scrive chi dichiara (ADR-0059).
//!
//! # Che cosa non fa, mai
//!
//! **Non associa niente da solo.** Nessun percorso di acquisizione, nessun
//! temporizzatore e nessuna analisi chiamano `declare`: se lo facessero, il
//! prodotto avrebbe una regola che collega parole a tecniche di attacco senza
//! che nessuno lo abbia deciso, ed è precisamente ciò che il congelamento
//! vieta.
//!
//! **E non alza il livello di analisi.** Un riferimento tassonomico non è un
//! segnale: se potesse alzare un livello o generare un alert, il prodotto
//! direbbe «questo contenuto è più grave perché qualcuno ha collegato una sua
//! parola a una tecnica». Il modulo non nomina né il livello né gli alert, e una
//! guardia lo verifica.

use lisi_core::model::NewAuditEntry;
use lisi_core::model::attack_association::{
    AssociatedTerm, AttackAssociationWithdrawal, NewAttackAssociation, StandingAssociation,
};
use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};
use lisi_core::{AttackAssociationId, AttackSnapshotId, ContentId};
use lisi_storage::Database;
use lisi_storage::repository::attack::StoredAttackSnapshot;

use crate::error::{ServiceError, ServiceResult};

/// Il servizio della mappatura.
pub struct AttackMappingService<'a> {
    database: &'a mut Database,
}

impl<'a> AttackMappingService<'a> {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub fn new(database: &'a mut Database) -> Self {
        Self { database }
    }

    /// Le fotografie disponibili, dalla più recente.
    ///
    /// # Perché non esiste una «fotografia corrente» implicita
    ///
    /// Perché **su quale versione** si dichiari un'associazione è parte
    /// dell'atto: una tecnica significa ciò che significa nella propria
    /// versione. Scegliere la più recente al posto di chi dichiara
    /// significherebbe decidere per lui, e nascondere la scelta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn snapshots(&self) -> ServiceResult<Vec<StoredAttackSnapshot>> {
        Ok(self.database.attack_snapshots()?)
    }

    /// Dichiara che un termine è associato a una tecnica.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il motivo manca, se la tecnica non esiste dentro
    /// quella fotografia, se lo stesso legame è già in piedi, o se la scrittura
    /// non riesce.
    pub fn declare(
        &mut self,
        snapshot_id: AttackSnapshotId,
        association: NewAttackAssociation,
    ) -> ServiceResult<AttackAssociationId> {
        let association = association.validated()?;
        let id = self
            .database
            .declare_attack_association(snapshot_id, &association)
            .map_err(|errore| match errore {
                // Un doppione ordinario, non un guasto (F-10).
                lisi_storage::StorageError::DuplicateAttackAssociation => {
                    ServiceError::AttackAssociationAlreadyStanding
                }
                altro => ServiceError::Storage(altro),
            })?;

        self.database.append_audit(&NewAuditEntry {
            actor: association.declared_by.clone(),
            action: AuditAction::try_new("associazione_attack_dichiarata")?,
            entity: AuditEntity::try_new("attack_association")?,
            entity_id: Some(id.get()),
            // Dichiarare un riferimento tassonomico non e' un'azione riservata:
            // e' un atto documentato, e il motivo lo accompagna.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "termine «{termine}» ({categoria}) associato alla tecnica {tecnica}: {motivo}",
                termine = association.term.normalised(),
                categoria = association.term.category(),
                tecnica = association.technique.as_str(),
                motivo = association.reason,
            ))?),
            recorded_at: association.declared_at,
        })?;

        Ok(id)
    }

    /// Ritira un'associazione, con il proprio motivo.
    ///
    /// # Perché ritirare è un atto e non una cancellazione
    ///
    /// Perché un legame sciolto in silenzio non dice se fosse sbagliato o
    /// scomodo, e cancellarlo renderebbe illeggibili i rapporti che lo
    /// citavano.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il motivo manca, se l'associazione non esiste o
    /// era già ritirata, o se la scrittura non riesce.
    pub fn withdraw(
        &mut self,
        association_id: AttackAssociationId,
        withdrawal: AttackAssociationWithdrawal,
    ) -> ServiceResult<()> {
        let withdrawal = withdrawal.validated()?;
        self.database
            .withdraw_attack_association(association_id, &withdrawal)?;

        self.database.append_audit(&NewAuditEntry {
            actor: withdrawal.withdrawn_by.clone(),
            action: AuditAction::try_new("associazione_attack_ritirata")?,
            entity: AuditEntity::try_new("attack_association")?,
            entity_id: Some(association_id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "associazione ritirata: {motivo}",
                motivo = withdrawal.reason
            ))?),
            recorded_at: withdrawal.withdrawn_at,
        })?;

        Ok(())
    }

    /// Le associazioni in piedi di un termine.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn for_term(&self, term: &AssociatedTerm) -> ServiceResult<Vec<StandingAssociation>> {
        Ok(self.database.standing_associations_for_term(term)?)
    }

    /// Le tecniche associate ai termini che un contenuto ha riscontrato.
    ///
    /// # Che cosa questa risposta dice, e che cosa no
    ///
    /// Dice che il contenuto **contiene termini** che questo ufficio ha
    /// associato a certe tecniche. Non dice che chi lo ha scritto abbia
    /// impiegato quelle tecniche, né che sia accaduto qualcosa: la frase di ogni
    /// associazione lo scrive per esteso, e il motivo di chi l'ha dichiarata
    /// viaggia con essa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn for_content(&self, content_id: ContentId) -> ServiceResult<Vec<StandingAssociation>> {
        Ok(self
            .database
            .standing_associations_for_content(content_id)?)
    }
}

#[cfg(test)]
mod tests {

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("attack_mapping.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]")
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

    /// **Il servizio non propone, non cerca e non somiglia.**
    ///
    /// È la regola di PERS-06 applicata alla tassonomia: una proposta è il modo
    /// in cui un riferimento diventa un'imputazione.
    #[test]
    fn il_servizio_non_propone_e_non_somiglia() {
        for vietato in [
            "suggest",
            "suggerisc",
            "propos",
            "proponi",
            "candidat",
            "similar",
            "somiglia",
            "score",
            "punteggio",
            "ranking",
        ] {
            assert!(
                !codice_di_produzione().contains(vietato),
                "il servizio della mappatura non deve nominare «{vietato}»"
            );
        }
    }

    /// **E non tocca il livello di analisi né gli alert.**
    ///
    /// Un riferimento tassonomico non è un segnale. Se potesse alzare un
    /// livello, il prodotto avrebbe l'inferenza che ADR-0048 vieta, travestita
    /// da tassonomia.
    #[test]
    fn il_servizio_non_tocca_il_livello_ne_gli_alert() {
        for vietato in [
            "AnalysisLevel",
            "analysis_level",
            "Alert",
            "insert_alert",
            "NewAlert",
        ] {
            assert!(
                !codice_di_produzione().contains(vietato),
                "il servizio della mappatura non deve nominare «{vietato}»"
            );
        }
    }

    /// **E non attribuisce, nemmeno nel codice.**
    #[test]
    fn il_servizio_non_nomina_l_attribuzione() {
        let codice = codice_di_produzione().to_lowercase();
        for vietato in ["ha usato", "ha impiegato", "attaccante", "adversary"] {
            assert!(
                !codice.contains(vietato),
                "il servizio non deve nominare «{vietato}»"
            );
        }
    }
}

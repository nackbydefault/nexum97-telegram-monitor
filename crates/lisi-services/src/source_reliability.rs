//! L'affidabilità di una fonte, valutata a mano (SOURCE-RELIABILITY-01,
//! ADR-0167; ADR-0035, decisione 9).
//!
//! # Lo decide una persona
//!
//! Il servizio registra un atto — una parola, oppure il ritiro — con chi,
//! quando e perché, e dice qual è la valutazione in vigore. **Non propone un
//! livello**: non guarda i contenuti, gli avvisi o il numero di iscritti, e
//! non ha una funzione che ricavi un giudizio da un dato.
//!
//! # Nei documenti
//!
//! La relazione la riporta accanto alla fonte, attribuita a chi l'ha data e
//! separata dai contenuti (`crate::report`).

use lisi_core::model::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::model::source_reliability::{NewReliability, ReliabilityAct, current_reliability};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SourceId, Timestamp};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// L'azione d'audit di un atto sull'affidabilità di una fonte.
pub const RELIABILITY_AUDIT_ACTION: &str = "affidabilita_fonte";

/// Una fonte, con la valutazione in vigore se c'è.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReliability {
    /// La fonte.
    pub source_id: SourceId,
    /// Come si chiama.
    pub name: String,
    /// La valutazione in vigore, in una frase; `None` se non è valutata.
    pub current: Option<String>,
}

/// Registra un atto sull'affidabilità di una fonte, con l'audit.
///
/// # Errori
///
/// Restituisce un errore se la fonte non esiste o se la scrittura non riesce.
pub fn record(
    database: &mut Database,
    source: SourceId,
    act: ReliabilityAct,
    reason: &OperationalReason,
    by: &Actor,
    at: Timestamp,
) -> ServiceResult<i64> {
    let fonte = database.source(source)?;
    let audit = NewAuditEntry {
        actor: by.clone(),
        action: AuditAction::try_new(RELIABILITY_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("fonte")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "fonte {} \u{ab}{}\u{bb}: {} \u{2014} {}",
            source.get(),
            fonte.display_name.as_str(),
            act.as_label(),
            reason.as_str()
        ))?),
        recorded_at: at,
    };
    Ok(database.insert_source_reliability(
        &NewReliability {
            source,
            act,
            reason: reason.clone(),
            by: by.clone(),
            at,
        },
        &audit,
    )?)
}

/// La valutazione in vigore di una fonte, in una frase: la parola, chi, quando,
/// perché, e che cosa non dice dei contenuti. `None` se la fonte non è
/// valutata.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn current_sentence(database: &Database, source: SourceId) -> ServiceResult<Option<String>> {
    let atti = database.source_reliability_history(source)?;
    Ok(current_reliability(&atti).map(|atto| {
        let spiegazione = match atto.act {
            ReliabilityAct::Assess(livello) => livello.as_sentence(),
            ReliabilityAct::Withdraw => "",
        };
        format!(
            "{}, valutazione data da {} il {}, perch\u{e9}: \u{ab}{}\u{bb}. {spiegazione}",
            atto.act.as_label(),
            atto.by.as_str(),
            atto.at.to_readable_local(),
            atto.reason.as_str()
        )
    }))
}

/// Le fonti configurate, ciascuna con la valutazione in vigore.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn overview(database: &Database) -> ServiceResult<Vec<SourceReliability>> {
    let mut righe = Vec::new();
    for fonte in database.sources()? {
        righe.push(SourceReliability {
            source_id: fonte.id,
            name: fonte.display_name.as_str().to_owned(),
            current: current_sentence(database, fonte.id)?,
        });
    }
    Ok(righe)
}

#[cfg(test)]
mod tests {
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::source_reliability::{ReliabilityAct, ReliabilityLevel};
    use lisi_core::model::{NewSource, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{SourceId, Timestamp};
    use lisi_storage::Database;

    use super::{RELIABILITY_AUDIT_ACTION, current_sentence, overview, record};

    const ORA: i64 = 1_760_000_000_000;
    const THIS_MODULE: &str = include_str!("source_reliability.rs");

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn ragione() -> OperationalReason {
        let Ok(ragione) =
            OperationalReason::try_new("riscontri dell'ufficio sugli ultimi tre mesi")
        else {
            panic!("ragione valida");
        };
        ragione
    }

    fn archivio_con_fonte() -> (Database, SourceId) {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio in memoria");
        };
        let (Ok(identificativo), Ok(nome)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale di prova"),
        ) else {
            panic!("valori validi");
        };
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: operatore(),
                active: true,
            },
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la fonte deve registrarsi");
        };
        (database, fonte)
    }

    /// **Una valutazione si registra con chi, quando e perché, si legge in una
    /// frase che dice che cosa non dice dei contenuti, e si ritira**
    /// (SOURCE-RELIABILITY-01, criteri 2 e 5).
    #[test]
    fn una_valutazione_si_registra_si_legge_e_si_ritira() {
        let (mut db, fonte) = archivio_con_fonte();
        assert_eq!(
            current_sentence(&db, fonte).ok(),
            Some(None),
            "non valutata"
        );
        let Ok(_) = record(
            &mut db,
            fonte,
            ReliabilityAct::Assess(ReliabilityLevel::Unreliable),
            &ragione(),
            &operatore(),
            Timestamp::from_millis(ORA + 1),
        ) else {
            panic!("la valutazione deve registrarsi");
        };
        let Ok(Some(frase)) = current_sentence(&db, fonte) else {
            panic!("la valutazione deve leggersi");
        };
        assert!(
            frase.starts_with("POCO AFFIDABILE PER L'ESPERIENZA DELL'UFFICIO"),
            "{frase}"
        );
        assert!(frase.contains("operatore.prova"), "{frase}");
        assert!(frase.contains("riscontri dell'ufficio"), "{frase}");
        assert!(frase.contains("Non rende falso un contenuto"), "{frase}");
        let Ok(righe) = overview(&db) else {
            panic!("l'elenco deve leggersi");
        };
        assert_eq!(righe.len(), 1);
        assert_eq!(righe[0].current.as_deref(), Some(frase.as_str()));

        let Ok(_) = record(
            &mut db,
            fonte,
            ReliabilityAct::Withdraw,
            &ragione(),
            &operatore(),
            Timestamp::from_millis(ORA + 2),
        ) else {
            panic!("il ritiro deve registrarsi");
        };
        assert_eq!(current_sentence(&db, fonte).ok(), Some(None), "ritirata");
        let Ok(audit) = db.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(
            audit
                .iter()
                .filter(|voce| voce.action.as_str() == RELIABILITY_AUDIT_ACTION)
                .count(),
            2,
            "due atti, due righe d'audit"
        );
    }

    /// **Una fonte che non esiste non si valuta** (criterio 5).
    #[test]
    fn una_fonte_che_non_esiste_non_si_valuta() {
        let (mut db, _) = archivio_con_fonte();
        assert!(
            record(
                &mut db,
                SourceId::new(999),
                ReliabilityAct::Assess(ReliabilityLevel::Reliable),
                &ragione(),
                &operatore(),
                Timestamp::from_millis(ORA),
            )
            .is_err()
        );
    }

    /// **Il servizio non ricava un giudizio**: nessuna lettura di contenuti,
    /// avvisi, iscritti o elenchi di chat (criterio 3).
    #[test]
    fn il_servizio_non_ricava_un_giudizio() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        for lettura in [
            "session_contents",
            "content_alert",
            "accessible_chats",
            "member",
            "analysis",
            "subscriber",
        ] {
            assert!(
                !produzione.contains(lettura),
                "il servizio chiama «{lettura}»: l'affidabilità la decide una persona"
            );
        }
    }
}

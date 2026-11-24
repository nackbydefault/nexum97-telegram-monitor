//! Il modo di acquisizione, ricavato dai fatti (PR-07, ADR-0123).
//!
//! # Il criterio «Modo di acquisizione»
//!
//! | Percorso registrato | Fatti | Modo |
//! |---|---|---|
//! | recuperato | con un'operazione registrata | recuperato, con istante, intervallo e operatore |
//! | recuperato | senza operazione (prima di PR-07) | recuperato: «operatore e intervallo non registrati» |
//! | osservato | la copertura della fonte era coperta nell'istante di pubblicazione | dal vivo |
//! | osservato | altrimenti | non determinabile |
//!
//! **Non si inferisce altro.** Nessun valore predefinito «dal vivo», nessuna
//! deduzione dalla distanza fra pubblicazione e acquisizione, nessun operatore o
//! intervallo plausibile per i recuperi anteriori.
//!
//! # La versione, e la sua impronta
//!
//! [`ACQUISITION_MODE_VERSION`] numera il criterio; [`ACQUISITION_MODE_FINGERPRINT`]
//! è l'impronta del codice di [`derive`]. Chi lo cambia vede fallire una prova
//! che dice di alzare la versione.

use std::collections::BTreeMap;

use lisi_core::model::coverage::{Coverage, CoverageState};
use lisi_core::model::{AcquisitionMode, AcquisitionOrigin};
use lisi_core::{SessionId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::recovery_operation::StoredRecovery;

use crate::error::ServiceResult;

/// La versione del criterio «Modo di acquisizione».
pub const ACQUISITION_MODE_VERSION: u32 = 1;

/// L'impronta del codice di [`derive`] alla versione
/// [`ACQUISITION_MODE_VERSION`].
pub const ACQUISITION_MODE_FINGERPRINT: &str =
    "9cd63087bfcded1b305ae697aee00b3648ce15f8d7dc82946ba96d3d57755c16";

// ---------------------------------------------------------- criterio: inizio

/// Il modo di un contenuto, dai fatti (funzione pura).
///
/// `copertura` è quella della **sua fonte** dentro il **suo** monitoraggio
/// (PR-05). Si confronta con l'istante di pubblicazione; non se ne ricava
/// altro.
#[must_use]
pub fn derive(
    percorso: AcquisitionOrigin,
    archiviato_il: Timestamp,
    pubblicato_il: Timestamp,
    recupero: Option<&StoredRecovery>,
    copertura: &Coverage,
) -> AcquisitionMode {
    match percorso {
        AcquisitionOrigin::Recovered => match recupero {
            Some(operazione) => AcquisitionMode::Recovered {
                at: operazione.performed_at,
                interval: operazione.interval,
                operator: Some(operazione.requested_by.clone()),
            },
            // Un recupero anteriore a PR-07: l'istante di archiviazione è
            // registrato, chi e per quale intervallo no.
            None => AcquisitionMode::Recovered {
                at: archiviato_il,
                interval: None,
                operator: None,
            },
        },
        AcquisitionOrigin::Observed => {
            let si_ascoltava = copertura.intervals().iter().any(|tratto| {
                tratto.state == CoverageState::Covered
                    && tratto.from <= pubblicato_il
                    && pubblicato_il < tratto.to
            });
            if si_ascoltava {
                AcquisitionMode::Live
            } else {
                AcquisitionMode::Undetermined
            }
        }
    }
}

// ------------------------------------------------------------ criterio: fine

/// Come il modo si dichiara, sullo schermo e nei documenti: la frase e, per un
/// contenuto recuperato, ciò che il recupero non vede. **Una sola
/// composizione**, perché l'atto non dica una cosa diversa dalla schermata.
#[must_use]
pub fn declared(modo: &AcquisitionMode) -> String {
    if modo.is_recovered() {
        format!(
            "{} {}",
            modo.as_sentence(),
            lisi_core::model::RECOVERY_LIMITS
        )
    } else {
        modo.as_sentence()
    }
}

/// La parola breve, per una riga di elenco.
#[must_use]
pub const fn short_label(modo: &AcquisitionMode) -> &'static str {
    match modo {
        AcquisitionMode::Live => "dal vivo",
        AcquisitionMode::Recovered { .. } => "recuperato",
        AcquisitionMode::Undetermined => "modo non determinabile",
    }
}

/// Il modo di ogni contenuto di un monitoraggio, alla fotografia `until`.
///
/// # Errori
///
/// Restituisce un errore se una lettura non riesce.
pub fn for_session(
    database: &Database,
    session_id: SessionId,
    until: Timestamp,
) -> ServiceResult<BTreeMap<i64, AcquisitionMode>> {
    let copertura = crate::coverage::for_monitoring(database, session_id, until)?;
    let recuperi = database.session_recoveries(session_id)?;
    let vuota = Coverage::empty();
    let mut modi = BTreeMap::new();
    for contenuto in database.session_contents(session_id)? {
        let della_fonte = copertura
            .sources
            .iter()
            .find(|(fonte, _, _)| *fonte == contenuto.source_id)
            .map_or(&vuota, |(_, _, tratti)| tratti);
        modi.insert(
            contenuto.id.get(),
            derive(
                contenuto.origin,
                contenuto.acquired_at,
                contenuto.published_at,
                recuperi.get(&contenuto.id.get()),
                della_fonte,
            ),
        );
    }
    Ok(modi)
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::digest::Sha256Digest;
    use lisi_core::model::coverage::{
        Coverage, CoverageInterval, CoverageState, UndeterminedReason,
    };
    use lisi_core::model::{AcquisitionMode, AcquisitionOrigin};
    use lisi_storage::repository::recovery_operation::StoredRecovery;

    use super::{ACQUISITION_MODE_FINGERPRINT, ACQUISITION_MODE_VERSION, derive};

    const THIS_MODULE: &str = include_str!("acquisition_mode.rs");

    fn t(ore: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + ore * 3_600_000)
    }

    /// Coperta dalle 0 alle 10, non determinabile dalle 10 alle 12.
    fn copertura() -> Coverage {
        let Some(copertura) = Coverage::build(vec![
            CoverageInterval {
                from: t(0),
                to: t(10),
                state: CoverageState::Covered,
            },
            CoverageInterval {
                from: t(10),
                to: t(12),
                state: CoverageState::Undetermined(UndeterminedReason::ConnectionRestored),
            },
        ]) else {
            panic!("tratti contigui");
        };
        copertura
    }

    fn operazione() -> StoredRecovery {
        StoredRecovery {
            operation_id: 1,
            interval: Some((t(10), t(12))),
            requested_by: String::from("operatore.prova"),
            performed_at: t(20),
        }
    }

    /// Il codice del criterio, fra i due segni.
    fn criterio() -> &'static str {
        let (Some(inizio), Some(fine)) = (
            THIS_MODULE.find(
                "// ---------------------------------------------------------- criterio: inizio",
            ),
            THIS_MODULE.find(
                "// ------------------------------------------------------------ criterio: fine",
            ),
        ) else {
            panic!("i segni del criterio devono esserci");
        };
        &THIS_MODULE[inizio..fine]
    }

    /// **Dal vivo soltanto dove si ascoltava**; altrimenti non determinabile,
    /// mai dal vivo (controlli negativi 8 e 10).
    #[test]
    fn dal_vivo_soltanto_dove_si_ascoltava() {
        assert_eq!(
            derive(AcquisitionOrigin::Observed, t(5), t(5), None, &copertura()),
            AcquisitionMode::Live
        );
        // Pubblicato mentre il collegamento mancava, e arrivato un minuto dopo:
        // la distanza è piccola, e non conta.
        assert_eq!(
            derive(
                AcquisitionOrigin::Observed,
                Timestamp::from_millis(t(11).as_millis() + 60_000),
                t(11),
                None,
                &copertura()
            ),
            AcquisitionMode::Undetermined
        );
        // Prima dell'inizio della copertura.
        assert_eq!(
            derive(AcquisitionOrigin::Observed, t(1), t(-1), None, &copertura()),
            AcquisitionMode::Undetermined
        );
    }

    /// **Un recupero resta un recupero**, e un recupero anteriore a PR-07 non
    /// riceve un operatore né un intervallo (controlli negativi 1 e 9).
    #[test]
    fn un_recupero_resta_un_recupero() {
        let con = derive(
            AcquisitionOrigin::Recovered,
            t(20),
            t(5),
            Some(&operazione()),
            &copertura(),
        );
        assert!(con.is_recovered() && !con.is_live());
        assert!(
            con.as_sentence().contains("da operatore.prova"),
            "{}",
            con.as_sentence()
        );

        let senza = derive(
            AcquisitionOrigin::Recovered,
            t(20),
            t(5),
            None,
            &copertura(),
        );
        assert_eq!(
            senza,
            AcquisitionMode::Recovered {
                at: t(20),
                interval: None,
                operator: None,
            }
        );
        assert!(
            senza
                .as_sentence()
                .contains("operatore e intervallo non registrati")
        );
    }

    /// **Il criterio non deduce dalla distanza fra pubblicazione e
    /// acquisizione** (controllo negativo 8), e non legge l'orologio.
    #[test]
    fn il_criterio_non_deduce_dalla_distanza() {
        let codice = criterio();
        for vietato in ["as_millis()", "millis_since", "now("] {
            assert!(!codice.contains(vietato), "«{vietato}» nel criterio");
        }
    }

    /// **Il criterio non cambia senza cambiare versione.**
    #[test]
    fn l_impronta_del_criterio_corrisponde_al_codice() {
        let calcolata = Sha256Digest::of_text(criterio()).as_str().to_owned();
        assert_eq!(
            calcolata, ACQUISITION_MODE_FINGERPRINT,
            "il criterio del modo di acquisizione è cambiato: se è cambiato davvero, alzare \
             ACQUISITION_MODE_VERSION (oggi {ACQUISITION_MODE_VERSION}); poi sostituire \
             ACQUISITION_MODE_FINGERPRINT con:\n\n  \"{calcolata}\""
        );
    }
}

//! Collegamento fra la sezione «Conservazione» e il servizio omonimo.
//!
//! Come gli altri moduli di collegamento non contiene logica: traduce la
//! politica conservata in proprietà dell'interfaccia e le scelte dell'operatore
//! in chiamate al servizio.
//!
//! # Perché il servizio sta dietro un `RefCell`
//!
//! Applicare la conservazione cancella, e cancellare richiede l'archivio in
//! scrittura esclusiva. Gli altri collegamenti tengono un servizio condiviso in
//! sola lettura; qui serve il prestito mutabile, e la cella lo rende esplicito
//! invece di nasconderlo.
//!
//! # Le due proprietà separate
//!
//! `retention-preview` dice **quanto sparirebbe** e si aggiorna a ogni scelta;
//! `retention-message` dice che cosa è successo dopo un comando. Una sola
//! proprietà farebbe scambiare una previsione per un esito.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::retention::RetentionPolicy;
use lisi_services::retention::RetentionPreview;
use lisi_services::retention::RetentionService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::AppWindow;

/// Servizio della conservazione condiviso fra i gestori.
pub type SharedRetention = Rc<RefCell<RetentionService>>;

/// Crea il servizio della conservazione sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedRetention> {
    Some(Rc::new(RefCell::new(RetentionService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> lisi_services::ServiceResult<lisi_core::text::Actor> {
    crate::operator::audit_actor()
}

/// Etichette delle politiche proposte, nell'ordine del dominio.
fn options() -> ModelRc<SharedString> {
    let labels: Vec<SharedString> = RetentionPolicy::presets()
        .iter()
        .map(|policy| crate::lingua::schermo(policy.label()))
        .collect();
    ModelRc::from(Rc::new(VecModel::from(labels)))
}

/// Politica corrispondente all'indice scelto nell'interfaccia.
///
/// Un indice fuori elenco diventa «si conserva tutto»: davanti a una scelta che
/// non si capisce, la cosa prudente è **non cancellare nulla**.
fn policy_from_index(index: i32) -> RetentionPolicy {
    usize::try_from(index)
        .ok()
        .and_then(|position| RetentionPolicy::presets().get(position).copied())
        .unwrap_or(RetentionPolicy::Unlimited)
}

/// Indice dell'interfaccia corrispondente a una politica.
///
/// Una politica scelta a mano e non fra quelle proposte — possibile in archivio
/// — non ha un indice: si ricade su «si conserva tutto», che è la prima voce, e
/// il testo della conseguenza continua a dire la verità perché viene dalla
/// politica reale, non dall'indice.
fn index_of_policy(policy: RetentionPolicy) -> i32 {
    RetentionPolicy::presets()
        .iter()
        .position(|preset| *preset == policy)
        .and_then(|position| i32::try_from(position).ok())
        .unwrap_or(0)
}

/// Perché restano contenuti più vecchi del limite, detto con i numeri.
///
/// Vuota quando non ne resta nessuno. Un contenuto vecchio che sopravvive
/// senza spiegazione sembra un guasto: la ragione va detta dove si vede il
/// numero (ADR-0133).
fn retained_text(preview: &RetentionPreview, verbo: &str) -> String {
    let mut testo = String::new();
    if preview.preserved_because_history > 0 {
        testo.push_str(&format!(
            " {} {verbo} anche se più vecchi del limite: hanno versioni successive o una \
             fotografia del contesto, e la loro storia non si cancella.",
            preview.preserved_because_history
        ));
    }
    if preview.preserved_because_cited > 0 {
        testo.push_str(&format!(
            " Altri {} {verbo}: sono citati da un documento già prodotto.",
            preview.preserved_because_cited
        ));
    }
    testo
}

/// L'anteprima, detta in una frase che si legge senza contare.
fn preview_text(policy: RetentionPolicy, preview: &RetentionPreview) -> String {
    if policy == RetentionPolicy::Unlimited {
        return String::new();
    }
    if preview.is_empty() && preview.retained() == 0 {
        return String::from(
            "Con questa scelta non c'è nulla da togliere: nessun contenuto è più vecchio del limite.",
        );
    }
    if preview.is_empty() {
        return format!(
            "Con questa scelta non si toglie nulla.{}",
            retained_text(preview, "restano")
        );
    }

    format!(
        "Con questa scelta sparirebbero {} contenuti, con {} corrispondenze e {} avvisi.{}",
        preview.contents,
        preview.matches,
        preview.alerts,
        retained_text(preview, "restano")
    )
}

/// L'esito di una cancellazione, detto in una frase.
///
/// Non dice mai che la conservazione è completa quando qualcosa è stato
/// trattenuto: dice che è stata applicata dove era possibile (ADR-0133).
fn applied_text(preview: &RetentionPreview) -> String {
    if preview.is_empty() && preview.retained() == 0 {
        return String::from("Non c'era nulla da togliere.");
    }
    if preview.is_empty() {
        return format!(
            "Non è stato tolto nulla.{}",
            retained_text(preview, "sono rimasti")
        );
    }
    let dove = if preview.retained() > 0 {
        " La conservazione è stata applicata solo dove era possibile."
    } else {
        ""
    };
    format!(
        "Tolti {} contenuti, con {} corrispondenze e {} avvisi.{dove}{} L'archivio è stato \
         ricompattato, quindi lo spazio è tornato libero. L'operazione è scritta nel registro \
         delle operazioni.",
        preview.contents,
        preview.matches,
        preview.alerts,
        retained_text(preview, "sono rimasti")
    )
}

/// Riporta nell'interfaccia la politica **conservata**.
pub fn refresh(window: &AppWindow, retention: &SharedRetention, message: Option<&str>) {
    if let Some(text) = message {
        window.set_retention_message(SharedString::from(text));
    }
    window.set_retention_options(options());

    let service = retention.borrow();
    let policy = match service.policy() {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(
                kind = error.kind(),
                "politica di conservazione non leggibile"
            );
            window.set_retention_message(crate::lingua::schermo(error.operator_message()));
            // Non leggibile non è «severa»: si mostra la scelta prudente,
            // perché una schermata che dichiarasse un limite inesistente
            // inviterebbe a fidarsene.
            RetentionPolicy::Unlimited
        }
    };

    window.set_retention_index(index_of_policy(policy));
    show_policy(window, &service, policy);
}

/// Mostra conseguenza e anteprima della politica indicata, senza salvarla.
///
/// Serve sia alla rilettura sia al cambio di scelta: **guardare non salva**, e
/// chi sposta il selettore deve poter leggere che cosa comporterebbe prima di
/// impegnarsi.
fn show_policy(window: &AppWindow, service: &RetentionService, policy: RetentionPolicy) {
    window.set_retention_consequence(crate::lingua::schermo(policy.consequence()));

    match service.preview(policy, now()) {
        Ok(preview) => {
            window.set_retention_preview(SharedString::from(preview_text(policy, &preview)));
            window.set_retention_has_work(!preview.is_empty());
        }
        Err(error) => {
            tracing::warn!(
                kind = error.kind(),
                "anteprima della conservazione non riuscita"
            );
            window.set_retention_preview(crate::lingua::schermo(
                "Non è stato possibile contare che cosa verrebbe tolto.",
            ));
            // Senza conteggio il comando resta spento: offrire una
            // cancellazione di cui non si sa la portata è peggio che non
            // offrirla.
            window.set_retention_has_work(false);
        }
    }
}

/// La dimensione dell'archivio, detta come la si dice a voce.
///
/// Non in byte: «2 281 472 byte» non si legge, e chi deve decidere se
/// preoccuparsi ragiona in megabyte.
fn size_text(size_bytes: Option<u64>) -> String {
    let Some(byte) = size_bytes else {
        return String::from("Archivio in memoria: non occupa spazio su disco.");
    };
    let mega = byte as f64 / (1024.0 * 1024.0);
    if mega < 1.0 {
        return String::from("L'archivio occupa meno di un megabyte.");
    }
    format!("L'archivio occupa circa {mega:.0} MB.")
}

/// Riporta nell'interfaccia l'esito di una verifica dell'archivio.
fn show_integrity(window: &AppWindow, retention: &SharedRetention) {
    let rapporto = retention.borrow().verify_integrity();
    window.set_archive_size(SharedString::from(size_text(rapporto.size_bytes)));
    window.set_archive_message(crate::lingua::schermo(rapporto.operator_message()));
    window.set_archive_damaged(!rapporto.is_healthy());
    window.set_archive_checked(true);
}

/// Collega i comandi della sezione al servizio.
pub fn wire(window: &AppWindow, retention: &SharedRetention) {
    {
        let handle = window.as_weak();
        let retention = Rc::clone(retention);
        window.on_verify_archive(move || {
            if crate::lock::refuse_while_locked("verify_archive") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                show_integrity(&window, &retention);
            }
        });
    }

    {
        let handle = window.as_weak();
        let retention = Rc::clone(retention);
        window.on_retention_chosen(move |index| {
            if crate::lock::refuse_while_locked("retention_chosen") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let service = retention.borrow();
            show_policy(&window, &service, policy_from_index(index));
            // La scelta non è ancora salvata, e la schermata lo dice: un
            // selettore che si muove senza conseguenze visibili farebbe credere
            // che la politica sia già cambiata.
            window.set_retention_message(crate::lingua::schermo(
                "Scelta non ancora salvata. Premi «Salva la conservazione».",
            ));
        });
    }

    {
        let handle = window.as_weak();
        let retention = Rc::clone(retention);
        window.on_save_retention(move || {
            if crate::lock::refuse_while_locked("save_retention") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let policy = policy_from_index(window.get_retention_index());
            let outcome = {
                let service = retention.borrow();
                actor().and_then(|actor| service.save_policy(policy, &actor, now()))
            };

            let message = match outcome {
                Ok(()) => String::from(
                    "Conservazione salvata. Nulla è stato cancellato: per farlo usa il comando accanto.",
                ),
                Err(error) => {
                    tracing::warn!(kind = error.kind(), "conservazione non salvata");
                    error.operator_message()
                }
            };
            refresh(&window, &retention, Some(&message));
        });
    }

    {
        let handle = window.as_weak();
        let retention = Rc::clone(retention);
        window.on_apply_retention(move || {
            if crate::lock::refuse_while_locked("apply_retention") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Si applica la politica **conservata**, non quella selezionata: se
            // l'operatore ha spostato il selettore senza salvare, cancellare
            // secondo la selezione toglierebbe materiale in base a una scelta
            // che non ha mai confermato.
            let outcome = {
                let mut service = retention.borrow_mut();
                actor().and_then(|actor| service.apply(&actor, now()))
            };

            let message = match outcome {
                Ok(preview) => applied_text(&preview),
                Err(error) => {
                    tracing::warn!(kind = error.kind(), "conservazione non applicata");
                    error.operator_message()
                }
            };
            refresh(&window, &retention, Some(&message));
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::retention::{RetentionDays, RetentionPolicy};
    use lisi_services::retention::RetentionPreview;

    use super::{applied_text, index_of_policy, policy_from_index, preview_text};

    fn politica(giorni: u32) -> RetentionPolicy {
        let Ok(giorni) = RetentionDays::try_new(giorni) else {
            panic!("i giorni di prova devono essere ammessi");
        };
        RetentionPolicy::Days(giorni)
    }

    #[test]
    fn la_dimensione_si_legge_senza_contare_gli_zeri() {
        // «2 281 472 byte» non si legge, e chi deve decidere se preoccuparsi
        // ragiona in megabyte.
        assert!(super::size_text(Some(50 * 1024 * 1024)).contains("50 MB"));
        assert!(super::size_text(Some(1_000)).contains("meno di un megabyte"));
        assert!(super::size_text(None).contains("memoria"));
    }

    #[test]
    fn un_indice_fuori_elenco_non_cancella_nulla() {
        // Davanti a una scelta che non si capisce, la cosa prudente e' non
        // cancellare. Un indice sbagliato che diventasse «un giorno»
        // svuoterebbe l'archivio.
        assert_eq!(policy_from_index(-1), RetentionPolicy::Unlimited);
        assert_eq!(policy_from_index(9_999), RetentionPolicy::Unlimited);
    }

    #[test]
    fn ogni_politica_proposta_ritrova_il_proprio_indice() {
        for policy in RetentionPolicy::presets() {
            assert_eq!(
                policy_from_index(index_of_policy(policy)),
                policy,
                "{policy:?} non ritrova se' stessa"
            );
        }
    }

    #[test]
    fn conservare_tutto_non_promette_alcuna_cancellazione() {
        let preview = RetentionPreview::default();
        assert!(
            preview_text(RetentionPolicy::Unlimited, &preview).is_empty(),
            "con «tutto» non si mostra alcuna anteprima di cancellazione"
        );
    }

    #[test]
    fn l_anteprima_dice_i_numeri_e_dice_chi_resta_perche_citato() {
        // Un contenuto vecchio che sopravvive senza spiegazione sembra un
        // guasto. La ragione va detta dove si vede il numero.
        let preview = RetentionPreview {
            contents: 12,
            matches: 30,
            alerts: 4,
            notifications: 2,
            preserved_because_cited: 3,
            preserved_because_history: 0,
        };
        let testo = preview_text(politica(30), &preview);
        assert!(
            testo.contains("12"),
            "manca il numero dei contenuti: «{testo}»"
        );
        assert!(
            testo.contains('3'),
            "manca il numero dei risparmiati: «{testo}»"
        );
        assert!(
            testo.contains("citati"),
            "non dice PERCHE' restano: «{testo}»"
        );
    }

    #[test]
    fn un_esito_vuoto_lo_dice_invece_di_fingere_un_lavoro() {
        let testo = applied_text(&RetentionPreview::default());
        assert!(
            testo.contains("Non c'era nulla"),
            "un esito vuoto deve dirlo: «{testo}»"
        );
        assert!(
            !testo.contains("Tolti"),
            "non deve annunciare una cancellazione che non c'e' stata: «{testo}»"
        );
    }

    #[test]
    fn un_esito_reale_rimanda_all_audit() {
        // Chi ha appena cancellato del materiale deve sapere che ne resta
        // traccia, e dove.
        let preview = RetentionPreview {
            contents: 5,
            matches: 9,
            alerts: 1,
            notifications: 0,
            preserved_because_cited: 0,
            preserved_because_history: 0,
        };
        let testo = applied_text(&preview);
        assert!(testo.contains('5'));
        assert!(
            testo.contains("registro delle operazioni"),
            "l'esito non dice dove resta la traccia: «{testo}»"
        );
        assert!(
            testo.contains("spazio"),
            "chi cancella per liberare spazio deve sapere che e' tornato: «{testo}»"
        );
    }

    /// **D-17 (ADR-0133): ciò che resta per la sua storia si dice, con il
    /// numero e con la ragione**, nell'anteprima e nell'esito.
    #[test]
    fn i_trattenuti_per_la_storia_si_dicono_e_non_si_annuncia_una_conservazione_completa() {
        let parziale = RetentionPreview {
            contents: 5,
            matches: 9,
            alerts: 1,
            notifications: 0,
            preserved_because_cited: 0,
            preserved_because_history: 2,
        };
        let anteprima = preview_text(politica(30), &parziale);
        assert!(
            anteprima.contains('2') && anteprima.contains("storia"),
            "{anteprima}"
        );
        let esito = applied_text(&parziale);
        assert!(esito.contains("solo dove era possibile"), "{esito}");
        assert!(esito.contains("storia"), "{esito}");
        assert!(!esito.to_lowercase().contains("complet"), "{esito}");
    }

    /// Con **soli** trattenuti nulla si toglie, ma non è vero che «nessun
    /// contenuto è più vecchio del limite»: la frase lo direbbe, e mentirebbe.
    #[test]
    fn con_soli_trattenuti_non_si_dice_che_nulla_e_vecchio() {
        let soli = RetentionPreview {
            preserved_because_history: 3,
            ..RetentionPreview::default()
        };
        let anteprima = preview_text(politica(30), &soli);
        assert!(
            !anteprima.contains("nessun contenuto è più vecchio"),
            "{anteprima}"
        );
        assert!(anteprima.contains('3'), "{anteprima}");
        let esito = applied_text(&soli);
        assert!(!esito.contains("Non c'era nulla"), "{esito}");
        assert!(
            esito.contains("Non è stato tolto nulla") && esito.contains('3'),
            "{esito}"
        );
    }
}

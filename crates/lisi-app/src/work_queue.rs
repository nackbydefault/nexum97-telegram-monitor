//! Collegamento fra la schermata «Coda di lavoro» e il servizio che la compone.
//!
//! Come gli altri moduli dell'interfaccia, non contiene logica: traduce la coda
//! composta dal servizio in righe, e il comando «Aggiorna» in una nuova
//! composizione.
//!
//! # Che cosa questo modulo non fa, e non per dimenticanza
//!
//! **Non assegna nulla a nessuno.** Non esiste «Prendi in carico» perché non
//! esiste ancora un'identità di operatore autenticata: su questa postazione chi
//! agisce è un segnaposto ([`crate::operator`]), e un'assegnazione fatta a un
//! segnaposto direbbe che qualcuno ha preso in carico qualcosa quando nessuno
//! lo ha fatto.
//!
//! **Non mostra un numero di priorità.** Ogni riga porta i fatti che l'hanno
//! collocata dov'è, nella stessa precedenza in cui l'ordine li guarda.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_services::work_queue::WorkQueueService;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, QueueRow};

/// Servizio della coda, condiviso fra i gestori dei comandi.
pub type SharedWorkQueue = Rc<RefCell<WorkQueueService>>;

/// Crea il servizio della coda sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedWorkQueue> {
    Some(Rc::new(RefCell::new(WorkQueueService::new(database))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn adesso() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Compone la coda e la riporta nell'interfaccia.
pub fn refresh(window: &AppWindow, queue: &SharedWorkQueue) {
    let now = adesso();
    let Ok(coda) = queue.borrow().compose(now) else {
        tracing::warn!("coda di lavoro non componibile: la schermata resta vuota");
        window.set_work_queue(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        window.set_work_queue_summary(crate::lingua::schermo(
            "Non è stato possibile comporre la coda di lavoro.",
        ));
        window.set_work_queue_composed_at(SharedString::default());
        return;
    };

    let righe: Vec<QueueRow> = coda
        .items
        .iter()
        .map(|item| QueueRow {
            source: SharedString::from(item.source_name.as_str()),
            session: crate::lingua::schermo(format!("Sessione «{}»", item.session_label)),
            level_label: crate::lingua::schermo(format!("Livello {}", item.level)),
            level: i32::from(item.level),
            state: crate::lingua::schermo(item.state_label()),
            untouched: item.is_untouched(),
            why_here: SharedString::from(item.why_here(now)),
            reason: SharedString::from(item.reason.as_str()),
            excerpt: SharedString::from(crate::history::excerpt(&item.body)),
            content_id: i32::try_from(item.content_id.get()).unwrap_or(0),
        })
        .collect();

    window.set_work_queue_summary(crate::lingua::schermo(coda.as_sentence()));
    window.set_work_queue_composed_at(crate::lingua::schermo(format!(
        "Composta il {}.",
        coda.composed_at.to_readable_local()
    )));
    window.set_work_queue(ModelRc::from(Rc::new(VecModel::from(righe))));
    // I periodi non coperti prioritari stanno nel loro modulo (PR-06): una
    // priorita' tecnica non si mescola al codice che ordina i contenuti.
    crate::gaps::show(window, queue, now);
}

/// Registra i gestori dei comandi della schermata.
pub fn wire(window: &AppWindow, queue: &SharedWorkQueue) {
    {
        // All'ingresso la coda si ricompone: una coda vecchia in una schermata
        // che dice che cosa aspetta ADESSO manderebbe a lavorare su qualcosa
        // che qualcun altro ha già chiuso.
        let weak = window.as_weak();
        let queue = Rc::clone(queue);
        window.on_work_queue_shown(move || {
            let Some(window) = weak.upgrade() else { return };
            refresh(&window, &queue);
        });
    }

    {
        let weak = window.as_weak();
        let queue = Rc::clone(queue);
        window.on_refresh_work_queue(move || {
            if crate::lock::refuse_while_locked("refresh_work_queue") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            refresh(&window, &queue);
        });
    }

    crate::gaps::wire(window, queue);
}

#[cfg(test)]
mod guardie {
    /// Il file dell'interfaccia, per le guardie testuali.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Questo modulo, per verificare che cosa il codice di produzione fa.
    const THIS_MODULE: &str = include_str!("work_queue.rs");

    /// Il codice di produzione **senza i commenti**.
    ///
    /// Le guardie cercano parole che il codice non deve contenere, e la prosa
    /// che spiega perché non deve contenerle le nomina per forza.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod guardie {") else {
            panic!("il modulo deve avere un blocco di guardie riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// L'indice della pagina «Coda di lavoro» nell'interfaccia.
    const CODA_PAGE: i32 = 18;

    /// **La sola** pagina che questa guardia sorveglia.
    ///
    /// Fino al 2026-09-21 guardava tutta l'interfaccia, perché in tutta
    /// l'interfaccia non esisteva un'identità di persona autenticata. Da
    /// TEAM-ASSIGN-01 esiste **sull'Hub**, e la Revisione condivisa assegna il
    /// lavoro a persone che si sono dimostrate (ADR-0097, ADR-0098).
    ///
    /// La proprietà non è stata indebolita: è cambiata. Qui, su una postazione
    /// sola, non c'è nessuno che si dimostri, e assegnare direbbe ancora una
    /// cosa che nessuno può verificare.
    fn pagina_della_coda() -> String {
        let pagina =
            crate::page_guard::corpo_della_pagina(u32::try_from(CODA_PAGE).unwrap_or_default());
        assert!(
            pagina.contains("Questa coda non assegna nulla a nessuno"),
            "la guardia non sta guardando la pagina che crede"
        );
        pagina
    }

    /// Le righe che un operatore **legge** nella coda di lavoro.
    ///
    /// # Perché comprende anche le etichette dei comandi
    ///
    /// Perché il primo controllo negativo di questa milestone ha aggiunto un
    /// pulsante «Prendi in carico» e la guardia **non è diventata rossa**:
    /// guardava le righe `text:` e non quelle `label:`. Era la prova a essere
    /// debole, non il codice a essere buono — e un comando è precisamente la
    /// forma in cui un'assegnazione comparirebbe.
    fn testi_mostrati() -> Vec<String> {
        pagina_della_coda()
            .lines()
            .map(str::trim)
            .filter(|riga| {
                riga.starts_with("text:") || riga.starts_with("label:") || riga.starts_with("+ \"")
            })
            .map(str::to_owned)
            .collect()
    }

    /// **La coda di una postazione sola non offre di prendere in carico
    /// nulla.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un comando «Prendi in carico» su una postazione senza identità di
    /// operatore autenticata scriverebbe «preso in carico» accanto a un
    /// segnaposto. Due operatori sulla stessa macchina lo leggerebbero come una
    /// persona, e il lavoro che ciascuno pensa dell'altro non lo farebbe
    /// nessuno.
    ///
    /// # Perché adesso guarda una pagina sola
    ///
    /// Perché da TEAM-ASSIGN-01 l'assegnazione **esiste**, dove una persona si
    /// dimostra: sull'Hub, nella Revisione condivisa. Questa guardia è stata
    /// vista rossa e **sostituita**, non tolta: qui, dove nessuno si dimostra,
    /// il divieto vale ancora.
    #[test]
    fn la_schermata_non_offre_di_prendere_in_carico() {
        for vietato in ["Prendi in carico", "Assegna", "Assegnato a", "Revoca"] {
            for riga in testi_mostrati() {
                assert!(
                    !riga.contains(vietato),
                    "l'interfaccia mostra «{vietato}»: senza un'identità di operatore \
                     autenticata l'assegnazione direbbe una cosa che nessuno può \
                     verificare — «{riga}»"
                );
            }
        }

        let codice = codice_senza_commenti();
        for vietato in ["assignee", "assign(", "take_charge"] {
            assert!(
                !codice.contains(vietato),
                "la schermata nomina «{vietato}»: l'assegnazione arriva con \
                 TEAM-ASSIGN-01, dopo l'identità"
            );
        }
    }

    /// **La schermata dichiara perché non assegna.**
    ///
    /// Un'assenza non spiegata si legge come una mancanza, e chi la nota
    /// chiede di colmarla. Detta con la ragione, diventa una scelta.
    #[test]
    fn la_schermata_dichiara_perche_non_assegna() {
        assert!(
            UI.contains("Questa coda non assegna nulla a nessuno"),
            "il limite va dichiarato nella schermata, non solo nel codice"
        );
        assert!(
            UI.contains("nessun operatore entra con un proprio accesso"),
            "va detta la ragione, non solo il fatto"
        );
    }

    /// **Nessun numero di priorità è mostrato.**
    ///
    /// Il numero mostrato è il **livello** che il motore ha assegnato al
    /// contenuto, e la riga lo scrive per esteso: «Livello 3». Un secondo
    /// numero, composto per ordinare, si leggerebbe come una misura di gravità.
    #[test]
    fn la_coda_non_mostra_alcun_punteggio() {
        let codice = codice_senza_commenti();
        for vietato in ["score", "punteggio", "priority"] {
            assert!(
                !codice.contains(vietato),
                "la schermata nomina «{vietato}»: l'ordine è un confronto fra fatti"
            );
        }

        // LE RIGHE DEI CONTENUTI, e non quelle dei periodi. Da PR-06 la pagina
        // ha anche i periodi non coperti prioritari, e il piano chiede per
        // quelli una priorità TECNICA detta per quello che è (ADR-0122,
        // DEC-363): la loro guardia sta in `crate::gaps`, e pretende la parola
        // insieme a «tecnica». Qui il divieto resta intero su ciò che aveva
        // sempre protetto: l'ordine dei contenuti.
        let pagina = pagina_della_coda();
        let Some((contenuti, _)) = pagina.split_once("PERIODI NON COPERTI PRIORITARI") else {
            panic!("la sezione dei periodi deve essere riconoscibile, dopo i contenuti");
        };
        let testi: Vec<&str> = contenuti
            .lines()
            .map(str::trim)
            .filter(|riga| {
                riga.starts_with("text:") || riga.starts_with("label:") || riga.starts_with("+ \"")
            })
            .collect();
        assert!(
            testi.len() >= 5,
            "la guardia non sta leggendo le righe dei contenuti"
        );
        for riga in testi {
            for vietato in ["Priorità", "Punteggio", "Urgenza"] {
                assert!(
                    !riga.contains(vietato),
                    "l'interfaccia mostra «{vietato}»: la riga dice i fatti che la \
                     collocano, non un giudizio riassunto — «{riga}»"
                );
            }
        }
    }

    /// Ogni riga dice perché sta dov'è.
    #[test]
    fn ogni_riga_dice_perche_sta_dov_e() {
        assert!(
            UI.contains("text: riga.why-here;"),
            "i fatti che collocano la riga devono essere mostrati"
        );
    }

    /// Comporre la coda non scrive nulla.
    ///
    /// Guardare il lavoro non è lavoro: se aprirla registrasse qualcosa,
    /// l'atto di guardare cambierebbe ciò che si sta guardando.
    #[test]
    fn guardare_la_coda_non_la_cambia() {
        let codice = codice_senza_commenti();

        for scrittura in ["insert_review", "append_audit", "record(", "insert_alert"] {
            assert!(
                !codice.contains(scrittura),
                "la schermata della coda chiama «{scrittura}»: guardare il lavoro \
                 non è lavoro"
            );
        }
    }
}

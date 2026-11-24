//! Che cosa stavamo guardando, sullo schermo (PR-05, ADR-0121).
//!
//! # Due forme della stessa cosa
//!
//! La **barra** — i tratti in proporzione alla finestra — e le **parole** — i
//! tratti non coperti o non determinabili, con il perché. La barra si legge a
//! colpo d'occhio; le parole si leggono con una tecnologia assistiva e si
//! copiano in un atto. Nessuna delle due senza l'altra.
//!
//! # In Team
//!
//! Una postazione che segue un Hub mostra la **propria** copertura, e lo dice
//! (ADR-0121, decisione 6): la copertura dell'ufficio la conosce l'Hub.

use lisi_core::Timestamp;
use lisi_core::model::coverage::{COVERAGE_MEANING, Coverage, CoverageState};

use crate::{StatoCopertura, TrattoCopertura, TrattoRecuperato};

/// La finestra della schermata Fonti, in giorni.
pub const WINDOW_DAYS: i64 = 7;

const GIORNO: i64 = 24 * 60 * 60 * 1_000;

/// L'inizio della finestra della schermata Fonti.
#[must_use]
pub const fn window_start(until: Timestamp) -> Timestamp {
    Timestamp::from_millis(until.as_millis() - WINDOW_DAYS * GIORNO)
}

/// La frase che fissa il senso della copertura: la stessa dei documenti.
#[must_use]
pub const fn meaning() -> &'static str {
    COVERAGE_MEANING
}

/// La nota che in Team dice di chi è la copertura mostrata.
///
/// Vuota fuori dal Team. **Non si toglie in Team**: mostrare la copertura di
/// una postazione come quella dell'ufficio direbbe che l'ufficio non guardava
/// quando guardava un collega (PR-05, controllo negativo 3).
#[must_use]
pub const fn scope_note(in_team: bool) -> &'static str {
    if in_team {
        "Questa è la copertura di questa postazione, non quella dell'ufficio: quella la \
         conosce l'Hub."
    } else {
        ""
    }
}

/// Se la postazione segue un Hub.
#[must_use]
pub fn in_team() -> bool {
    lisi_services::hub_client::HubConnectionStore::default_location()
        .is_ok_and(|configurazione| configurazione.exists())
}

/// I tratti della barra, in frazioni della finestra `[from, until)`.
#[must_use]
pub fn bar(copertura: &Coverage, from: Timestamp, until: Timestamp) -> Vec<TrattoCopertura> {
    let totale = until.as_millis() - from.as_millis();
    if totale <= 0 {
        return Vec::new();
    }
    // Le misure sono millisecondi di una finestra di giorni: stanno ben dentro
    // la precisione di un `f64`, e la barra le vuole in frazioni.
    let frazione = |millis: i64| ((millis as f64) / (totale as f64)) as f32;
    copertura
        .intervals()
        .iter()
        .map(|tratto| TrattoCopertura {
            inizio: frazione(tratto.from.as_millis() - from.as_millis()),
            ampiezza: frazione(tratto.to.as_millis() - tratto.from.as_millis()),
            stato: match tratto.state {
                CoverageState::Covered => StatoCopertura::Coperto,
                CoverageState::NotCovered(_) => StatoCopertura::NonCoperto,
                CoverageState::Undetermined(_) => StatoCopertura::NonDeterminabile,
            },
        })
        .collect()
}

/// La barra e lo strato dei periodi **recuperati dopo** (PR-08, ADR-0124).
///
/// Due elenchi, e restano due: un periodo recuperato non entra fra i tratti
/// della copertura, perché nessuno guardava. Fonderli direbbe «coperto» dove
/// si è soltanto letto dopo.
#[must_use]
pub fn bars(
    copertura: &Coverage,
    recuperati: &[(Timestamp, Timestamp)],
    from: Timestamp,
    until: Timestamp,
) -> (Vec<TrattoCopertura>, Vec<TrattoRecuperato>) {
    let totale = until.as_millis() - from.as_millis();
    if totale <= 0 {
        return (Vec::new(), Vec::new());
    }
    let frazione = |millis: i64| ((millis as f64) / (totale as f64)) as f32;
    let strato: Vec<TrattoRecuperato> = recuperati
        .iter()
        .map(|(da, a)| TrattoRecuperato {
            inizio: frazione(da.as_millis() - from.as_millis()),
            ampiezza: frazione(a.as_millis() - da.as_millis()),
        })
        .collect();
    (bar(copertura, from, until), strato)
}

/// La frase della copertura con, in coda, i periodi recuperati dopo.
#[must_use]
pub fn in_words_with_recovered(
    copertura: &Coverage,
    recuperati: &[(Timestamp, Timestamp)],
) -> String {
    let mut frase = in_words(copertura);
    let recuperati = lisi_services::coverage::recovered_in_words_on_screen(recuperati);
    if !recuperati.is_empty() {
        frase.push(' ');
        frase.push_str(&recuperati);
    }
    frase
}

/// I tratti non coperti o non determinabili, a parole: le frasi del servizio,
/// le stesse dei documenti, con l'ora locale davanti all'UTC (ADR-0136).
#[must_use]
pub fn in_words(copertura: &Coverage) -> String {
    lisi_services::coverage::gaps_in_words_on_screen(copertura)
}

/// Il programma e il collegamento su tutta la finestra di un monitoraggio.
#[must_use]
pub fn overall_in_words(copertura: &Coverage) -> String {
    if copertura.intervals().is_empty() {
        return String::from("Il monitoraggio non è stato avviato: non ha una finestra.");
    }
    format!(
        "Sulla sua finestra: {}",
        lisi_services::coverage::totals_in_words(copertura)
    )
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::coverage::{
        Coverage, CoverageInterval, CoverageState, NotCoveredReason, UndeterminedReason,
    };

    use super::{bar, in_words, scope_note};
    use crate::StatoCopertura;

    const UI: &str = include_str!("../ui/app-window.slint");
    const COMPONENTS: &str = include_str!("../ui/components.slint");

    fn copertura() -> Coverage {
        let tratti = vec![
            CoverageInterval {
                from: Timestamp::from_millis(0),
                to: Timestamp::from_millis(50),
                state: CoverageState::NotCovered(NotCoveredReason::NoMonitoring),
            },
            CoverageInterval {
                from: Timestamp::from_millis(50),
                to: Timestamp::from_millis(75),
                state: CoverageState::Covered,
            },
            CoverageInterval {
                from: Timestamp::from_millis(75),
                to: Timestamp::from_millis(100),
                state: CoverageState::Undetermined(UndeterminedReason::AfterLastFact),
            },
        ];
        let Some(copertura) = Coverage::build(tratti) else {
            panic!("tratti contigui");
        };
        copertura
    }

    #[test]
    fn la_barra_e_in_proporzione_alla_finestra() {
        let tratti = bar(
            &copertura(),
            Timestamp::from_millis(0),
            Timestamp::from_millis(100),
        );
        assert_eq!(tratti.len(), 3);
        assert!((tratti[1].inizio - 0.5).abs() < 1e-6);
        assert!((tratti[1].ampiezza - 0.25).abs() < 1e-6);
        assert_eq!(tratti[0].stato, StatoCopertura::NonCoperto);
        assert_eq!(tratti[2].stato, StatoCopertura::NonDeterminabile);
    }

    /// **Un periodo recuperato dopo non diventa copertura** (PR-08, controllo
    /// negativo 1): resta uno strato a parte, e i tratti della barra non
    /// cambiano.
    #[test]
    fn un_periodo_recuperato_non_e_copertura() {
        let recuperati = [(Timestamp::from_millis(10), Timestamp::from_millis(40))];
        let (tratti, strato) = super::bars(
            &copertura(),
            &recuperati,
            Timestamp::from_millis(0),
            Timestamp::from_millis(100),
        );
        assert_eq!(
            tratti,
            bar(
                &copertura(),
                Timestamp::from_millis(0),
                Timestamp::from_millis(100)
            ),
            "la barra della copertura non cambia"
        );
        assert!(
            tratti
                .iter()
                .all(|tratto| tratto.stato != StatoCopertura::Coperto || tratto.inizio >= 0.5),
            "nessun tratto coperto dove si è soltanto recuperato"
        );
        assert_eq!(strato.len(), 1);
        assert!((strato[0].inizio - 0.1).abs() < 1e-6);
        assert!((strato[0].ampiezza - 0.3).abs() < 1e-6);
        let frase = super::in_words_with_recovered(&copertura(), &recuperati);
        assert!(frase.contains("Recuperato dopo dal"), "{frase}");
        assert!(frase.contains("non guardato allora"), "{frase}");
        // La legenda lo dice, e lo dice come strato, non come stato.
        assert!(crate::surface_text::assegna(
            COMPONENTS,
            "text",
            "recuperato dopo, non guardato allora"
        ));
    }

    /// **Ogni tratto non coperto si dice a parole, con il perché.**
    #[test]
    fn i_vuoti_si_dicono_con_il_perche() {
        let frase = in_words(&copertura());
        // I tratti di prova durano millisecondi: si dicono «per meno di un
        // secondo», non «dal X al X» (E2E01-20).
        assert!(
            frase.contains("Non coperto per meno di un secondo"),
            "{frase}"
        );
        assert!(frase.contains("nessun monitoraggio la seguiva"), "{frase}");
        assert!(
            frase.contains("Non determinabile per meno di un secondo"),
            "{frase}"
        );
        assert!(
            !frase.contains("Coperto dal"),
            "un tratto coperto non va elencato: {frase}"
        );
    }

    #[test]
    fn le_durate_si_dicono_in_parole() {
        assert_eq!(
            lisi_services::coverage::duration_in_words(90 * 60_000),
            "1 ora, 30 minuti"
        );
        assert_eq!(
            lisi_services::coverage::duration_in_words(2 * 86_400_000),
            "2 giorni"
        );
        assert_eq!(
            lisi_services::coverage::duration_in_words(10),
            "meno di un minuto"
        );
    }

    /// **In Team la copertura si dice della postazione, e la nota si vede**
    /// (PR-05, controllo negativo 3).
    #[test]
    fn in_team_la_copertura_e_della_postazione() {
        assert!(scope_note(true).contains("non quella dell'ufficio"));
        assert_eq!(scope_note(false), "");
        // La nota compare in entrambe le schermate che mostrano la copertura.
        assert_eq!(UI.matches("text: root.coverage-scope-note;").count(), 2);
    }
}

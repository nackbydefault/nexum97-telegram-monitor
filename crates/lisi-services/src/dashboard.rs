//! Le undici domande a cui la prima schermata deve rispondere subito.
//!
//! # Che cosa vuol dire «nessuna metrica decorativa»
//!
//! Che ogni riga di questa schermata deve essere qualcosa su cui **si decide**.
//! Un numero che sta bene e che nessuno userebbe per scegliere il gesto
//! successivo non è informazione: è arredamento, e l'arredamento in un cruscotto
//! costa attenzione a chi lo guarda ogni giorno.
//!
//! Le undici domande vengono dal congelamento di prodotto, e sono undici
//! perché qualcuno le ha scritte guardando che cosa un operatore chiede
//! aprendo il programma la mattina.
//!
//! # Il cruscotto riceve le risposte, non le ricompone
//!
//! È DEC-252 alla terza applicazione. La salute delle fonti la compone il
//! servizio della salute; la coda quella della coda; l'archivio e le notifiche
//! il centro diagnostico. Ricomporle qui creerebbe una seconda derivazione, e
//! due schermate direbbero cose diverse nello stesso istante — sulla schermata
//! che esiste per orientare, che è il posto peggiore in cui accada.
//!
//! # «Non disponibile» non è «zero»
//!
//! Una domanda a cui questa versione non sa rispondere lo **dichiara**.
//! Mostrare zero direbbe che non c'è nulla, quando in realtà nessuno ha ancora
//! guardato: è la regola di ADR-0053 e di ADR-0054, qui alla terza superficie.

use lisi_core::Timestamp;

use crate::diagnostics::{CheckOutcome, DiagnosticArea, DiagnosticReport};
use crate::source_health::HealthSummary;
use crate::trend::TrendReport;
use crate::work_queue::WorkQueue;

/// Quanto indietro guarda «di recente».
///
/// # Perché ventiquattro ore e non «oggi»
///
/// Perché «oggi» richiede un confine di calendario, e un confine di calendario
/// richiede un fuso orario. Gli istanti di questo prodotto sono in UTC: un
/// «oggi» calcolato in UTG su una postazione italiana finirebbe alle due del
/// mattino d'estate, e chi lavora alla una e mezza vedrebbe il conteggio
/// azzerarsi mentre sta guardando.
///
/// Ventiquattro ore non hanno bisogno di un fuso e non si azzerano mai a
/// sorpresa. La schermata dice «nelle ultime ventiquattro ore», non «oggi»,
/// perché è quello che misura.
pub const RECENT_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;

/// Che cosa una risposta chiede a chi la legge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerState {
    /// Misurata, e non chiede nulla.
    Calm,
    /// Misurata, e chiede a una persona di guardare.
    Attention,
    /// **Non disponibile in questa versione.** Non è zero, e non è un guasto.
    Unavailable,
}

impl AnswerState {
    /// Se la risposta chiede un gesto.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::Attention)
    }

    /// Se la risposta è stata misurata.
    #[must_use]
    pub const fn is_available(self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

/// Le undici domande del congelamento, nell'ordine in cui si leggono.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardQuestion {
    /// Il monitoraggio sta girando?
    Monitoring,
    /// Come stanno le fonti configurate?
    SourceHealth,
    /// Quali fonti chiedono un intervento?
    DegradedSources,
    /// Quanto è entrato di recente?
    RecentContents,
    /// Ci sono avvisi nuovi?
    NewAlerts,
    /// Ci sono grappoli da guardare?
    CyberEvents,
    /// Quanto lavoro aspetta una persona?
    ReviewQueue,
    /// Telegram è utilizzabile?
    TelegramState,
    /// L'archivio è a posto?
    ArchiveState,
    /// Windows accetta gli avvisi?
    NotificationsState,
    /// Che cosa sta emergendo?
    EmergingSignals,
}

impl DashboardQuestion {
    /// Tutte le domande, nell'ordine di lettura.
    pub const ALL: &'static [Self] = &[
        Self::Monitoring,
        Self::SourceHealth,
        Self::DegradedSources,
        Self::RecentContents,
        Self::NewAlerts,
        Self::CyberEvents,
        Self::ReviewQueue,
        Self::TelegramState,
        Self::ArchiveState,
        Self::NotificationsState,
        Self::EmergingSignals,
    ];

    /// L'etichetta con cui la domanda compare.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Monitoring => "Monitoraggio",
            Self::SourceHealth => "Salute delle fonti",
            // «da guardare», non «da attenzionare» (SIM3-11: burocratese).
            Self::DegradedSources => "Fonti da guardare",
            Self::RecentContents => "Contenuti nelle ultime 24 ore",
            Self::NewAlerts => "Avvisi da esaminare",
            Self::CyberEvents => "Grappoli di segnali cyber",
            Self::ReviewQueue => "Coda di lavoro",
            Self::TelegramState => "Account Telegram",
            Self::ArchiveState => "Archivio",
            Self::NotificationsState => "Avvisi di Windows",
            Self::EmergingSignals => "Segnali emergenti",
        }
    }
}

/// Una risposta del cruscotto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardAnswer {
    /// A che cosa risponde.
    pub question: DashboardQuestion,
    /// La risposta breve: un numero, o una parola.
    pub value: String,
    /// La frase che la qualifica, e che dice il gesto quando ce n'è uno.
    pub note: String,
    /// Che cosa chiede a chi la legge.
    pub state: AnswerState,
}

impl DashboardAnswer {
    /// Compone una risposta misurata.
    fn measured(
        question: DashboardQuestion,
        state: AnswerState,
        value: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        Self {
            question,
            value: value.into(),
            note: note.into(),
            state,
        }
    }

    /// Compone una risposta **non disponibile**, con la ragione.
    fn unavailable(question: DashboardQuestion, note: impl Into<String>) -> Self {
        Self {
            question,
            value: String::from("—"),
            note: note.into(),
            state: AnswerState::Unavailable,
        }
    }
}

/// Il cruscotto, a un istante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dashboard {
    /// Le undici risposte, nell'ordine di lettura.
    pub answers: Vec<DashboardAnswer>,
    /// Quando è stato composto.
    pub composed_at: Timestamp,
}

impl Dashboard {
    /// Quante risposte chiedono un gesto.
    #[must_use]
    pub fn needing_attention(&self) -> usize {
        self.answers
            .iter()
            .filter(|answer| answer.state.needs_attention())
            .count()
    }

    /// La frase in cima.
    ///
    /// # Perché non dice mai «tutto in ordine»
    ///
    /// Perché una risposta non disponibile non è una risposta rassicurante, e
    /// «tutto in ordine» detto di un insieme in cui qualcosa non si è potuto
    /// misurare è la stessa frase falsa che il congelamento vieta per le fonti.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let attenzione = self.needing_attention();
        let non_disponibili = self
            .answers
            .iter()
            .filter(|answer| !answer.state.is_available())
            .count();

        // «Voci qui sotto», non «risposte»: l'operatore simulato non sapeva a
        // quali domande fossero risposte, e «1 … sono» non concordava
        // (OPERATOR-UX-REMEDIATION-01, OS-08).
        if attenzione == 0 && non_disponibili == 0 {
            return String::from("Nessuna delle voci qui sotto chiede un intervento.");
        }

        let mut frase = String::new();
        match attenzione {
            0 => frase.push_str("Nessuna delle voci qui sotto chiede un intervento"),
            1 => frase.push_str("1 voce qui sotto chiede un intervento"),
            n => frase.push_str(&format!("{n} voci qui sotto chiedono un intervento")),
        }
        match non_disponibili {
            0 => {}
            1 => frase.push_str("; 1 non è disponibile in questa versione"),
            n => frase.push_str(&format!("; {n} non sono disponibili in questa versione")),
        }
        frase.push('.');
        frase
    }
}

/// Ciò che il cruscotto **riceve già composto**.
///
/// # Perché non compone nulla da sé
///
/// Perché ciascuna di queste risposte ha già un servizio che la compone, e una
/// seconda derivazione dello stesso stato diverge dalla prima. Il cruscotto
/// esiste per **mettere in fila** le risposte, non per darne di proprie
/// (DEC-252).
#[derive(Debug, Clone)]
pub struct DashboardFacts {
    /// Se un monitoraggio risulta in corso in questa esecuzione.
    pub monitoring_active: bool,
    /// Su quante fonti, quando è in corso.
    ///
    /// **Vale per il monitoraggio che la schermata mostra**, e non è una somma:
    /// due monitoraggi sulla stessa fonte produrrebbero un totale che conta
    /// quella fonte due volte (ADR-0065 §2.4).
    pub monitoring_sources: usize,
    /// **Quanti** monitoraggi risultano in corso.
    ///
    /// Quando sono più d'uno la risposta dice **quanti**, e non le fonti di uno
    /// solo: dire «Su 4 fonti» con due monitoraggi in corso significherebbe
    /// mostrare il perimetro di uno come se fosse quello di tutti.
    pub monitoring_running: usize,
    /// Quanti di quelli in corso hanno **l'acquisizione in pausa**
    /// (COLLAUDO-FIX-01, CU01-004, DEC-509).
    ///
    /// Non è lo stato «avvisi sospesi» del monitoraggio: quello tacita le
    /// notifiche e lascia acquisire; la pausa ferma l'acquisizione, e il suo
    /// periodo resta non coperto (ADR-0172).
    pub monitoring_paused: usize,
    /// La salute delle fonti, composta dal servizio della salute.
    pub sources: HealthSummary,
    /// La coda, composta dal servizio della coda.
    pub queue: WorkQueue,
    /// La diagnostica, composta dal centro diagnostico.
    pub diagnostics: DiagnosticReport,
    /// Quanti contenuti sono entrati nella finestra recente.
    pub recent_contents: u64,
    /// Quanti grappoli nelle sessioni attive di recente.
    pub cyber_events: usize,
    /// Se un account risulta autorizzato e collegato in questa esecuzione.
    pub telegram_ready: bool,
    /// Se la postazione è in Esercitazione, dove l'account non serve
    /// (ADR-0129; OPERATOR-UX-REMEDIATION-01, OS-03).
    pub exercise: bool,
    /// Il confronto fra i due periodi, composto da `crate::emerging`.
    ///
    /// `None` quando l'analisi non e' stata preparata in questa esecuzione:
    /// la riga lo dichiara invece di scrivere zero.
    pub trend: Option<TrendReport>,
}

/// Mette in fila le undici risposte.
///
/// # Che cosa questa funzione fa, e che cosa non fa
///
/// **Non legge nulla e non calcola nulla**: riceve fatti già composti e li
/// traduce in frasi. È il motivo per cui è una funzione libera e non un
/// servizio con un archivio: non ne ha bisogno, e averlo la metterebbe in
/// condizione di ricomporre ciò che le viene passato.
#[must_use]
pub fn compose(facts: &DashboardFacts, now: Timestamp) -> Dashboard {
    let answers = vec![
        monitoring_answer(facts),
        source_health_answer(facts),
        degraded_answer(facts),
        recent_answer(facts),
        alerts_answer(facts),
        cyber_answer(facts),
        queue_answer(facts),
        telegram_answer(facts),
        diagnostic_answer(
            facts,
            DashboardQuestion::ArchiveState,
            DiagnosticArea::Archive,
            "Impostazioni › «Stato dell'archivio».",
        ),
        diagnostic_answer(
            facts,
            DashboardQuestion::NotificationsState,
            DiagnosticArea::WindowsNotifications,
            "Diagnostica › «Avvisi di Windows».",
        ),
        emerging_answer(facts.trend.as_ref()),
    ];

    Dashboard {
        answers,
        composed_at: now,
    }
}

/// Il monitoraggio sta girando?
fn monitoring_answer(facts: &DashboardFacts) -> DashboardAnswer {
    // PIU' D'UNO: SI DICE QUANTI, E NON LE FONTI DI UNO SOLO (ADR-0065).
    //
    // Mostrare «Su 4 fonti» con due monitoraggi in corso farebbe passare il
    // perimetro di uno per quello di tutti; sommarli conterebbe due volte una
    // fonte guardata da entrambi.
    // IN CORSO NELL'ARCHIVIO, E NIENTE ARRIVA (BUG-UX-5). Senza l'account
    // d'ufficio collegato la postazione non acquisisce: «man mano che arrivano»
    // descriveva un arrivo che non c'era. In Esercitazione non si acquisisce
    // per costruzione, e lo dice la riga di Telegram.
    if facts.monitoring_active && !facts.telegram_ready && !facts.exercise {
        let quanti = facts.monitoring_running.max(1);
        return DashboardAnswer::measured(
            DashboardQuestion::Monitoring,
            AnswerState::Attention,
            if quanti > 1 {
                format!("{quanti} in corso, senza acquisire")
            } else {
                String::from("In corso, senza acquisire")
            },
            "Questa postazione non sta acquisendo: l'account d'ufficio non è collegato. Da \
             «Account» si collega, e da quel momento arrivano i messaggi nuovi.",
        );
    }

    // LA PAUSA NON E' «IN CORSO» (COLLAUDO-FIX-01, CU01-004, DEC-509).
    //
    // Nell'archivio un monitoraggio in pausa resta in corso, ma non acquisisce,
    // e il suo periodo resta non coperto (ADR-0172). Nel collaudo la riga
    // diceva «In corso … man mano che arrivano» a pausa decisa.
    let fermi = facts.monitoring_paused.min(facts.monitoring_running);
    if facts.monitoring_active && fermi > 0 {
        let quanti = facts.monitoring_running.max(1);
        if fermi >= quanti {
            return DashboardAnswer::measured(
                DashboardQuestion::Monitoring,
                AnswerState::Attention,
                if quanti > 1 {
                    format!("{quanti} in pausa")
                } else {
                    String::from("In pausa")
                },
                "L'acquisizione è in pausa: i contenuti di questo periodo non vengono acquisiti, \
                 e il periodo resta non coperto. Si riprende dalla schermata Monitoraggio.",
            );
        }
        return DashboardAnswer::measured(
            DashboardQuestion::Monitoring,
            AnswerState::Attention,
            format!("{quanti} in corso, di cui {fermi} in pausa"),
            "Un monitoraggio in pausa non acquisisce, e il suo periodo resta non coperto. La \
             schermata Monitoraggio li elenca.",
        );
    }

    if facts.monitoring_running > 1 {
        return DashboardAnswer::measured(
            DashboardQuestion::Monitoring,
            AnswerState::Calm,
            format!("{} in corso", facts.monitoring_running),
            "Ciascuno ha il proprio perimetro e il proprio rapporto. La schermata \
             Monitoraggio li elenca.",
        );
    }

    if facts.monitoring_active {
        // Le fonti si dicono solo quando si sanno: «Su 0 fonti» detto di un
        // monitoraggio in corso sarebbe falso (OPERATOR-UX-REMEDIATION-01,
        // OS-06). I contenuti si leggono negli Avvisi e nello Storico.
        let dove = "I contenuti compaiono negli Avvisi e nello Storico man mano che arrivano.";
        let nota = if facts.monitoring_sources > 0 {
            format!(
                "Su {}. {dove}",
                lisi_core::text::counted(facts.monitoring_sources, "fonte", "fonti")
            )
        } else {
            format!("{dove} La schermata Monitoraggio dice su quali fonti.")
        };
        return DashboardAnswer::measured(
            DashboardQuestion::Monitoring,
            AnswerState::Calm,
            "In corso",
            nota,
        );
    }

    // Fermo NON chiede attenzione: un monitoraggio si avvia quando serve, e
    // segnalare come anomalia il riposo insegnerebbe a ignorare la segnalazione.
    DashboardAnswer::measured(
        DashboardQuestion::Monitoring,
        AnswerState::Calm,
        "Fermo",
        "Nessun monitoraggio in corso. Se ne compone uno da «Nuovo monitoraggio».",
    )
}

/// Come stanno le fonti configurate?
fn source_health_answer(facts: &DashboardFacts) -> DashboardAnswer {
    let riepilogo = facts.sources;
    if riepilogo.total == 0 {
        return DashboardAnswer::measured(
            DashboardQuestion::SourceHealth,
            AnswerState::Attention,
            "Nessuna",
            "Nessuna fonte configurata: non c'è nulla da monitorare. Si aggiungono da «Fonti».",
        );
    }

    // Le mai verificate NON sono un guasto, e non chiedono attenzione: sono
    // fonti di cui non si sa ancora nulla (ADR-0053 Decisione 6).
    DashboardAnswer::measured(
        DashboardQuestion::SourceHealth,
        AnswerState::Calm,
        format!("{}/{}", riepilogo.operational, riepilogo.total),
        riepilogo.as_sentence(),
    )
}

/// Quali fonti chiedono un intervento?
///
/// # Perché è una risposta a sé, e non decorazione
///
/// Perché è la riga **azionabile** delle due: la precedente orienta — quante
/// fonti su quante — questa dice se qualcuno deve alzarsi. Il congelamento le
/// elenca entrambe, e fanno due mestieri diversi.
fn degraded_answer(facts: &DashboardFacts) -> DashboardAnswer {
    let quante = facts.sources.needing_attention();
    if quante == 0 {
        return DashboardAnswer::measured(
            DashboardQuestion::DegradedSources,
            AnswerState::Calm,
            "0",
            "Nessuna fonte risulta degradata o in errore.",
        );
    }

    DashboardAnswer::measured(
        DashboardQuestion::DegradedSources,
        AnswerState::Attention,
        quante.to_string(),
        "Fonti › «Perché questo stato?» sulla riga della fonte dice che cosa è stato \
         osservato.",
    )
}

/// Quanto è entrato di recente?
fn recent_answer(facts: &DashboardFacts) -> DashboardAnswer {
    // Un conteggio di contenuti NON chiede attenzione: è la misura di che cosa
    // il monitoraggio ha fatto, e non c'è una soglia che lo renda un problema.
    DashboardAnswer::measured(
        DashboardQuestion::RecentContents,
        AnswerState::Calm,
        facts.recent_contents.to_string(),
        "Acquisiti nelle ultime ventiquattro ore, di ogni livello — anche quelli che \
         non hanno prodotto un avviso.",
    )
}

/// Ci sono avvisi nuovi?
fn alerts_answer(facts: &DashboardFacts) -> DashboardAnswer {
    let mai_visti = facts.queue.untouched();
    if mai_visti == 0 {
        return DashboardAnswer::measured(
            DashboardQuestion::NewAlerts,
            AnswerState::Calm,
            "0",
            "Nessun avviso che qualcuno non abbia ancora guardato.",
        );
    }

    DashboardAnswer::measured(
        DashboardQuestion::NewAlerts,
        AnswerState::Attention,
        mai_visti.to_string(),
        "Avvisi che nessuno ha ancora guardato. Si trovano in cima alla «Coda di lavoro».",
    )
}

/// Ci sono grappoli da guardare?
fn cyber_answer(facts: &DashboardFacts) -> DashboardAnswer {
    if facts.cyber_events == 0 {
        return DashboardAnswer::measured(
            DashboardQuestion::CyberEvents,
            AnswerState::Calm,
            "0",
            "Nessun grappolo nelle sessioni attive di recente.",
        );
    }

    // Un grappolo NON è un incidente confermato, e la nota lo dice: il numero
    // è un invito a guardare, non un allarme (ADR-0035).
    DashboardAnswer::measured(
        DashboardQuestion::CyberEvents,
        AnswerState::Attention,
        facts.cyber_events.to_string(),
        "Contenuti che nominano gli stessi indicatori tecnici. Non è un incidente \
         confermato: è un invito a guardare, in «Segnali cyber».",
    )
}

/// Quanto lavoro aspetta una persona?
fn queue_answer(facts: &DashboardFacts) -> DashboardAnswer {
    let quanti = facts.queue.items.len();
    if quanti == 0 {
        return DashboardAnswer::measured(
            DashboardQuestion::ReviewQueue,
            AnswerState::Calm,
            "0",
            "Nessun contenuto in attesa di revisione.",
        );
    }

    DashboardAnswer::measured(
        DashboardQuestion::ReviewQueue,
        AnswerState::Attention,
        quanti.to_string(),
        facts.queue.as_sentence(),
    )
}

/// Telegram è utilizzabile?
fn telegram_answer(facts: &DashboardFacts) -> DashboardAnswer {
    if facts.telegram_ready {
        return DashboardAnswer::measured(
            DashboardQuestion::TelegramState,
            AnswerState::Calm,
            "Attivo",
            "Un account d'ufficio risulta collegato in questa esecuzione.",
        );
    }

    // In Esercitazione l'account non si collega per progetto (ADR-0129):
    // «Non collegato», in arancio, chiedeva un intervento che non serve e
    // contraddiceva la fascia dell'Esercitazione (OPERATOR-SIM-01, OS-03).
    if facts.exercise {
        return DashboardAnswer::measured(
            DashboardQuestion::TelegramState,
            AnswerState::Calm,
            "Non serve",
            "In Esercitazione non ci si collega a Telegram: i messaggi di prova sono già \
             nell'archivio.",
        );
    }

    DashboardAnswer::measured(
        DashboardQuestion::TelegramState,
        AnswerState::Attention,
        "Non collegato",
        "Senza un account collegato non si acquisisce nulla. Si configura da «Account».",
    )
}

/// Una risposta che viene dal centro diagnostico.
///
/// # Perché la traduce invece di ricalcolarla
///
/// Perché il centro diagnostico ha già deciso che cosa quell'area dica, e con
/// quale esito. Ricalcolarlo qui creerebbe due schermate che dicono cose
/// diverse della stessa area nello stesso istante.
fn diagnostic_answer(
    facts: &DashboardFacts,
    question: DashboardQuestion,
    area: DiagnosticArea,
    dove: &str,
) -> DashboardAnswer {
    let Some(voce) = facts
        .diagnostics
        .checks
        .iter()
        .find(|check| check.area == area)
    else {
        return DashboardAnswer::unavailable(
            question,
            "La diagnostica non ha risposto per quest'area in questa composizione.",
        );
    };

    match voce.outcome {
        CheckOutcome::Unmeasured => DashboardAnswer::unavailable(question, voce.detail.clone()),
        CheckOutcome::Good => DashboardAnswer::measured(
            question,
            AnswerState::Calm,
            "In ordine",
            voce.detail.clone(),
        ),
        CheckOutcome::Attention | CheckOutcome::Problem => DashboardAnswer::measured(
            question,
            AnswerState::Attention,
            voce.outcome.label(),
            format!("{} {dove}", voce.detail),
        ),
    }
}

/// Che cosa sta emergendo?
///
/// # Quando questa riga può finalmente dire «zero», e quando ancora no
///
/// Fino a TREND-01 diceva sempre «non disponibile», e aveva ragione: mostrare
/// zero avrebbe detto che non c'era nulla che emergeva, quando in realtà
/// nessuno aveva guardato.
///
/// Adesso il confronto esiste, e la differenza resta la stessa. **Zero si
/// scrive soltanto dopo aver guardato**: quando le due finestre sono state
/// confrontate davvero e nulla è cresciuto. Quando il confronto **non si è
/// potuto fare** — archivio vuoto, archivio più giovane del periodo di
/// confronto, linea di partenza vuota, troppe osservazioni — la riga torna a
/// dire «non disponibile» e riporta la ragione, che il confronto stesso ha
/// composto.
///
/// La riga **riceve** la frase e non la ricompone (DEC-252, sesta superficie).
fn emerging_answer(trend: Option<&TrendReport>) -> DashboardAnswer {
    let Some(trend) = trend else {
        return DashboardAnswer::unavailable(
            DashboardQuestion::EmergingSignals,
            "L'analisi temporale non è stata preparata in questa esecuzione. Non significa \
             che non ci sia nulla che emerge: significa che nessuno lo ha ancora cercato.",
        );
    };

    match trend.emerging_count() {
        None => {
            DashboardAnswer::unavailable(DashboardQuestion::EmergingSignals, trend.as_sentence())
        }
        Some(0) => DashboardAnswer::measured(
            DashboardQuestion::EmergingSignals,
            AnswerState::Calm,
            "0",
            trend.as_sentence(),
        ),
        Some(quante) => DashboardAnswer::measured(
            DashboardQuestion::EmergingSignals,
            // **Non è un allarme.** Qualcosa che compare più di prima è un
            // invito a guardare, non un fatto grave: chiedere attenzione qui
            // insegnerebbe a ignorare le richieste di attenzione vere.
            AnswerState::Calm,
            quante.to_string(),
            trend.as_sentence(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::{
        AnswerState, Dashboard, DashboardFacts, DashboardQuestion, RECENT_WINDOW_MS, TrendReport,
        compose,
    };
    use crate::diagnostics::DiagnosticReport;
    use crate::source_health::HealthSummary;
    use crate::work_queue::WorkQueue;

    /// Questo modulo, per le guardie testuali.
    const THIS_MODULE: &str = include_str!("dashboard.rs");

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Una postazione appena installata: niente configurato, niente osservato.
    fn facts() -> DashboardFacts {
        DashboardFacts {
            monitoring_active: false,
            monitoring_sources: 0,
            monitoring_running: 0,
            monitoring_paused: 0,
            sources: HealthSummary::default(),
            queue: WorkQueue {
                items: Vec::new(),
                composed_at: now(),
            },
            diagnostics: DiagnosticReport {
                taken_at: now(),
                checks: Vec::new(),
            },
            recent_contents: 0,
            cyber_events: 0,
            telegram_ready: false,
            exercise: false,
            trend: None,
        }
    }

    /// Le due finestre standard, per le prove sui segnali emergenti.
    fn finestre() -> crate::trend::ComparisonWindows {
        let Some(finestre) =
            crate::trend::ComparisonWindows::ending_at(now(), crate::trend::DEFAULT_WINDOW_MS)
        else {
            panic!("le finestre di prova devono potersi costruire");
        };
        finestre
    }

    /// Un confronto eseguito che non ha trovato nulla.
    fn confronto_senza_emergenze() -> TrendReport {
        TrendReport {
            windows: finestre(),
            outcome: crate::trend::TrendOutcome::Compared {
                findings: Vec::new(),
                recent_total: 40,
                baseline_total: 38,
                distinct_keys: 12,
            },
        }
    }

    /// Un confronto che non si è potuto fare.
    fn confronto_impossibile() -> TrendReport {
        TrendReport {
            windows: finestre(),
            outcome: crate::trend::TrendOutcome::NotComparable(
                crate::trend::TrendGap::EmptyBaseline,
            ),
        }
    }

    fn risposta(cruscotto: &Dashboard, question: DashboardQuestion) -> &super::DashboardAnswer {
        let Some(risposta) = cruscotto
            .answers
            .iter()
            .find(|answer| answer.question == question)
        else {
            panic!("la domanda «{}» deve avere una risposta", question.label());
        };
        risposta
    }

    /// Tutte e undici le domande del congelamento hanno una risposta.
    ///
    /// Una domanda che scomparisse non lascerebbe alcun buco visibile: la
    /// schermata avrebbe una riga in meno, e nessuno se ne accorgerebbe.
    #[test]
    fn tutte_le_undici_domande_hanno_una_risposta() {
        let cruscotto = compose(&facts(), now());

        assert_eq!(cruscotto.answers.len(), DashboardQuestion::ALL.len());
        assert_eq!(DashboardQuestion::ALL.len(), 11);
        for domanda in DashboardQuestion::ALL {
            let quante = cruscotto
                .answers
                .iter()
                .filter(|answer| answer.question == *domanda)
                .count();
            assert_eq!(
                quante,
                1,
                "la domanda «{}» deve comparire una volta sola",
                domanda.label()
            );
        }
    }

    /// **Senza confronto i segnali emergenti non si dichiarano a zero.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Mostrare «0 segnali emergenti» direbbe che non c'è nulla che emerge,
    /// quando in realtà nessuno ha guardato. È la differenza fra «non risulta»
    /// e «non è stato cercato», e non è cambiata con TREND-01: è cambiato
    /// soltanto che adesso, **dopo aver guardato**, zero si può scrivere.
    #[test]
    fn senza_confronto_i_segnali_emergenti_dicono_di_non_essere_disponibili() {
        let cruscotto = compose(&facts(), now());
        let risposta = risposta(&cruscotto, DashboardQuestion::EmergingSignals);

        assert_eq!(risposta.state, AnswerState::Unavailable);
        assert_ne!(risposta.value, "0", "«non cercato» non si scrive «zero»");
        assert!(
            risposta.note.contains("nessuno lo ha ancora cercato"),
            "la ragione va detta: «{}»",
            risposta.note
        );
    }

    /// **Un confronto impossibile torna a «non disponibile», con la ragione.**
    ///
    /// Una linea di partenza vuota non è «non sta emergendo nulla»: è
    /// «qualunque cosa sembrerebbe un aumento».
    #[test]
    fn un_confronto_impossibile_non_diventa_zero() {
        let mut fatti = facts();
        fatti.trend = Some(confronto_impossibile());

        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::EmergingSignals);

        assert_eq!(risposta.state, AnswerState::Unavailable);
        assert_ne!(risposta.value, "0");
        assert!(
            risposta.note.contains("linea di partenza vuota"),
            "la ragione del confronto va riportata: «{}»",
            risposta.note
        );
    }

    /// **Dopo aver guardato, zero si può scrivere** — con le finestre accanto.
    #[test]
    fn dopo_aver_guardato_zero_si_puo_scrivere() {
        let mut fatti = facts();
        fatti.trend = Some(confronto_senza_emergenze());

        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::EmergingSignals);

        assert_eq!(risposta.value, "0");
        assert_eq!(risposta.state, AnswerState::Calm);
        assert!(
            risposta.note.contains("Periodo recente:"),
            "il numero va letto accanto alle finestre su cui è stato calcolato: «{}»",
            risposta.note
        );
    }

    /// **Ciò che emerge non chiede attenzione.**
    ///
    /// Qualcosa che compare più di prima è un invito a guardare, non un fatto
    /// grave: chiedere attenzione qui insegnerebbe a ignorare le richieste di
    /// attenzione vere, che in questa schermata riguardano guasti.
    #[test]
    fn cio_che_emerge_non_e_un_allarme() {
        let mut fatti = facts();
        fatti.trend = Some(TrendReport {
            windows: finestre(),
            outcome: crate::trend::TrendOutcome::Compared {
                findings: vec![crate::trend::EmergingObservation {
                    kind: crate::trend::ObservationKind::Term,
                    key: String::from("assalto"),
                    recent: 14,
                    baseline: 2,
                }],
                recent_total: 40,
                baseline_total: 38,
                distinct_keys: 12,
            },
        });

        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::EmergingSignals);

        assert_eq!(risposta.value, "1");
        assert!(
            !risposta.state.needs_attention(),
            "un termine che compare piu' di prima non e' un guasto"
        );
    }

    /// Un monitoraggio fermo non chiede attenzione.
    ///
    /// Un monitoraggio si avvia quando serve. Segnalare come anomalia il riposo
    /// insegnerebbe a ignorare la segnalazione.
    #[test]
    fn un_monitoraggio_fermo_non_e_un_allarme() {
        let cruscotto = compose(&facts(), now());
        let risposta = risposta(&cruscotto, DashboardQuestion::Monitoring);

        assert_eq!(risposta.state, AnswerState::Calm);
        assert_eq!(risposta.value, "Fermo");
    }

    /// **Con più monitoraggi il cruscotto dice quanti, e non le fonti di uno.**
    ///
    /// Mostrare «Su 4 fonti» con due monitoraggi in corso farebbe passare il
    /// perimetro di uno per quello di tutti; sommarli conterebbe due volte una
    /// fonte guardata da entrambi (ADR-0065 §2.4).
    #[test]
    fn con_piu_monitoraggi_si_dice_quanti_e_non_le_fonti_di_uno() {
        let mut fatti = facts();
        fatti.monitoring_active = true;
        fatti.monitoring_sources = 4;
        fatti.monitoring_running = 2;
        fatti.telegram_ready = true;

        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::Monitoring);

        assert_eq!(risposta.value, "2 in corso");
        assert!(
            !risposta.note.contains('4'),
            "le fonti di un monitoraggio non valgono per tutti: «{}»",
            risposta.note
        );
        assert!(risposta.note.contains("proprio perimetro"));
    }

    /// Un monitoraggio solo continua a dire su quante fonti.
    #[test]
    fn un_monitoraggio_solo_dice_ancora_su_quante_fonti() {
        let mut fatti = facts();
        fatti.monitoring_active = true;
        fatti.monitoring_sources = 4;
        fatti.monitoring_running = 1;
        fatti.telegram_ready = true;

        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::Monitoring);

        assert_eq!(risposta.value, "In corso");
        assert!(risposta.note.contains("Su 4 fonti"));
    }

    /// **In Esercitazione l'account non chiede un intervento**
    /// (OPERATOR-UX-REMEDIATION-01, OS-03): non ci si collega per progetto.
    #[test]
    fn in_esercitazione_l_account_non_chiede_un_intervento() {
        let mut fatti = facts();
        fatti.exercise = true;
        let cruscotto = compose(&fatti, now());
        let prova = risposta(&cruscotto, DashboardQuestion::TelegramState);
        assert_eq!(prova.state, AnswerState::Calm);
        assert!(!prova.note.contains("non si acquisisce"), "{}", prova.note);

        // Fuori dall'Esercitazione la riga resta quella di prima.
        let cruscotto = compose(&facts(), now());
        let reale = risposta(&cruscotto, DashboardQuestion::TelegramState);
        assert_eq!(reale.state, AnswerState::Attention);
    }

    /// **Un monitoraggio in corso di cui non si sanno le fonti non è «su 0
    /// fonti»** (OPERATOR-UX-REMEDIATION-01, OS-06), e la risposta dice dove
    /// arrivano i contenuti.
    #[test]
    fn in_corso_senza_fonti_note_non_dice_zero() {
        let mut fatti = facts();
        fatti.monitoring_active = true;
        fatti.monitoring_sources = 0;
        fatti.monitoring_running = 1;
        fatti.telegram_ready = true;
        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::Monitoring);
        assert_eq!(risposta.value, "In corso");
        assert!(!risposta.note.contains("Su 0"), "{}", risposta.note);
        assert!(risposta.note.contains("Avvisi"), "{}", risposta.note);
    }

    /// **In corso nell'archivio, senza account collegato, non arriva niente**
    /// (BUG-UX-5). La riga diceva «In corso … man mano che arrivano» mentre la
    /// postazione non acquisiva.
    #[test]
    fn in_corso_senza_account_non_promette_arrivi() {
        for quanti in [1, 2] {
            let mut fatti = facts();
            fatti.monitoring_active = true;
            fatti.monitoring_sources = 4;
            fatti.monitoring_running = quanti;
            let cruscotto = compose(&fatti, now());
            let risposta = risposta(&cruscotto, DashboardQuestion::Monitoring);
            assert!(
                risposta.value.contains("senza acquisire"),
                "{}",
                risposta.value
            );
            assert_eq!(risposta.state, AnswerState::Attention);
            assert!(!risposta.note.contains("man mano"), "{}", risposta.note);
            assert!(risposta.note.contains("Account"), "{}", risposta.note);
        }

        // In Esercitazione non si acquisisce per costruzione: la riga non chiede
        // l'account che la riga di Telegram dice non servire.
        let mut fatti = facts();
        fatti.monitoring_active = true;
        fatti.monitoring_running = 1;
        fatti.exercise = true;
        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::Monitoring);
        assert_eq!(risposta.value, "In corso");
    }

    /// **Con l'acquisizione in pausa la riga non dice «In corso»**
    /// (COLLAUDO-FIX-01, CU01-004, DEC-509).
    ///
    /// Nel collaudo, a pausa decisa, il Cruscotto diceva «In corso — I
    /// contenuti compaiono negli Avvisi e nello Storico man mano che
    /// arrivano»: chi guardava il quadro credeva che si acquisisse.
    #[test]
    fn in_pausa_la_riga_non_dice_in_corso() {
        let mut fatti = facts();
        fatti.monitoring_active = true;
        fatti.monitoring_sources = 1;
        fatti.monitoring_running = 1;
        fatti.monitoring_paused = 1;
        fatti.telegram_ready = true;
        let cruscotto = compose(&fatti, now());
        let riga = risposta(&cruscotto, DashboardQuestion::Monitoring);
        assert_eq!(riga.value, "In pausa", "{}", riga.note);
        assert_eq!(riga.state, AnswerState::Attention);
        assert!(!riga.note.contains("man mano"), "{}", riga.note);
        assert!(riga.note.contains("non coperto"), "{}", riga.note);
        assert!(riga.note.contains("Monitoraggio"), "{}", riga.note);

        // Due in corso, uno in pausa: si dice quanti, e che uno non acquisisce.
        fatti.monitoring_running = 2;
        let cruscotto = compose(&fatti, now());
        let riga = risposta(&cruscotto, DashboardQuestion::Monitoring);
        assert_eq!(riga.value, "2 in corso, di cui 1 in pausa");
        assert_eq!(riga.state, AnswerState::Attention);
        assert!(riga.note.contains("non coperto"), "{}", riga.note);
    }

    /// **Il riepilogo concorda al singolare** (OS-08: «1 … sono»).
    #[test]
    fn il_riepilogo_concorda_al_singolare() {
        let cruscotto = compose(&facts(), now());
        let frase = cruscotto.as_sentence();
        assert!(!frase.contains("1 non sono"), "{frase}");
        assert!(!frase.contains("1 voci"), "{frase}");
        assert!(!frase.contains("risposte chiedono"), "{frase}");
    }

    /// Il riepilogo non dice «tutto in ordine» quando qualcosa manca.
    #[test]
    fn il_riepilogo_non_nasconde_cio_che_non_e_disponibile() {
        let cruscotto = compose(&facts(), now());
        let frase = cruscotto.as_sentence();

        assert!(
            frase.contains("non sono disponibili") || frase.contains("non è disponibile"),
            "il riepilogo deve nominare le risposte non disponibili: «{frase}»"
        );
        for vietato in ["tutto in ordine", "tutto a posto", "100%"] {
            assert!(
                !frase.to_lowercase().contains(vietato),
                "il riepilogo contiene «{vietato}»: «{frase}»"
            );
        }
    }

    /// Le fonti mai verificate non chiedono attenzione.
    ///
    /// Al primo avvio sono tutte «Sconosciute», e un cruscotto che lo segnalasse
    /// come un problema insegnerebbe a ignorare i problemi.
    #[test]
    fn le_fonti_mai_verificate_non_chiedono_attenzione() {
        let mut fatti = facts();
        fatti.sources = HealthSummary {
            total: 5,
            operational: 0,
            degraded: 0,
            failed: 0,
            unknown: 5,
            stopped: 0,
        };

        let cruscotto = compose(&fatti, now());
        assert_eq!(
            risposta(&cruscotto, DashboardQuestion::SourceHealth).state,
            AnswerState::Calm
        );
        assert_eq!(
            risposta(&cruscotto, DashboardQuestion::DegradedSources).state,
            AnswerState::Calm
        );
    }

    /// Una fonte degradata chiede attenzione e dice dove si guarda.
    #[test]
    fn una_fonte_degradata_chiede_attenzione_e_dice_dove() {
        let mut fatti = facts();
        fatti.sources = HealthSummary {
            total: 3,
            operational: 2,
            degraded: 1,
            failed: 0,
            unknown: 0,
            stopped: 0,
        };

        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::DegradedSources);

        assert_eq!(risposta.state, AnswerState::Attention);
        assert_eq!(risposta.value, "1");
        assert!(
            risposta.note.contains("Fonti ›"),
            "deve dire dove si guarda"
        );
    }

    /// Un grappolo non è un incidente confermato, e la nota lo dice.
    #[test]
    fn un_grappolo_non_e_un_incidente_confermato() {
        let mut fatti = facts();
        fatti.cyber_events = 2;

        let cruscotto = compose(&fatti, now());
        let risposta = risposta(&cruscotto, DashboardQuestion::CyberEvents);

        assert!(
            risposta.note.contains("Non è un incidente"),
            "il numero è un invito a guardare, non un allarme: «{}»",
            risposta.note
        );
    }

    /// **Nessuna percentuale, nessuna copertura, nessun punteggio.**
    ///
    /// Un cruscotto è il posto in cui una metrica riassuntiva sembra più
    /// innocua e fa più danno: viene letta come un giudizio sulla postazione.
    #[test]
    fn il_cruscotto_non_riassume_nulla_in_un_numero_solo() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        for parola in [
            "score",
            "punteggio",
            "percentuale",
            "copertura",
            "health_index",
        ] {
            assert!(
                !codice.contains(parola),
                "il cruscotto nomina «{parola}»: undici risposte non si riassumono in \
                 un numero, e un numero solo verrebbe letto come un giudizio"
            );
        }
    }

    /// La finestra recente è di ventiquattro ore, e non di un giorno di
    /// calendario.
    ///
    /// Un «oggi» in UTC su una postazione italiana finirebbe alle due del
    /// mattino d'estate, e chi lavora alla una e mezza vedrebbe il conteggio
    /// azzerarsi mentre sta guardando.
    #[test]
    fn la_finestra_recente_non_dipende_da_un_fuso_orario() {
        assert_eq!(RECENT_WINDOW_MS, 86_400_000);

        let cruscotto = compose(&facts(), now());
        let risposta = risposta(&cruscotto, DashboardQuestion::RecentContents);
        assert!(
            risposta.note.contains("ventiquattro ore"),
            "la schermata dice che cosa misura: «{}»",
            risposta.note
        );
        assert!(
            !risposta.note.contains("oggi"),
            "«oggi» richiederebbe un fuso orario che questo prodotto non ha"
        );
    }
}

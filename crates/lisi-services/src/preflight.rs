//! «Pronto per lavorare» (PR-04, ADR-0120).
//!
//! # Una domanda, una riga
//!
//! All'avvio un operatore chiede una cosa sola: **posso cominciare a lavorare?**
//! La risposta è **«Pronto per lavorare.»** oppure **«Non ancora: …»**, con la
//! prima cosa che manca, che cosa fare e dove.
//!
//! # Il controllo riceve le risposte, non le ricompone
//!
//! È DEC-252 alla quarta superficie. Sei dei nove controlli **sono** voci del
//! centro diagnostico, prese come il centro le compone: qui se ne decidono
//! soltanto l'ordine e la forma. Una voce «Da guardare» o «Guasto» è una cosa
//! che manca; una voce «Non misurato» non ferma e non si tace.
//!
//! I tre controlli che il centro non aveva — il monitoraggio interrotto, l'Hub,
//! l'ora — arrivano in [`PreflightFacts`], raccolti da chi li può osservare.
//!
//! # Come Windows tiene l'ora: si dice, non ferma
//!
//! Da CLOCK-01 (ADR-0168) la riga dice anche se Windows sincronizza l'ora,
//! come chi chiama l'ha letto dal registro. Non è un decimo controllo: un
//! orologio non sincronizzato non è un orologio tornato indietro, e decidere
//! come la postazione tiene l'ora è di chi la amministra.
//!
//! # Il controllo propone, non ripara
//!
//! [`assess`] è una funzione pura: non legge l'archivio, non scrive, non avvia
//! nulla. L'unica scrittura del controllo è la sua riga d'audit
//! ([`PreflightService::record`]), che porta l'esito e il titolo del controllo,
//! mai una frase.

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::role::{OperatingMode, RestrictedAction};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_platform::time_sync::TimeSyncState;
use lisi_storage::Database;

use crate::diagnostics::{CheckOutcome, DiagnosticArea, DiagnosticCheck, DiagnosticReport};
use crate::error::ServiceResult;
use crate::source_health::HealthSummary;

/// L'azione d'audit di un controllo di avvio.
pub const PREFLIGHT_AUDIT_ACTION: &str = "controllo_di_avvio";

/// Il giorno in cui questo codice è stato scritto: 25 settembre 2026, 00:00 UTC.
///
/// # Perché è un fatto e non una soglia
///
/// Perché un programma non gira prima di essere stato scritto. Un orologio che
/// dice una data precedente è tornato indietro, e ogni istante che
/// registrerebbe sarebbe falso.
pub const CODE_WRITTEN_AT: Timestamp = Timestamp::from_millis(1_790_294_400_000);

/// I nove controlli, nell'ordine in cui si fanno.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreflightCheck {
    /// L'archivio si apre, risponde e si lascia scrivere.
    Archive,
    /// Un account autorizzato, e la libreria di Telegram in questa copia.
    TelegramAccount,
    /// Almeno una fonte configurata e non in errore.
    Sources,
    /// Nessun monitoraggio interrotto senza che nessuno lo fermasse.
    Monitoring,
    /// Windows accetta gli avvisi.
    WindowsNotifications,
    /// C'è spazio per l'archivio, le copie e la manutenzione.
    DiskSpace,
    /// Almeno una copia di sicurezza è stata prodotta.
    Backup,
    /// In Team: l'Hub risponde, ed è quello atteso.
    Hub,
    /// L'ora di sistema non è tornata indietro.
    SystemClock,
}

impl PreflightCheck {
    /// I nove controlli, nell'ordine.
    pub const ALL: [Self; 9] = [
        Self::Archive,
        Self::TelegramAccount,
        Self::Sources,
        Self::Monitoring,
        Self::WindowsNotifications,
        Self::DiskSpace,
        Self::Backup,
        Self::Hub,
        Self::SystemClock,
    ];

    /// Il titolo, come compare nella riga e nell'audit.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Archive => "archivio",
            Self::TelegramAccount => "account Telegram",
            Self::Sources => "fonti",
            Self::Monitoring => "monitoraggio",
            Self::WindowsNotifications => "avvisi di Windows",
            Self::DiskSpace => "spazio su disco",
            Self::Backup => "copia di sicurezza",
            Self::Hub => "Hub dell'ufficio",
            Self::SystemClock => "ora di sistema",
        }
    }
}

/// Dove si compie il gesto che manca.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreflightPlace {
    /// La schermata Account.
    Accounts,
    /// La schermata Fonti.
    Sources,
    /// La schermata Monitoraggio.
    Monitoring,
    /// La schermata Impostazioni.
    Settings,
    /// La schermata Live condiviso, dove si configura l'Hub.
    TeamLive,
    /// Fuori dal prodotto: Windows, il volume, l'orologio di sistema.
    OutsideTheProduct,
}

/// Che cosa fare, e dove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightFix {
    /// La frase che lo dice. **Mai un percorso di file.**
    pub what_to_do: String,
    /// Dove si compie.
    pub place: PreflightPlace,
    /// L'azione riservata all'amministratore che la correzione richiede, se ne
    /// richiede una (ADR-0015).
    pub requires: Option<RestrictedAction>,
}

/// L'esito del controllo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// Si può cominciare. Porta i controlli che non si sono potuti misurare.
    Ready {
        /// Controlli non misurati: non fermano, e non si tacciono.
        not_verified: Vec<PreflightCheck>,
    },
    /// Manca qualcosa: **la prima** cosa.
    NotYet {
        /// Quale controllo.
        check: PreflightCheck,
        /// Che cosa manca.
        what_is_missing: String,
        /// Che cosa fare, e dove.
        fix: PreflightFix,
    },
}

/// Ciò che il centro diagnostico non osserva, e il controllo sì.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightFacts {
    /// La modalità in vigore.
    pub mode: OperatingMode,
    /// Le fonti, **già composte** da chi le compone (DEC-252).
    pub sources: HealthSummary,
    /// Le interruzioni rilevate all'avvio e non ancora prese in carico.
    pub open_interruptions: usize,
    /// L'Hub, in Team.
    pub hub: HubReachability,
    /// L'ultimo istante registrato nell'archivio, se ce n'è uno.
    pub latest_recorded: Option<Timestamp>,
    /// Se il processo è in Esercitazione (ADR-0129).
    ///
    /// # Perché quattro controlli non si fanno
    ///
    /// In Esercitazione il programma non si collega a Telegram, le fonti sono
    /// inventate, l'Hub non si collega e l'archivio si butta: account, fonti,
    /// Hub e copia di sicurezza non dicono nulla su che cosa si può provare.
    /// Chiederli faceva dire alla fascia «non si può acquisire nulla» mentre la
    /// fascia sopra prometteva una prova completa (OPERATOR-SIM-01, OS-03).
    /// Archivio, monitoraggio interrotto, avvisi di Windows, spazio e ora
    /// restano: valgono anche per la prova.
    pub exercise: bool,
    /// Come Windows tiene l'ora, letto da chi chiama (CLOCK-01, ADR-0168).
    pub time_sync: TimeSyncState,
}

/// Che cosa ha risposto l'Hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubReachability {
    /// Nessun Hub configurato: la postazione non è in Team.
    NotConfigured,
    /// Il canale cifrato si è aperto, e l'Hub è quello atteso.
    Reachable,
    /// Non risponde.
    Unreachable,
    /// Risponde, ma con una chiave diversa da quella attesa.
    NotTheExpectedHub,
    /// La postazione non ha ciò che serve per collegarsi.
    NotUsable,
}

/// La fotografia di un controllo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    /// L'esito.
    pub outcome: PreflightOutcome,
    /// La modalità in cui è stato fatto: decide se una correzione riservata si
    /// può compiere da qui.
    pub mode: OperatingMode,
    /// Se il controllo è stato fatto in Esercitazione: la riga lo dice.
    pub exercise: bool,
    /// Come Windows tiene l'ora: la riga lo dice, e non ferma (ADR-0168).
    pub time_sync: TimeSyncState,
}

impl Preflight {
    /// Se si può cominciare.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.outcome, PreflightOutcome::Ready { .. })
    }

    /// La riga.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.outcome {
            PreflightOutcome::Ready { not_verified } => {
                // UNA RIGA CHE NON LASCIA UN DUBBIO (UX-EXCELLENCE-02, SIM3-22).
                //
                // Diceva anche «La verifica completa dell'archivio non fa parte
                // di questo controllo: si fa da Impostazioni», e chi la leggeva
                // al primo avvio si chiedeva se ci fosse qualcosa da fare. La
                // dichiarazione di ADR-0120 §5 resta — il controllo è rapido, e
                // la verifica completa non è stata fatta — ma dice anche che è
                // facoltativa: si può lavorare.
                let mut riga = if self.exercise {
                    String::from("Pronto per l'esercitazione: non servono Telegram né un account.")
                } else {
                    String::from("Pronto per lavorare.")
                };
                if !not_verified.is_empty() {
                    let titoli: Vec<&str> = not_verified.iter().map(|c| c.title()).collect();
                    riga.push_str(&format!(" Non verificati: {}.", titoli.join(", ")));
                }
                riga.push(' ');
                riga.push_str(ora_di_windows(self.time_sync));
                riga.push_str(
                    " Controllo rapido: la verifica completa dell'archivio è facoltativa, da \
                     Impostazioni.",
                );
                riga
            }
            PreflightOutcome::NotYet {
                check,
                what_is_missing,
                ..
            } => {
                let riga = format!("Non ancora: {}. {what_is_missing}", check.title());
                // L'orologio da correggere: come Windows tiene l'ora è la prima
                // cosa che serve a chi lo corregge (ADR-0168). Le altre righe
                // restano sulla cosa che manca.
                if *check == PreflightCheck::SystemClock {
                    format!("{riga} {}", ora_di_windows(self.time_sync))
                } else {
                    riga
                }
            }
        }
    }

    /// Che cosa fare, quando manca qualcosa.
    ///
    /// Dove la correzione è riservata all'amministratore e la postazione è in
    /// modalità operatore, **lo dice**: il pulsante porta comunque soltanto
    /// alla schermata, con i controlli che la schermata ha già.
    #[must_use]
    pub fn what_to_do(&self) -> Option<String> {
        let PreflightOutcome::NotYet { fix, .. } = &self.outcome else {
            return None;
        };
        let mut frase = fix.what_to_do.clone();
        // La frase si aggiunge solo se la modalità **rifiuta** davvero l'azione:
        // prima bastava che la postazione fosse in modalità operatore, e dal
        // 2026-10-15 l'operatore configura account e fonti (ADR-0140). Dirgli di
        // chiedere a chi amministra lo avrebbe mandato da qualcuno per un gesto
        // che può fare da sé.
        if fix.requires.is_some_and(|azione| !self.mode.allows(azione)) {
            frase.push_str(
                " Serve la modalità amministratore: chiederlo a chi amministra la postazione.",
            );
        }
        Some(frase)
    }

    /// Il dettaglio d'audit: l'esito e **il titolo** del controllo, mai la
    /// frase.
    #[must_use]
    pub fn audit_detail(&self) -> String {
        match &self.outcome {
            PreflightOutcome::Ready { not_verified } if not_verified.is_empty() => {
                String::from("pronto")
            }
            PreflightOutcome::Ready { not_verified } => format!(
                "pronto; non verificati: {}",
                not_verified
                    .iter()
                    .map(|c| c.title())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            PreflightOutcome::NotYet { check, .. } => format!("non ancora: {}", check.title()),
        }
    }
}

/// La voce del centro diagnostico per un'area.
fn voce(report: &DiagnosticReport, area: DiagnosticArea) -> Option<&DiagnosticCheck> {
    report.checks.iter().find(|check| check.area == area)
}

/// Che cosa dice una voce del centro: manca qualcosa, non si è misurata, o va.
enum Lettura {
    Manca(String),
    NonMisurata,
    Va,
}

/// Legge una voce del centro **senza ricomporla**.
///
/// Una voce assente dal rapporto è una voce **non misurata**: il centro compone
/// sempre tutte le aree, e se ne mancasse una non sarebbe un «va bene».
fn leggi(report: &DiagnosticReport, area: DiagnosticArea) -> Lettura {
    match voce(report, area) {
        None => Lettura::NonMisurata,
        Some(check) => match check.outcome {
            CheckOutcome::Attention | CheckOutcome::Problem => Lettura::Manca(check.detail.clone()),
            CheckOutcome::Unmeasured => Lettura::NonMisurata,
            CheckOutcome::Good => Lettura::Va,
        },
    }
}

/// Il gesto che il centro indica per un'area, o la frase data qui.
fn gesto(report: &DiagnosticReport, area: DiagnosticArea, altrimenti: &str) -> String {
    voce(report, area)
        .and_then(|check| check.action.clone())
        .unwrap_or_else(|| String::from(altrimenti))
}

/// Una voce del centro diventa un controllo: manca, non misurata, o va.
fn da_voce(
    report: &DiagnosticReport,
    area: DiagnosticArea,
    check: PreflightCheck,
    fix: PreflightFix,
    non_verificati: &mut Vec<PreflightCheck>,
) -> Option<(String, PreflightFix)> {
    match leggi(report, area) {
        Lettura::Manca(frase) => Some((frase, fix)),
        Lettura::NonMisurata => {
            non_verificati.push(check);
            None
        }
        Lettura::Va => None,
    }
}

/// Il controllo: nove domande, in ordine, fermandosi alla prima che manca.
///
/// # Funzione pura
///
/// Non legge l'archivio, non scrive, non avvia nulla, e non legge l'orologio:
/// l'istante arriva da chi chiama. Stesso rapporto, stessi fatti, stesso
/// istante: stesso esito.
#[must_use]
pub fn assess(report: &DiagnosticReport, facts: &PreflightFacts, now: Timestamp) -> Preflight {
    let mut non_verificati = Vec::new();

    for check in PreflightCheck::ALL {
        if facts.exercise
            && matches!(
                check,
                PreflightCheck::TelegramAccount
                    | PreflightCheck::Sources
                    | PreflightCheck::Hub
                    | PreflightCheck::Backup
            )
        {
            continue;
        }
        let esito = match check {
            PreflightCheck::Archive => da_voce(
                report,
                DiagnosticArea::Archive,
                check,
                PreflightFix {
                    what_to_do: gesto(
                        report,
                        DiagnosticArea::Archive,
                        "Impostazioni › «Stato dell'archivio».",
                    ),
                    place: PreflightPlace::Settings,
                    requires: None,
                },
                &mut non_verificati,
            ),
            PreflightCheck::TelegramAccount => account(report, &mut non_verificati),
            PreflightCheck::Sources => fonti(facts.sources),
            PreflightCheck::Monitoring => monitoraggio(facts.open_interruptions),
            PreflightCheck::WindowsNotifications => da_voce(
                report,
                DiagnosticArea::WindowsNotifications,
                check,
                PreflightFix {
                    what_to_do: String::from(
                        "Impostazioni di Windows › Sistema › Notifiche: consentire le notifiche \
                         di NEXUM/97. Poi «Ricontrolla».",
                    ),
                    place: PreflightPlace::OutsideTheProduct,
                    requires: None,
                },
                &mut non_verificati,
            ),
            PreflightCheck::DiskSpace => da_voce(
                report,
                DiagnosticArea::DiskSpace,
                check,
                PreflightFix {
                    what_to_do: format!(
                        "{} Poi «Ricontrolla».",
                        gesto(
                            report,
                            DiagnosticArea::DiskSpace,
                            "Liberare spazio sul volume."
                        )
                    ),
                    place: PreflightPlace::OutsideTheProduct,
                    requires: None,
                },
                &mut non_verificati,
            ),
            PreflightCheck::Backup => da_voce(
                report,
                DiagnosticArea::LastBackup,
                check,
                PreflightFix {
                    what_to_do: gesto(
                        report,
                        DiagnosticArea::LastBackup,
                        "Impostazioni › «Copia di sicurezza».",
                    ),
                    place: PreflightPlace::Settings,
                    requires: None,
                },
                &mut non_verificati,
            ),
            PreflightCheck::Hub => hub(facts.hub),
            PreflightCheck::SystemClock => orologio(now, facts.latest_recorded),
        };

        if let Some((what_is_missing, fix)) = esito {
            return Preflight {
                outcome: PreflightOutcome::NotYet {
                    check,
                    what_is_missing,
                    fix,
                },
                mode: facts.mode,
                exercise: facts.exercise,
                time_sync: facts.time_sync,
            };
        }
    }

    Preflight {
        outcome: PreflightOutcome::Ready {
            not_verified: non_verificati,
        },
        mode: facts.mode,
        exercise: facts.exercise,
        time_sync: facts.time_sync,
    }
}

/// Il controllo 2: la libreria di Telegram in questa copia, poi l'account.
fn account(
    report: &DiagnosticReport,
    non_verificati: &mut Vec<PreflightCheck>,
) -> Option<(String, PreflightFix)> {
    if let Lettura::Manca(frase) = leggi(report, DiagnosticArea::Tdlib) {
        return Some((
            frase,
            PreflightFix {
                what_to_do: String::from(
                    "Installare la copia di NEXUM/97 costruita con la libreria di Telegram: la \
                     fornisce chi distribuisce il programma nell'ufficio.",
                ),
                place: PreflightPlace::OutsideTheProduct,
                requires: None,
            },
        ));
    }
    da_voce(
        report,
        DiagnosticArea::TelegramRuntime,
        PreflightCheck::TelegramAccount,
        PreflightFix {
            what_to_do: gesto(
                report,
                DiagnosticArea::TelegramRuntime,
                "Account › scegliere l'account e completare l'accesso.",
            ),
            place: PreflightPlace::Accounts,
            requires: Some(RestrictedAction::ConfigureSources),
        },
        non_verificati,
    )
}

/// Il controllo 3: almeno una fonte che si possa sorvegliare.
///
/// Una fonte **ferma per scelta** non è in errore, ma non si sorveglia; una
/// **mai verificata** non è in errore, e si sorveglia. Il riepilogo è quello
/// già composto dalla salute delle fonti (DEC-252).
fn fonti(riepilogo: HealthSummary) -> Option<(String, PreflightFix)> {
    let utilizzabili = riepilogo
        .total
        .saturating_sub(riepilogo.failed)
        .saturating_sub(riepilogo.stopped);
    if utilizzabili > 0 {
        return None;
    }
    let frase = if riepilogo.total == 0 {
        String::from("Nessuna fonte configurata.")
    } else {
        format!(
            "Nessuna fonte si può sorvegliare adesso: {} in errore e {}, su {}.",
            riepilogo.failed,
            lisi_core::text::counted(riepilogo.stopped, "ferma per scelta", "ferme per scelta"),
            riepilogo.total
        )
    };
    Some((
        frase,
        PreflightFix {
            what_to_do: String::from(
                "Fonti › aggiungere una fonte, oppure «Perché questo stato?» sulla riga di una \
                 fonte in errore.",
            ),
            place: PreflightPlace::Sources,
            requires: Some(RestrictedAction::ConfigureSources),
        },
    ))
}

/// Il controllo 4: un monitoraggio interrotto **non** è un monitoraggio fermato.
///
/// Uno fermato da una persona, o concluso, non è una cosa che manca: è una
/// scelta (ADR-0064). Uno interrotto — il programma chiuso o caduto mentre
/// sorvegliava — lo è, finché qualcuno non l'ha preso in carico.
fn monitoraggio(interrotti: usize) -> Option<(String, PreflightFix)> {
    if interrotti == 0 {
        return None;
    }
    let frase = if interrotti == 1 {
        String::from(
            "Un monitoraggio si è interrotto senza che nessuno lo fermasse, e nessuno l'ha ancora \
             preso in carico.",
        )
    } else {
        format!(
            "{interrotti} monitoraggi si sono interrotti senza che nessuno li fermasse, e nessuno \
             li ha ancora presi in carico."
        )
    };
    Some((
        frase,
        PreflightFix {
            // IL GESTO E' QUELLO DELL'AVVISO DELL'INTERRUZIONE (BUG-UX-6). La frase
            // diceva che collegare l'account bastava a ricevere di nuovo: era vero
            // prima di ADR-0146. Da allora un monitoraggio interrotto non riceve
            // finche' qualcuno non decide, e l'avviso lo dice: due fasce sulla
            // stessa situazione davano istruzioni opposte. Il nome del comando
            // viene dal dominio, come quello che compare sull'avviso.
            what_to_do: format!(
                "Sull'avviso dell'interruzione, «{riprendi}» lo fa continuare fino alla sua \
                 scadenza: riceve i messaggi nuovi con l'account d'ufficio collegato. Il tratto \
                 rimasto chiuso resta non coperto. Se non serve più, Monitoraggio › «Arresta».",
                riprendi = lisi_core::model::interruption::decision_label(true),
            ),
            place: PreflightPlace::Monitoring,
            requires: None,
        },
    ))
}

/// Il controllo 8: l'Hub, soltanto in Team.
fn hub(raggiungibilita: HubReachability) -> Option<(String, PreflightFix)> {
    let frase = match raggiungibilita {
        HubReachability::NotConfigured | HubReachability::Reachable => return None,
        HubReachability::Unreachable => {
            "L'Hub dell'ufficio non risponde: il lavoro condiviso non si può fare."
        }
        HubReachability::NotTheExpectedHub => {
            "All'indirizzo dell'Hub risponde un'altra macchina: la sua chiave non è quella attesa. \
             Il lavoro condiviso non parte."
        }
        HubReachability::NotUsable => {
            "Questa postazione non ha ciò che serve per collegarsi all'Hub: l'identità o i tetti \
             del collegamento non sono utilizzabili."
        }
    };
    Some((
        String::from(frase),
        PreflightFix {
            what_to_do: String::from(
                "Live condiviso › controllare l'indirizzo dell'Hub, e chiedere a chi lo gestisce \
                 se è acceso.",
            ),
            place: PreflightPlace::TeamLive,
            requires: None,
        },
    ))
}

/// Il controllo 9: un orologio che è tornato indietro.
///
/// # Due fatti, nessuna soglia
///
/// Un istante **precedente all'ultimo fatto registrato** dice che l'orologio è
/// tornato indietro; uno **precedente al giorno in cui questo codice è stato
/// scritto** anche. Un orologio **avanti** non si vede senza una fonte esterna,
/// e il prodotto non ne interroga: lo dice l'ADR.
fn orologio(now: Timestamp, ultimo: Option<Timestamp>) -> Option<(String, PreflightFix)> {
    let frase = if now < CODE_WRITTEN_AT {
        format!(
            "L'ora di sistema dice {}, prima del giorno in cui questo programma è stato scritto.",
            now.to_readable_local()
        )
    } else {
        // Nessun fatto registrato dopo adesso: l'orologio non è tornato
        // indietro, per quanto l'archivio sa dire.
        let ultimo = ultimo.filter(|ultimo| now < *ultimo)?;
        format!(
            "L'ora di sistema dice {}, prima dell'ultimo fatto registrato nell'archivio ({}).",
            now.to_readable_local(),
            ultimo.to_readable_local()
        )
    };
    Some((
        format!("{frase} Ogni istante registrato adesso sarebbe falso."),
        PreflightFix {
            what_to_do: String::from(
                "Impostazioni di Windows › Ora e lingua › Data e ora: correggere l'ora. Poi \
                 «Ricontrolla».",
            ),
            place: PreflightPlace::OutsideTheProduct,
            requires: None,
        },
    ))
}

/// Come Windows tiene l'ora, in una frase che non promette ciò che non sa
/// (CLOCK-01, ADR-0168).
///
/// # Che cosa non dice
///
/// Che l'ora sia giusta: il registro dice come Windows è configurato, non
/// com'è andata l'ultima sincronizzazione. Chi non sincronizza dice che cosa
/// allora non si vedrebbe, e di chi è il gesto.
const fn ora_di_windows(stato: TimeSyncState) -> &'static str {
    match stato {
        TimeSyncState::FromServer => "Windows sincronizza l'ora con un orologio in rete.",
        TimeSyncState::FromDomain => "Windows sincronizza l'ora con il dominio dell'ufficio.",
        TimeSyncState::FromBoth => {
            "Windows sincronizza l'ora con il dominio dell'ufficio o con un orologio in rete."
        }
        TimeSyncState::NotSynchronized => {
            "Windows non sincronizza l'ora: un orologio avanti nel tempo non si vedrebbe. \
             Sincronizzarla è compito di chi amministra la postazione."
        }
        TimeSyncState::ServiceDisabled => {
            "Il servizio dell'ora di Windows è disattivato: un orologio avanti nel tempo non si \
             vedrebbe. Attivarlo è compito di chi amministra la postazione."
        }
        TimeSyncState::Undeterminable => "Non si è potuto leggere se Windows sincronizza l'ora.",
    }
}

/// Raccoglie i fatti che il centro non osserva, e registra il controllo.
#[derive(Debug)]
pub struct PreflightService {
    database: Database,
}

impl PreflightService {
    /// Crea il servizio attorno all'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante, per le prove.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Le interruzioni aperte: rilevate all'avvio, non ancora prese in carico.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn open_interruptions(&self) -> ServiceResult<usize> {
        Ok(self.database.open_interruptions()?.len())
    }

    /// L'ultimo istante registrato nell'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn latest_recorded(&self) -> ServiceResult<Option<Timestamp>> {
        Ok(self.database.latest_audit_at()?)
    }

    /// Lascia **una** riga d'audit: l'esito e il titolo del controllo.
    ///
    /// È l'unica scrittura del controllo di avvio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn record(
        &self,
        preflight: &Preflight,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        // Il dettaglio è l'esito e il TITOLO del controllo, mai la frase: la
        // frase del centro diagnostico può nominare una cartella da
        // correggere, e l'audit non è il posto dove conservarla.
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(PREFLIGHT_AUDIT_ACTION)?,
            entity: AuditEntity::try_new("postazione")?,
            entity_id: None,
            actor_mode: Some(preflight.mode),
            detail: Some(AuditDetail::try_new(&preflight.audit_detail())?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::role::{OperatingMode, RestrictedAction};
    use lisi_core::text::Actor;
    use lisi_platform::time_sync::TimeSyncState;

    use super::{
        CODE_WRITTEN_AT, HubReachability, PREFLIGHT_AUDIT_ACTION, Preflight, PreflightCheck,
        PreflightFacts, PreflightOutcome, PreflightPlace, PreflightService, assess, ora_di_windows,
    };
    use crate::diagnostics::{CheckOutcome, DiagnosticArea, DiagnosticCheck, DiagnosticReport};
    use crate::source_health::HealthSummary;
    use crate::sources::open_in_memory_database;

    /// Il sorgente del modulo, per le prove sulla forma.
    const THIS_MODULE: &str = include_str!("preflight.rs");

    fn adesso() -> Timestamp {
        Timestamp::from_millis(CODE_WRITTEN_AT.as_millis() + 86_400_000)
    }

    /// Un rapporto del centro con tutte le aree in ordine, salvo quelle indicate.
    fn rapporto(eccezioni: &[(DiagnosticArea, CheckOutcome)]) -> DiagnosticReport {
        let checks = DiagnosticArea::ALL
            .iter()
            .map(|area| {
                let outcome = eccezioni
                    .iter()
                    .find(|(quale, _)| quale == area)
                    .map_or(CheckOutcome::Good, |(_, esito)| *esito);
                DiagnosticCheck {
                    area: *area,
                    outcome,
                    detail: format!("Frase del centro su {}.", area.title()),
                    action: None,
                }
            })
            .collect();
        DiagnosticReport {
            taken_at: adesso(),
            checks,
        }
    }

    fn fonti_in_ordine() -> HealthSummary {
        HealthSummary {
            total: 2,
            operational: 2,
            ..HealthSummary::default()
        }
    }

    fn fatti() -> PreflightFacts {
        PreflightFacts {
            mode: OperatingMode::Administrator,
            sources: fonti_in_ordine(),
            open_interruptions: 0,
            hub: HubReachability::NotConfigured,
            latest_recorded: Some(Timestamp::from_millis(adesso().as_millis() - 3_600_000)),
            exercise: false,
            time_sync: TimeSyncState::FromServer,
        }
    }

    /// Il rapporto e i fatti in cui **soltanto** il controllo indicato manca.
    fn solo_rotto(check: PreflightCheck) -> (DiagnosticReport, PreflightFacts, Timestamp) {
        let mut facts = fatti();
        let mut now = adesso();
        let report = match check {
            PreflightCheck::Archive => {
                rapporto(&[(DiagnosticArea::Archive, CheckOutcome::Problem)])
            }
            PreflightCheck::TelegramAccount => {
                rapporto(&[(DiagnosticArea::TelegramRuntime, CheckOutcome::Attention)])
            }
            PreflightCheck::Sources => {
                facts.sources = HealthSummary::default();
                rapporto(&[])
            }
            PreflightCheck::Monitoring => {
                facts.open_interruptions = 1;
                rapporto(&[])
            }
            PreflightCheck::WindowsNotifications => rapporto(&[(
                DiagnosticArea::WindowsNotifications,
                CheckOutcome::Attention,
            )]),
            PreflightCheck::DiskSpace => {
                rapporto(&[(DiagnosticArea::DiskSpace, CheckOutcome::Problem)])
            }
            PreflightCheck::Backup => {
                rapporto(&[(DiagnosticArea::LastBackup, CheckOutcome::Attention)])
            }
            PreflightCheck::Hub => {
                facts.hub = HubReachability::Unreachable;
                rapporto(&[])
            }
            PreflightCheck::SystemClock => {
                now = Timestamp::from_millis(CODE_WRITTEN_AT.as_millis() - 1);
                facts.latest_recorded = None;
                rapporto(&[])
            }
        };
        (report, facts, now)
    }

    #[test]
    fn tutto_in_ordine_e_pronto() {
        let esito = assess(&rapporto(&[]), &fatti(), adesso());
        assert!(esito.is_ready());
        assert!(
            esito.line().starts_with("Pronto per lavorare."),
            "{}",
            esito.line()
        );
        assert!(esito.what_to_do().is_none());
        assert_eq!(esito.audit_detail(), "pronto");
    }

    /// **Ogni condizione rotta produce la propria riga e la propria azione**
    /// (PR-04, controllo negativo 4).
    #[test]
    fn ogni_condizione_rotta_ha_la_sua_riga() {
        for check in PreflightCheck::ALL {
            let (report, facts, now) = solo_rotto(check);
            let esito = assess(&report, &facts, now);
            let PreflightOutcome::NotYet { check: quale, .. } = &esito.outcome else {
                panic!("{check:?} rotto deve produrre «Non ancora»");
            };
            assert_eq!(*quale, check);
            assert!(
                esito
                    .line()
                    .starts_with(&format!("Non ancora: {}.", check.title())),
                "{check:?}: «{}»",
                esito.line()
            );
            assert!(
                esito
                    .what_to_do()
                    .is_some_and(|frase| !frase.trim().is_empty()),
                "{check:?}: nessuna azione"
            );
            assert_eq!(
                esito.audit_detail(),
                format!("non ancora: {}", check.title())
            );
        }
    }

    /// **Si dice la prima cosa che manca**, non tutte.
    #[test]
    fn si_dice_la_prima_cosa_che_manca() {
        let tutto_rotto = rapporto(&[
            (DiagnosticArea::Archive, CheckOutcome::Problem),
            (DiagnosticArea::TelegramRuntime, CheckOutcome::Attention),
            (
                DiagnosticArea::WindowsNotifications,
                CheckOutcome::Attention,
            ),
            (DiagnosticArea::DiskSpace, CheckOutcome::Problem),
            (DiagnosticArea::LastBackup, CheckOutcome::Attention),
        ]);
        let mut facts = fatti();
        facts.sources = HealthSummary::default();
        facts.open_interruptions = 2;
        facts.hub = HubReachability::NotTheExpectedHub;
        let esito = assess(&tutto_rotto, &facts, adesso());
        let PreflightOutcome::NotYet { check, .. } = esito.outcome else {
            panic!("tutto rotto non è pronto");
        };
        assert_eq!(check, PreflightCheck::Archive);

        let senza_archivio = rapporto(&[
            (DiagnosticArea::TelegramRuntime, CheckOutcome::Attention),
            (DiagnosticArea::DiskSpace, CheckOutcome::Problem),
        ]);
        let PreflightOutcome::NotYet { check, .. } =
            assess(&senza_archivio, &facts, adesso()).outcome
        else {
            panic!("manca ancora qualcosa");
        };
        assert_eq!(check, PreflightCheck::TelegramAccount);
    }

    /// **Un monitoraggio fermo per scelta non è un errore**; uno interrotto sì.
    #[test]
    fn fermo_per_scelta_non_e_un_errore() {
        let mut facts = fatti();
        facts.sources.stopped = 1;
        facts.sources.operational = 1;
        assert!(assess(&rapporto(&[]), &facts, adesso()).is_ready());
        facts.open_interruptions = 1;
        assert!(!assess(&rapporto(&[]), &facts, adesso()).is_ready());
    }

    /// **La fascia e l'avviso dell'interruzione dicono lo stesso gesto**
    /// (BUG-UX-6). La fascia diceva che collegare l'account bastava a ricevere
    /// di nuovo, l'avviso che senza una decisione non si riceve nulla.
    #[test]
    fn la_fascia_dice_il_gesto_dell_avviso_dell_interruzione() {
        let mut facts = fatti();
        facts.open_interruptions = 1;
        let esito = assess(&rapporto(&[]), &facts, adesso());
        let Some(gesto) = esito.what_to_do() else {
            panic!("un monitoraggio interrotto chiede un gesto");
        };
        let riprendi = lisi_core::model::interruption::decision_label(true);
        assert!(gesto.contains(&format!("«{riprendi}»")), "{gesto}");
        assert!(!gesto.contains("riceve di nuovo"), "{gesto}");
        assert!(!gesto.starts_with("Account ›"), "{gesto}");
    }

    /// **Almeno una fonte che si possa sorvegliare**: una mai verificata va,
    /// tutte in errore o ferme per scelta no.
    #[test]
    fn almeno_una_fonte_si_deve_poter_sorvegliare() {
        let mut facts = fatti();
        facts.sources = HealthSummary {
            total: 3,
            failed: 2,
            unknown: 1,
            ..HealthSummary::default()
        };
        assert!(assess(&rapporto(&[]), &facts, adesso()).is_ready());
        facts.sources = HealthSummary {
            total: 3,
            failed: 2,
            stopped: 1,
            ..HealthSummary::default()
        };
        let esito = assess(&rapporto(&[]), &facts, adesso());
        assert!(
            esito
                .line()
                .contains("2 in errore e 1 ferma per scelta, su 3"),
            "{}",
            esito.line()
        );
    }

    /// **«Non misurato» non ferma, e non si tace.**
    #[test]
    fn non_misurato_non_ferma_e_non_si_tace() {
        let esito = assess(
            &rapporto(&[(
                DiagnosticArea::WindowsNotifications,
                CheckOutcome::Unmeasured,
            )]),
            &fatti(),
            adesso(),
        );
        assert!(esito.is_ready());
        assert!(
            esito.line().contains("Non verificati: avvisi di Windows."),
            "{}",
            esito.line()
        );
        assert_eq!(
            esito.audit_detail(),
            "pronto; non verificati: avvisi di Windows"
        );
    }

    /// **Un orologio tornato indietro si vede**, rispetto all'archivio e al
    /// giorno in cui il codice è stato scritto.
    #[test]
    fn un_orologio_tornato_indietro_si_vede() {
        let mut facts = fatti();
        facts.latest_recorded = Some(Timestamp::from_millis(adesso().as_millis() + 60_000));
        let esito = assess(&rapporto(&[]), &facts, adesso());
        assert!(
            esito.line().starts_with("Non ancora: ora di sistema."),
            "{}",
            esito.line()
        );
        assert!(esito.line().contains("prima dell'ultimo fatto registrato"));
    }

    /// Le sei risposte che Windows può dare sull'ora.
    const OGNI_STATO_DELL_ORA: [TimeSyncState; 6] = [
        TimeSyncState::FromServer,
        TimeSyncState::FromDomain,
        TimeSyncState::FromBoth,
        TimeSyncState::NotSynchronized,
        TimeSyncState::ServiceDisabled,
        TimeSyncState::Undeterminable,
    ];

    /// **La riga dice come Windows tiene l'ora, e non ferma** (CLOCK-01,
    /// criteri 2 e 3; prove negative: la frase tolta dalla riga → rossa; un
    /// orologio non sincronizzato che ferma il lavoro → rossa).
    #[test]
    fn la_riga_dice_come_windows_tiene_l_ora_e_non_ferma() {
        for stato in OGNI_STATO_DELL_ORA {
            for exercise in [false, true] {
                let mut facts = fatti();
                facts.time_sync = stato;
                facts.exercise = exercise;
                let esito = assess(&rapporto(&[]), &facts, adesso());
                assert!(esito.is_ready(), "{stato:?}: {}", esito.line());
                assert!(
                    esito.line().contains(ora_di_windows(stato)),
                    "{stato:?}: {}",
                    esito.line()
                );
                assert_eq!(esito.audit_detail(), "pronto", "{stato:?}");
            }
        }
    }

    /// **Chi non sincronizza dice che cosa non si vedrebbe e di chi è il
    /// gesto, e nessuna frase promette un'ora giusta** (criterio 2).
    #[test]
    fn nessuna_frase_promette_un_ora_giusta() {
        for stato in [
            TimeSyncState::NotSynchronized,
            TimeSyncState::ServiceDisabled,
        ] {
            let frase = ora_di_windows(stato);
            assert!(
                frase.contains("un orologio avanti nel tempo non si vedrebbe"),
                "{stato:?}: {frase}"
            );
            assert!(
                frase.contains("chi amministra la postazione"),
                "{stato:?}: {frase}"
            );
        }
        for stato in OGNI_STATO_DELL_ORA {
            let frase = ora_di_windows(stato).to_lowercase();
            for promessa in ["giusta", "corretta", "esatta", "verificata", "precisa"] {
                assert!(!frase.contains(promessa), "{stato:?}: {frase}");
            }
        }
    }

    /// **Un orologio tornato indietro dice anche come Windows tiene l'ora;
    /// le altre cose che mancano no** (criterio 3).
    #[test]
    fn un_orologio_tornato_indietro_dice_come_windows_tiene_l_ora() {
        let mut facts = fatti();
        facts.latest_recorded = Some(Timestamp::from_millis(adesso().as_millis() + 60_000));
        facts.time_sync = TimeSyncState::NotSynchronized;
        let esito = assess(&rapporto(&[]), &facts, adesso());
        assert!(!esito.is_ready());
        assert!(
            esito
                .line()
                .ends_with(ora_di_windows(TimeSyncState::NotSynchronized)),
            "{}",
            esito.line()
        );

        let (report, mut facts, now) = solo_rotto(PreflightCheck::DiskSpace);
        facts.time_sync = TimeSyncState::NotSynchronized;
        let riga = assess(&report, &facts, now).line();
        assert!(!riga.contains("sincronizza"), "{riga}");
    }

    /// **Una correzione dichiara l'azione che richiede, e il rimando
    /// all'amministratore compare solo se la modalità la rifiuta** (PR-04,
    /// controllo negativo 2; ADR-0140).
    ///
    /// Fino al 2026-10-15 la prova voleva il rimando in modalità operatore per
    /// account e fonti. Il proprietario ha deciso che l'operatore li configura
    /// da sé: il rimando lo avrebbe mandato da qualcuno senza ragione. La prova
    /// è stata riscritta per la regola nuova; la parte negativa resta, e dice
    /// che nessuna delle due correzioni manda dall'amministratore.
    #[test]
    fn le_correzioni_riservate_lo_dichiarano() {
        for check in [PreflightCheck::TelegramAccount, PreflightCheck::Sources] {
            let (report, mut facts, now) = solo_rotto(check);
            let PreflightOutcome::NotYet { fix, .. } = assess(&report, &facts, now).outcome else {
                panic!("{check:?} rotto");
            };
            assert_eq!(
                fix.requires,
                Some(RestrictedAction::ConfigureSources),
                "{check:?}"
            );

            facts.mode = OperatingMode::Operator;
            let frase = assess(&report, &facts, now)
                .what_to_do()
                .unwrap_or_default();
            assert!(
                !frase.contains("Serve la modalità amministratore"),
                "{check:?}: l'operatore configura account e fonti da sé (ADR-0140): {frase}"
            );

            facts.mode = OperatingMode::Administrator;
            let frase = assess(&report, &facts, now)
                .what_to_do()
                .unwrap_or_default();
            assert!(
                !frase.contains("Serve la modalità amministratore"),
                "{check:?}: {frase}"
            );
        }
    }

    /// **Dove il gesto sta fuori dal prodotto, lo si dice**, e non si finge un
    /// pulsante.
    #[test]
    fn cio_che_sta_fuori_dal_prodotto_lo_dice() {
        for check in [
            PreflightCheck::WindowsNotifications,
            PreflightCheck::DiskSpace,
            PreflightCheck::SystemClock,
        ] {
            let (report, facts, now) = solo_rotto(check);
            let PreflightOutcome::NotYet { fix, .. } = assess(&report, &facts, now).outcome else {
                panic!("{check:?} rotto");
            };
            assert_eq!(fix.place, PreflightPlace::OutsideTheProduct, "{check:?}");
            assert!(fix.what_to_do.contains("Ricontrolla"), "{check:?}");
        }
    }

    /// **Nessuna frase contiene un percorso** (PR-04, controllo negativo 3).
    #[test]
    fn nessuna_frase_contiene_un_percorso() {
        let mut frasi: Vec<String> = Vec::new();
        for check in PreflightCheck::ALL {
            for mode in [OperatingMode::Administrator, OperatingMode::Operator] {
                let (report, mut facts, now) = solo_rotto(check);
                facts.mode = mode;
                let esito = assess(&report, &facts, now);
                frasi.push(esito.line());
                frasi.extend(esito.what_to_do());
                frasi.push(esito.audit_detail());
            }
        }
        for hub in [
            HubReachability::NotTheExpectedHub,
            HubReachability::NotUsable,
        ] {
            let mut facts = fatti();
            facts.hub = hub;
            frasi.push(assess(&rapporto(&[]), &facts, adesso()).line());
        }
        assert!(frasi.len() > 20);
        for frase in frasi {
            for segno in [
                ":\\", "\\\\", "/Users", "/home", "AppData", ".db", ".sqlite", "%",
            ] {
                assert!(
                    !frase.contains(segno),
                    "«{segno}» in una frase del controllo: {frase}"
                );
            }
        }
    }

    /// **Stesso rapporto, stessi fatti, stesso istante: stesso esito.**
    #[test]
    fn il_controllo_e_una_funzione_pura() {
        for check in PreflightCheck::ALL {
            let (report, facts, now) = solo_rotto(check);
            assert_eq!(assess(&report, &facts, now), assess(&report, &facts, now));
        }
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        assert!(
            !produzione.contains("now("),
            "il controllo non legge l'orologio da sé"
        );
        // Né il registro di Windows: come Windows tiene l'ora arriva da chi
        // chiama, come l'istante (CLOCK-01, criterio 4).
        assert!(
            !produzione.contains("time_sync_state("),
            "il controllo non legge Windows da sé"
        );
    }

    /// **Il controllo non modifica nulla**: l'unica scrittura è la sua riga
    /// d'audit (PR-04, controllo negativo 1).
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un controllo di avvio che «ripara» da solo — che avvia il monitoraggio,
    /// prende in carico un'interruzione, produce una copia — farebbe accadere
    /// all'avvio cose che nessuno ha deciso. Il contatore dell'archivio conta
    /// ogni riga scritta, aggiornata o cancellata: deve crescere di una.
    #[test]
    fn il_controllo_non_modifica_nulla() {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let service = PreflightService::new(database);
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };

        let prima = service.database().total_changes();
        let (Ok(interruzioni), Ok(ultimo)) =
            (service.open_interruptions(), service.latest_recorded())
        else {
            panic!("le letture del controllo devono riuscire");
        };
        let mut facts = fatti();
        facts.open_interruptions = interruzioni;
        facts.latest_recorded = ultimo;
        let esito: Preflight = assess(&rapporto(&[]), &facts, adesso());
        let Ok(()) = service.record(&esito, &attore, adesso()) else {
            panic!("la riga d'audit deve scriversi");
        };
        let dopo = service.database().total_changes();

        assert_eq!(
            dopo - prima,
            1,
            "il controllo deve scrivere una riga, e una sola"
        );
        let Ok(voci) = service.database().audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        let Some(ultima) = voci.last() else {
            panic!("la riga d'audit deve esserci");
        };
        assert_eq!(ultima.action.as_str(), PREFLIGHT_AUDIT_ACTION);
    }

    /// **In Esercitazione account, fonti, Hub e copia di sicurezza non fermano
    /// la prova** (OPERATOR-UX-REMEDIATION-01, OS-03), e la riga lo dice.
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La fascia «Non ancora: account Telegram… senza, non si può acquisire
    /// nulla» sotto la fascia che prometteva una prova completa su dati
    /// inventati: l'operatore simulato non capiva se poteva cominciare.
    #[test]
    fn in_esercitazione_l_account_non_ferma_la_prova() {
        for check in [
            PreflightCheck::TelegramAccount,
            PreflightCheck::Sources,
            PreflightCheck::Hub,
            PreflightCheck::Backup,
        ] {
            let (report, mut facts, now) = solo_rotto(check);
            assert!(
                !assess(&report, &facts, now).is_ready(),
                "fuori dall'Esercitazione {check:?} rotto ferma il controllo"
            );
            facts.exercise = true;
            let esito = assess(&report, &facts, now);
            assert!(esito.is_ready(), "in Esercitazione {check:?} non ferma");
            assert!(
                esito.line().starts_with("Pronto per l'esercitazione"),
                "la riga dice che è l'esercitazione: {}",
                esito.line()
            );
        }
    }

    /// **In Esercitazione l'archivio, lo spazio e l'ora contano ancora**: la
    /// prova non salta i controlli che valgono anche per lei.
    #[test]
    fn in_esercitazione_l_archivio_rotto_ferma_ancora() {
        for check in [
            PreflightCheck::Archive,
            PreflightCheck::DiskSpace,
            PreflightCheck::SystemClock,
            PreflightCheck::Monitoring,
        ] {
            let (report, mut facts, now) = solo_rotto(check);
            facts.exercise = true;
            let esito = assess(&report, &facts, now);
            assert!(!esito.is_ready(), "{check:?} rotto ferma anche la prova");
        }
    }
}

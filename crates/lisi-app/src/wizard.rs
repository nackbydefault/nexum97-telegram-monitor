//! Collegamento fra la pagina del wizard e la macchina a stati dei servizi.
//!
//! Come per le altre schermate, qui non c'è logica. In particolare **non si
//! decide se si possa passare avanti**: quella risposta viene da
//! `MonitoringWizard`, dove è coperta da diciannove test. Se la calcolasse
//! l'interfaccia, la regola vivrebbe in un file che nessun test guarda, e la
//! prima schermata costruita male la aggirerebbe.
//!
//! L'anteprima del riepilogo **non scrive nulla**: usa la stessa risoluzione
//! dell'avvio, così che ciò che l'operatore vede sia ciò che verrebbe usato.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::dictionary::{MatchMode, SuggestedLevel};
use lisi_core::model::schedule::LeadRefusal;
use lisi_core::time::{LocalConversion, LocalDateTime, local_to_instant_here};
use lisi_core::{DictionaryId, SourceId};
use lisi_services::SelectedDictionary;
use lisi_services::wizard::{
    MonitoringWizard, WizardDuration, WizardNotice, WizardStart, WizardStep,
};
use slint::{ComponentHandle, Model as _, ModelRc, SharedString, VecModel};

use crate::dictionaries::SharedDictionaries;
use crate::sources::SharedSources;
use crate::{
    AppWindow, WizardChosenDictionary, WizardDictionaryEntry, WizardNoticeEntry, WizardSourceEntry,
    WizardStepEntry, WizardTermEntry,
};

/// Composizione condivisa fra i gestori dei comandi.
pub type SharedWizard = Rc<RefCell<MonitoringWizard>>;

/// Crea una composizione vuota.
#[must_use]
pub fn create() -> SharedWizard {
    Rc::new(RefCell::new(MonitoringWizard::new()))
}

/// Riporta nell'interfaccia lo stato della composizione.
pub fn refresh(
    window: &AppWindow,
    wizard: &SharedWizard,
    dictionaries: &SharedDictionaries,
    sources: Option<&SharedSources>,
    message: Option<&str>,
) {
    if let Some(text) = message {
        window.set_wizard_message(SharedString::from(text));
    }

    let view = wizard.borrow().view();

    window.set_wizard_step(i32::try_from(view.step.number()).unwrap_or(1));
    window.set_wizard_title(crate::lingua::schermo(view.step.title()));
    window.set_wizard_prompt(crate::lingua::schermo(view.step.prompt()));
    window.set_wizard_can_advance(view.can_advance);
    window.set_wizard_can_go_back(view.can_go_back);
    window.set_wizard_blocking_reason(SharedString::from(view.blocking_reason.unwrap_or_default()));
    // Tradotta come le etichette dei pulsanti, che la confrontano per
    // accendere quello scelto (I18N-01): due lingue diverse non sarebbero mai
    // uguali.
    window.set_wizard_duration_label(SharedString::from(crate::lingua::tr(
        &view.duration.label(),
    )));
    window.set_wizard_duration_manual(matches!(view.duration, WizardDuration::Manual));
    window.set_wizard_duration_custom(matches!(view.duration, WizardDuration::Custom(_)));
    window.set_wizard_start_scheduled(matches!(view.start, WizardStart::At(_)));
    window.set_wizard_start_label(SharedString::from(start_label(view.start)));

    // I conteggi del riepilogo esistono solo da lì in avanti: prima non sono
    // zero, sono assenti, e mostrarli come zero significherebbe inventarli.
    window.set_wizard_has_preview(view.resolved_terms.is_some());
    window.set_wizard_resolved_terms(count_of(view.resolved_terms));
    window.set_wizard_shared_terms(count_of(view.shared_terms));
    window.set_wizard_digest(SharedString::from(view.digest.unwrap_or_default()));

    // Che cosa l'operatore ha SCELTO, non che cosa la libreria contiene.
    //
    // Sono due numeri diversi, e fino al 2026-08-25 il riepilogo mostrava il
    // secondo chiamandolo il primo: leggeva la lunghezza degli elenchi
    // disponibili invece dei conteggi della macchina a stati. Chi ne aveva
    // spuntato uno leggeva «dizionari scelti: 7».
    window.set_wizard_chosen_sources(i32::try_from(view.source_count).unwrap_or(i32::MAX));
    window.set_wizard_chosen_dictionary_count(
        i32::try_from(view.dictionary_count).unwrap_or(i32::MAX),
    );
    window.set_wizard_chosen_dictionaries(chosen_model(view.selected_dictionaries.as_deref()));
    window.set_wizard_notices(notice_model(&view.notices));

    window.set_wizard_steps(step_model(view.step));
    let fonti = source_model(wizard, sources);
    window.set_wizard_chosen_source_names(SharedString::from(chosen_source_names(&fonti)));
    window.set_wizard_sources(fonti);
    window.set_wizard_dictionaries(dictionary_model(wizard, dictionaries));
    window.set_wizard_terms(term_model(wizard));
}

/// Le fonti scelte, per nome e genere, una per riga (UX-EXCELLENCE-02,
/// SIM3-14): il riepilogo apriva con i conteggi e l'impronta, e la fonte
/// scelta non era nominata.
fn chosen_source_names(fonti: &ModelRc<WizardSourceEntry>) -> String {
    fonti
        .iter()
        .filter(|fonte| fonte.selected)
        .map(|fonte| format!("\u{2022} {} \u{2014} {}", fonte.title, fonte.kind))
        .collect::<Vec<_>>()
        .join("\n")
}

/// I dizionari scelti con la loro versione, come il riepilogo li mostra.
///
/// L'elenco è vuoto finché la fotografia non è stata scattata: prima del
/// riepilogo non esiste, e mostrarlo vuoto direbbe che nessun dizionario è
/// stato scelto — che è un'altra cosa.
fn chosen_model(selected: Option<&[SelectedDictionary]>) -> ModelRc<WizardChosenDictionary> {
    let entries: Vec<WizardChosenDictionary> = selected
        .unwrap_or_default()
        .iter()
        .map(|entry| WizardChosenDictionary {
            label: crate::lingua::schermo(entry.label()),
            scope: crate::lingua::schermo(entry.scope.label()),
            terms: i32::try_from(entry.terms).unwrap_or(i32::MAX),
            reducing_terms: i32::try_from(entry.reducing_terms).unwrap_or(i32::MAX),
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Gli avvisi del riepilogo.
///
/// Il rimedio è una stringa vuota quando non c'è: l'interfaccia mostra la riga
/// solo se non è vuota, invece di disegnare uno spazio dove un consiglio non
/// esiste.
fn notice_model(notices: &[WizardNotice]) -> ModelRc<WizardNoticeEntry> {
    let entries: Vec<WizardNoticeEntry> = notices
        .iter()
        .map(|notice| WizardNoticeEntry {
            text: SharedString::from(notice.text.as_str()),
            remedy: SharedString::from(notice.remedy.clone().unwrap_or_default()),
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Converte un conteggio facoltativo, con zero quando è assente.
///
/// Il valore è significativo **solo** insieme a `wizard-has-preview`, che dice
/// se il conteggio esiste: l'interfaccia non mostra il numero senza quello.
fn count_of(value: Option<usize>) -> i32 {
    value
        .and_then(|count| i32::try_from(count).ok())
        .unwrap_or(0)
}

/// Barra dei passi, con quelli già superati.
fn step_model(current: WizardStep) -> ModelRc<WizardStepEntry> {
    let entries: Vec<WizardStepEntry> = WizardStep::ALL
        .iter()
        .map(|step| WizardStepEntry {
            number: i32::try_from(step.number()).unwrap_or(0),
            title: crate::lingua::schermo(step.title()),
            reached: step.number() <= current.number(),
            current: *step == current,
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Fonti configurate, con quelle scelte.
fn source_model(
    wizard: &SharedWizard,
    sources: Option<&SharedSources>,
) -> ModelRc<WizardSourceEntry> {
    let Some(sources) = sources else {
        return ModelRc::from(Rc::new(VecModel::from(Vec::new())));
    };
    let Ok(configured) = sources.borrow().configured() else {
        return ModelRc::from(Rc::new(VecModel::from(Vec::new())));
    };

    let composition = wizard.borrow();
    let entries: Vec<WizardSourceEntry> = configured
        .iter()
        .filter(|source| source.active)
        .map(|source| WizardSourceEntry {
            source_id: i32::try_from(source.id.get()).unwrap_or(0),
            title: SharedString::from(source.display_name.as_str()),
            // LA PAROLA, non la chiave: questa riga stampava «channel»
            // accanto al nome della fonte, sullo schermo da cui si compone
            // un monitoraggio (FINAL-FPR-ALL-16, FPR-02).
            kind: crate::lingua::schermo(source.kind.label()),
            selected: composition.has_source(source.id),
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Dizionari utilizzabili, con quelli scelti.
fn dictionary_model(
    wizard: &SharedWizard,
    dictionaries: &SharedDictionaries,
) -> ModelRc<WizardDictionaryEntry> {
    let service = dictionaries.borrow();
    let Ok(usable) = service.usable() else {
        return ModelRc::from(Rc::new(VecModel::from(Vec::new())));
    };

    let composition = wizard.borrow();
    let entries: Vec<WizardDictionaryEntry> = usable
        .iter()
        .map(|dictionary| {
            let terms = service.published_terms(dictionary.id).unwrap_or_default();
            let (sample, truncated) = term_sample(&terms);
            WizardDictionaryEntry {
                dictionary_id: i32::try_from(dictionary.id.get()).unwrap_or(0),
                name: SharedString::from(dictionary.name.as_str()),
                scope: crate::lingua::schermo(dictionary.scope.label()),
                terms: i32::try_from(terms.len()).unwrap_or(i32::MAX),
                selected: composition.has_dictionary(dictionary.id),
                description: SharedString::from(dictionary.description.as_str()),
                sample: SharedString::from(sample),
                sample_truncated: truncated,
            }
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Quante parole di un dizionario si mostrano come assaggio nella riga.
///
/// Poche per stare su una riga leggibile, abbastanza da far capire di che cosa
/// il dizionario parli. L'elenco completo vive nella schermata Dizionari.
const SAMPLE_TERMS: usize = 6;

/// Assaggio delle parole di un dizionario, e se ne sono state omesse.
///
/// Fino al 2026-07-31 la riga del wizard mostrava solo un **numero** di
/// termini: chi doveva scegliere non aveva modo di sapere che cosa un
/// dizionario cercasse, e sceglieva alla cieca. Un conteggio dice quanto è
/// grande una cosa, non che cosa sia.
fn term_sample(terms: &[lisi_core::model::dictionary::DictionaryTerm]) -> (String, bool) {
    let shown: Vec<&str> = terms
        .iter()
        .take(SAMPLE_TERMS)
        .map(|term| term.text.as_str())
        .collect();
    (shown.join(", "), terms.len() > shown.len())
}

/// Gravità scelta nell'elenco a discesa, dall'indice della voce selezionata.
///
/// L'elenco mostra i livelli da 1 a 4, quindi la voce all'indice `i` vale
/// `i + 1`. Un indice fuori intervallo — che l'interfaccia non dovrebbe
/// produrre, ma che è un intero e potrebbe — ricade sul livello più debole
/// **che produce comunque un avviso**, mai su zero: zero è «nessun avviso», e
/// una parola che l'operatore ha chiesto di sorvegliare non deve mai finire
/// in uno stato che non può segnalare nulla. È il difetto rilevato nel pilot
/// del 2026-07-31, e questa funzione esiste anche per non reintrodurlo da
/// un'altra porta.
fn term_level_from_index(index: i32) -> SuggestedLevel {
    let Ok(offset) = i8::try_from(index) else {
        return SuggestedLevel::weakest_that_alerts();
    };
    let Some(level) = offset.checked_add(1) else {
        return SuggestedLevel::weakest_that_alerts();
    };
    SuggestedLevel::try_new(level)
        .ok()
        .filter(|chosen| chosen.get() >= SuggestedLevel::weakest_that_alerts().get())
        .unwrap_or_else(SuggestedLevel::weakest_that_alerts)
}

/// Etichette della gravità, nell'ordine dell'elenco a discesa.
///
/// Sono **le stesse parole** che il `ComboBox` mostra in
/// `ui/app-window.slint`: chi sceglie «prioritario» e poi rilegge la propria
/// scelta scritta in un altro modo ha ragione di dubitare di averla fatta. Un
/// test legge il file dell'interfaccia e fallisce se le due formulazioni
/// divergono.
const LEVEL_LABELS: [&str; 4] = [
    "Livello 1 — debole",
    "Livello 2 — da tenere d'occhio",
    "Livello 3 — forte",
    "Livello 4 — prioritario",
];

/// Etichetta della gravità dichiarata per una parola aggiunta.
///
/// I livelli fuori da 1..=4 non possono nascere da questa schermata, perché
/// [`term_level_from_index`] li esclude. Se ne arrivasse uno — da una
/// migrazione, da una composizione ripresa — viene reso com'è invece di essere
/// nascosto o normalizzato: un valore inatteso mostrato è un difetto che si
/// vede, un valore inatteso corretto in silenzio è un difetto che resta.
fn term_level_label(level: SuggestedLevel) -> String {
    let value = level.get();
    usize::try_from(value)
        .ok()
        .filter(|position| (1..=LEVEL_LABELS.len()).contains(position))
        .and_then(|position| LEVEL_LABELS.get(position - 1))
        .map_or_else(|| format!("livello {value}"), |label| (*label).to_string())
}

/// Parole aggiunte alla composizione.
fn term_model(wizard: &SharedWizard) -> ModelRc<WizardTermEntry> {
    let composition = wizard.borrow();
    let entries: Vec<WizardTermEntry> = composition
        .custom_terms()
        .iter()
        .enumerate()
        .map(|(index, term)| WizardTermEntry {
            index: i32::try_from(index).unwrap_or(0),
            text: SharedString::from(term.text.as_str()),
            match_mode: crate::lingua::schermo(term.match_mode.label()),
            level: SharedString::from(term_level_label(term.suggested_level)),
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Collega i comandi della pagina alla composizione.
pub fn wire(
    window: &AppWindow,
    wizard: &SharedWizard,
    dictionaries: &SharedDictionaries,
    sources: Option<&SharedSources>,
) {
    /// Ripete il collegamento di un comando che non produce messaggi.
    macro_rules! on_command {
        ($setter:ident, $body:expr) => {{
            let handle = window.as_weak();
            let composition = Rc::clone(wizard);
            let library = Rc::clone(dictionaries);
            let configured = sources.map(Rc::clone);
            window.$setter(move |value| {
                if crate::lock::refuse_while_locked(stringify!($setter)) {
                    return;
                }
                let Some(window) = handle.upgrade() else {
                    return;
                };
                #[allow(clippy::redundant_closure_call)]
                $body(&composition, value);
                refresh(
                    &window,
                    &composition,
                    &library,
                    configured.as_ref(),
                    Some(""),
                );
            });
        }};
    }

    on_command!(
        on_wizard_toggle_source,
        |composition: &SharedWizard, value: i32| {
            composition
                .borrow_mut()
                .toggle_source(SourceId::new(i64::from(value)));
        }
    );

    on_command!(
        on_wizard_toggle_dictionary,
        |composition: &SharedWizard, value: i32| {
            composition
                .borrow_mut()
                .toggle_dictionary(DictionaryId::new(i64::from(value)));
        }
    );

    on_command!(
        on_wizard_remove_term,
        |composition: &SharedWizard, value: i32| {
            let index = usize::try_from(value).unwrap_or(usize::MAX);
            composition.borrow_mut().remove_custom_term(index);
        }
    );

    {
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(
                    &window,
                    &composition,
                    &library,
                    configured.as_ref(),
                    Some(""),
                );
            }
        });
    }

    {
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_back(move || {
            if crate::lock::refuse_while_locked("wizard_back") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                composition.borrow_mut().go_back();
                refresh(
                    &window,
                    &composition,
                    &library,
                    configured.as_ref(),
                    Some(""),
                );
            }
        });
    }

    {
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_advance(move || {
            if crate::lock::refuse_while_locked("wizard_advance") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };

            // Il prestito del servizio finisce prima del refresh: `RefCell`
            // scopre i prestiti sovrapposti solo a runtime, e sarebbe un
            // arresto invece di un errore di compilazione.
            let outcome = {
                let service = library.borrow();
                composition.borrow_mut().advance(&service)
            };

            let message = match outcome {
                Ok(()) => String::new(),
                Err(error) => error.operator_message(),
            };
            refresh(
                &window,
                &composition,
                &library,
                configured.as_ref(),
                Some(&message),
            );
        });
    }

    {
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_add_term(move || {
            if crate::lock::refuse_while_locked("wizard_add_term") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let typed = window.get_wizard_term_input().to_string();

            // Una frase si riconosce dallo spazio: e' la scelta che l'operatore
            // farebbe comunque, e chiedergliela per ogni parola aggiungerebbe
            // un passo a un'operazione che deve restare rapida.
            let mode = if typed.trim().contains(' ') {
                MatchMode::Phrase
            } else {
                MatchMode::NormalizedWord
            };

            let level = term_level_from_index(window.get_wizard_term_level_index());
            // Una parola già aggiunta si dice, e il campo resta scritto (F-11):
            // svuotarlo farebbe credere che sia entrata una seconda volta.
            if composition.borrow().has_custom_term(&typed, mode) {
                let message = format!(
                    "«{}» è già fra le parole aggiunte: per cambiarne il livello, toglierla \
                     e aggiungerla di nuovo.",
                    typed.trim()
                );
                refresh(
                    &window,
                    &composition,
                    &library,
                    configured.as_ref(),
                    Some(&message),
                );
                return;
            }
            let message = match composition
                .borrow_mut()
                .add_custom_term(&typed, mode, level)
            {
                Ok(()) => {
                    window.set_wizard_term_input(SharedString::new());
                    String::new()
                }
                Err(error) => error.operator_message(),
            };
            refresh(
                &window,
                &composition,
                &library,
                configured.as_ref(),
                Some(&message),
            );
        });
    }

    {
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_set_duration(move |seconds, manual| {
            if crate::lock::refuse_while_locked("wizard_set_duration") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let duration = if manual {
                WizardDuration::Manual
            } else {
                WizardDuration::Preset(u32::try_from(seconds).unwrap_or(3_600))
            };
            composition.borrow_mut().set_duration(duration);
            window.set_wizard_duration_message(SharedString::default());
            refresh(
                &window,
                &composition,
                &library,
                configured.as_ref(),
                Some(""),
            );
        });
    }

    {
        // LA DURATA PERSONALIZZATA (ADR-0150): fuori dai limiti si rifiuta con
        // la misura, e la durata scelta prima resta.
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_set_custom_duration(move |ore, minuti| {
            if crate::lock::refuse_while_locked("wizard_set_custom_duration") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let scelta = custom_duration(ore, minuti);
            match scelta {
                Some(durata) => {
                    composition.borrow_mut().set_duration(durata);
                    window.set_wizard_duration_message(SharedString::default());
                }
                None => window
                    .set_wizard_duration_message(SharedString::from(WizardDuration::CUSTOM_LIMITS)),
            }
            refresh(
                &window,
                &composition,
                &library,
                configured.as_ref(),
                Some(""),
            );
        });
    }

    {
        // QUANDO PARTE (SCHEDULE-01, ADR-0171): adesso, oppure una data e
        // un'ora locali convertite con il fuso di quel giorno. Un rifiuto dice
        // perché, e la scelta di prima resta.
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_set_start_now(move || {
            if crate::lock::refuse_while_locked("wizard_set_start_now") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            composition.borrow_mut().set_start_now();
            window.set_wizard_start_message(SharedString::default());
            refresh(
                &window,
                &composition,
                &library,
                configured.as_ref(),
                Some(""),
            );
        });
    }

    {
        let handle = window.as_weak();
        let composition = Rc::clone(wizard);
        let library = Rc::clone(dictionaries);
        let configured = sources.map(Rc::clone);
        window.on_wizard_set_start_at(move |data, ora| {
            if crate::lock::refuse_while_locked("wizard_set_start_at") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let esito = start_from_fields(data.as_str(), ora.as_str(), local_to_instant_here)
                .and_then(|istante| {
                    composition
                        .borrow_mut()
                        .set_start_at(istante, crate::account::now())
                        .map_err(LeadRefusal::sentence)
                });
            window.set_wizard_start_message(SharedString::from(match esito {
                Ok(()) => "",
                Err(ragione) => ragione,
            }));
            refresh(
                &window,
                &composition,
                &library,
                configured.as_ref(),
                Some(""),
            );
        });
    }
}

/// Come si legge l'inizio scelto (SCHEDULE-01): l'ora locale con l'UTC
/// accanto (ADR-0136).
fn start_label(start: WizardStart) -> String {
    match start {
        WizardStart::Now => String::from("Adesso, alla conferma"),
        WizardStart::At(istante) => format!("programmato per {}", istante.to_readable_local()),
    }
}

/// L'inizio scritto nei due campi, come istante, o la ragione per cui non lo è
/// (SCHEDULE-01, ADR-0171, decisione 1).
fn start_from_fields(
    data: &str,
    ora: &str,
    convert: impl Fn(LocalDateTime) -> LocalConversion,
) -> Result<lisi_core::Timestamp, &'static str> {
    let Some(locale) = LocalDateTime::parse(data, ora) else {
        return Err("Data o ora non valide: scrivere la data come 26/10/2026 e l'ora come 09:30.");
    };
    match convert(locale) {
        LocalConversion::Exact(istante) => Ok(istante),
        LocalConversion::Nonexistent => Err(
            "Quel giorno quell'ora non esiste: l'orologio va avanti di un'ora per l'ora legale. \
             Scegliere un'altra ora.",
        ),
        LocalConversion::Ambiguous => Err(
            "Quel giorno quell'ora c'è due volte: l'orologio torna indietro di un'ora. \
             Scegliere un'altra ora.",
        ),
        LocalConversion::UnknownZone => {
            Err("Il fuso orario di Windows non si legge: l'inizio non si può programmare.")
        }
    }
}

/// La durata personalizzata dai due campi della schermata, se nei limiti.
/// Un numero negativo non è una durata, e si rifiuta come le altre.
fn custom_duration(ore: i32, minuti: i32) -> Option<WizardDuration> {
    let (Ok(ore), Ok(minuti)) = (u32::try_from(ore), u32::try_from(minuti)) else {
        return None;
    };
    WizardDuration::custom(ore, minuti)
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{MatchMode, SuggestedLevel};
    use lisi_core::{DictionaryId, SourceId};
    use lisi_services::wizard::{WizardDuration, WizardStep};

    use super::{
        LEVEL_LABELS, SAMPLE_TERMS, create, step_model, term_level_from_index, term_level_label,
        term_sample,
    };

    /// **I campi dell'inizio si leggono, e ogni rifiuto dice perché**
    /// (SCHEDULE-01, ADR-0171, criteri 1 e 2): una data malformata, un'ora
    /// che quel giorno non esiste o esiste due volte, un fuso che non si legge.
    #[test]
    fn i_campi_dell_inizio_si_leggono_o_dicono_perche_no() {
        use lisi_core::time::{LocalConversion, LocalDateTime};

        let esatto = |_: LocalDateTime| {
            LocalConversion::Exact(lisi_core::Timestamp::from_millis(1_800_000_000_000))
        };
        assert_eq!(
            super::start_from_fields("26/10/2026", "09:00", esatto),
            Ok(lisi_core::Timestamp::from_millis(1_800_000_000_000))
        );
        let Err(malformata) = super::start_from_fields("26-10-2026", "9", esatto) else {
            panic!("una data malformata si rifiuta");
        };
        assert!(malformata.contains("26/10/2026"));
        for (conversione, attesa) in [
            (LocalConversion::Nonexistent, "non esiste"),
            (LocalConversion::Ambiguous, "due volte"),
            (LocalConversion::UnknownZone, "fuso orario"),
        ] {
            let Err(ragione) = super::start_from_fields("26/10/2026", "09:00", |_| conversione)
            else {
                panic!("{conversione:?} si rifiuta");
            };
            assert!(ragione.contains(attesa), "{ragione}");
        }
        assert_eq!(
            super::start_label(lisi_services::wizard::WizardStart::Now),
            "Adesso, alla conferma"
        );
    }

    #[test]
    fn la_scelta_delle_fonti_scrive_il_genere_in_parole() {
        // Scriveva «channel» accanto al nome della fonte, nella schermata da
        // cui si compone un monitoraggio: si vede nella cattura 600-6 del
        // 2026-10-12 (FINAL-FPR-ALL-16, FPR-02). La parola viene dal dominio,
        // ed è la stessa che la schermata Fonti e il registro usano.
        for genere in lisi_services::sources::SourceKind::all() {
            let parola = genere.label();
            assert_ne!(
                parola,
                genere.as_str(),
                "«{}» arriverebbe allo schermo come chiave dell'archivio",
                genere.as_str()
            );
            assert!(!parola.is_empty());
        }
        assert_eq!(
            lisi_services::sources::SourceKind::Channel.label(),
            "Canale"
        );
    }

    #[test]
    fn a_fresh_composition_starts_at_the_first_step() {
        let wizard = create();
        let view = wizard.borrow().view();

        assert_eq!(view.step, WizardStep::Sources);
        assert!(!view.can_go_back);
        assert_eq!(view.resolved_terms, None, "prima del riepilogo non esiste");
    }

    #[test]
    fn the_step_bar_marks_what_has_been_reached_and_where_one_is() {
        use slint::Model;

        let steps = step_model(WizardStep::CustomTerms);
        let rendered: Vec<(i32, bool, bool)> = steps
            .iter()
            .map(|entry| (entry.number, entry.reached, entry.current))
            .collect();

        assert_eq!(rendered.len(), 6);
        assert_eq!(rendered[0], (1, true, false), "primo passo, gia' superato");
        assert_eq!(rendered[2], (3, true, true), "passo corrente");
        assert_eq!(rendered[3], (4, false, false), "non ancora raggiunto");
    }

    #[test]
    fn a_selection_toggled_twice_returns_to_nothing() {
        let wizard = create();
        {
            let mut composition = wizard.borrow_mut();
            composition.toggle_dictionary(DictionaryId::new(3));
            composition.toggle_source(SourceId::new(1));
        }
        assert_eq!(wizard.borrow().view().dictionary_count, 1);

        wizard.borrow_mut().toggle_dictionary(DictionaryId::new(3));
        assert_eq!(wizard.borrow().view().dictionary_count, 0);
        assert_eq!(wizard.borrow().view().source_count, 1);
    }

    #[test]
    fn a_word_with_a_space_is_added_as_a_phrase() {
        // E' la scelta che l'operatore farebbe comunque: chiedergliela per ogni
        // parola aggiungerebbe un passo a un'operazione che deve restare rapida.
        let wizard = create();
        {
            let mut composition = wizard.borrow_mut();
            let Ok(()) = composition.add_custom_term(
                "appiccare il fuoco",
                MatchMode::Phrase,
                SuggestedLevel::weakest_that_alerts(),
            ) else {
                panic!("la frase deve potersi aggiungere");
            };
            let Ok(()) = composition.add_custom_term(
                "incendio",
                MatchMode::NormalizedWord,
                SuggestedLevel::weakest_that_alerts(),
            ) else {
                panic!("la parola deve potersi aggiungere");
            };
        }

        let composition = wizard.borrow();
        assert_eq!(composition.custom_terms()[0].match_mode, MatchMode::Phrase);
        assert_eq!(
            composition.custom_terms()[1].match_mode,
            MatchMode::NormalizedWord
        );
    }

    /// Interfaccia principale, letta a tempo di compilazione.
    const UI: &str = include_str!("../ui/app-window.slint");

    #[test]
    fn every_gravity_the_wizard_offers_has_its_own_label() {
        for (position, expected) in LEVEL_LABELS.iter().enumerate() {
            let Ok(number) = i8::try_from(position + 1) else {
                panic!("il livello deve stare in un i8");
            };
            let Ok(level) = SuggestedLevel::try_new(number) else {
                panic!("il livello {number} deve essere ammesso");
            };
            assert_eq!(
                &term_level_label(level),
                expected,
                "la voce {number} deve rileggersi come e' stata scelta"
            );
        }
    }

    #[test]
    fn a_level_outside_the_offered_range_is_shown_rather_than_hidden() {
        // Non puo' nascere da questa schermata. Se arrivasse da altrove, un
        // valore mostrato e' un difetto che si vede; uno normalizzato in
        // silenzio e' un difetto che resta.
        let Ok(mitigating) = SuggestedLevel::try_new(-2) else {
            panic!("il livello -2 deve essere ammesso dal dominio");
        };
        assert_eq!(term_level_label(mitigating), "livello -2");
    }

    /// **I pulsanti della durata sono le sette durate decise**, con le
    /// etichette e i secondi di `WizardDuration::PRESETS` (ADR-0150).
    #[test]
    fn i_pulsanti_della_durata_ripetono_le_durate_decise() {
        for (secondi, etichetta) in WizardDuration::PRESETS {
            let pulsante = format!(
                "label: @tr(\"{etichetta}\");\n                                                    selected: root.wizard-duration-label == self.label;\n                                                    clicked => {{ root.wizard-set-duration({secondi}, false); }}"
            );
            assert!(
                UI.contains(&pulsante),
                "manca il pulsante «{etichetta}» con {secondi} secondi"
            );
        }
        assert!(UI.contains(
            "root.wizard-set-custom-duration(root.wizard-custom-hours, root.wizard-custom-minutes);"
        ));
    }

    /// **I campi della durata personalizzata non producono durate fuori dai
    /// limiti**, nemmeno con un numero negativo (ADR-0150).
    #[test]
    fn i_campi_della_durata_personalizzata_si_controllano() {
        assert_eq!(
            super::custom_duration(2, 15),
            Some(WizardDuration::Custom(8_100))
        );
        assert_eq!(super::custom_duration(-1, 30), None);
        assert_eq!(super::custom_duration(1, -5), None);
        assert_eq!(super::custom_duration(0, 0), None);
        assert_eq!(super::custom_duration(169, 0), None);
    }

    #[test]
    fn the_labels_match_the_ones_the_operator_chose_from() {
        // Le stesse parole vivono in due file: qui e nel modello del ComboBox.
        // Sceglierne una e rileggerla scritta in un altro modo darebbe ragione
        // di dubitare di averla scelta.
        for label in LEVEL_LABELS {
            assert!(
                UI.contains(label),
                "l'elenco a discesa non offre piu' la voce «{label}»"
            );
        }
    }

    #[test]
    fn the_declared_gravity_is_shown_back_on_the_row_and_in_the_summary() {
        // Fino al 2026-08-04 la gravita' si sceglieva e non si rivedeva piu':
        // ne' sulla riga, ne' nel riepilogo, che contava le parole senza dirne
        // il peso. Il riepilogo e' l'ultima occasione di accorgersi di un clic
        // sbagliato prima di avviare un monitoraggio che poi gira per ore.
        assert!(
            UI.matches("entry.level").count() >= 2,
            "la gravita' deve comparire sia sulla riga sia nel riepilogo"
        );
    }

    #[test]
    fn the_chosen_duration_is_reflected_in_the_view() {
        let wizard = create();
        wizard.borrow_mut().set_duration(WizardDuration::Manual);

        let view = wizard.borrow().view();
        assert_eq!(view.duration, WizardDuration::Manual);
        assert!(view.duration.label().contains("manuale"));
    }

    /// L'elenco a discesa mostra i livelli 1-4, quindi la voce all'indice `i`
    /// vale `i + 1`.
    #[test]
    fn the_level_chosen_in_the_list_matches_the_entry_shown() {
        for (index, expected) in [(0, 1), (1, 2), (2, 3), (3, 4)] {
            assert_eq!(
                term_level_from_index(index).get(),
                expected,
                "la voce all'indice {index} deve valere il livello {expected}"
            );
        }
    }

    /// Nessun indice, nemmeno assurdo, deve poter produrre un livello che non
    /// genera avvisi. Zero è «nessun avviso»: una parola che l'operatore ha
    /// chiesto di sorvegliare non deve mai finire in uno stato che non può
    /// segnalare nulla — è il difetto rilevato in campo il 2026-07-31, e
    /// questo test esiste perché non rientri da un'altra porta.
    #[test]
    fn no_index_can_produce_a_level_that_never_alerts() {
        for index in [-1, -128, i32::MIN, 4, 99, i32::MAX] {
            let level = term_level_from_index(index);
            assert!(
                level.get() >= SuggestedLevel::weakest_that_alerts().get(),
                "l'indice {index} ha prodotto un livello che non genera avvisi: {}",
                level.get()
            );
        }
    }

    /// Costruisce termini di prova con testi riconoscibili.
    fn sample_terms(count: usize) -> Vec<lisi_core::model::dictionary::DictionaryTerm> {
        (0..count)
            .map(|index| {
                let Ok(text) = lisi_core::text::TermText::try_new(&format!("parola{index}")) else {
                    panic!("il termine di prova deve essere valido");
                };
                let (Ok(category), Ok(language), Ok(level), Ok(note)) = (
                    lisi_core::text::TermCategory::try_new("prova"),
                    lisi_core::text::LanguageTag::try_new("it"),
                    SuggestedLevel::try_new(1),
                    lisi_core::text::TermNote::try_new(""),
                ) else {
                    panic!("i valori di prova devono essere validi");
                };
                lisi_core::model::dictionary::DictionaryTerm {
                    id: lisi_core::DictionaryTermId::new(
                        i64::try_from(index + 1).unwrap_or(i64::MAX),
                    ),
                    version_id: lisi_core::DictionaryVersionId::new(1),
                    text,
                    category,
                    language,
                    match_mode: MatchMode::NormalizedWord,
                    suggested_level: level,
                    note,
                }
            })
            .collect()
    }

    /// Chi sceglie un dizionario deve vederne **le parole**, non solo quante
    /// sono. Fino al 2026-07-31 la riga del wizard mostrava nome, ambito e un
    /// conteggio: un numero dice quanto è grande una cosa, non che cosa sia, e
    /// l'operatore sceglieva alla cieca (rilevato dall'operatore stesso).
    #[test]
    fn the_sample_shows_real_words_and_says_when_it_is_incomplete() {
        // Meno parole del tetto: si mostrano tutte, e nulla è troncato.
        let (few, truncated) = term_sample(&sample_terms(3));
        assert!(few.contains("parola0"), "le parole vere devono comparire");
        assert!(few.contains("parola2"));
        assert!(
            !truncated,
            "con meno parole del tetto non c'e' nulla da troncare"
        );

        // Più parole del tetto: se ne mostrano `SAMPLE_TERMS`, e lo si dice.
        let (many, truncated) = term_sample(&sample_terms(SAMPLE_TERMS + 5));
        assert_eq!(
            many.split(", ").count(),
            SAMPLE_TERMS,
            "l'assaggio non deve superare il tetto: {many}"
        );
        assert!(
            truncated,
            "se qualcosa e' stato omesso l'interfaccia deve poterlo dire, \
             altrimenti l'operatore crede di vedere tutto"
        );

        // Nessuna parola: l'assaggio è vuoto e non finge di esserci.
        let (none, truncated) = term_sample(&sample_terms(0));
        assert!(none.is_empty());
        assert!(!truncated);
    }

    /// **Il riepilogo conta la SCELTA, non la libreria.**
    ///
    /// # Il difetto che questa guardia impedisce
    ///
    /// Fino al 2026-08-25 il riepilogo scriveva:
    ///
    /// ```text
    /// Fonti: 3 configurate · dizionari scelti: 7 disponibili · ...
    /// ```
    ///
    /// I due numeri venivano dalla **lunghezza degli elenchi mostrati** —
    /// `wizard-sources` e `wizard-dictionaries`, che sono le fonti e i
    /// dizionari *disponibili* — e non dai conteggi della macchina a stati. Chi
    /// aveva spuntato un dizionario su sette leggeva «dizionari scelti: 7», e
    /// la frase stessa si contraddiceva: «scelti: 7 disponibili».
    ///
    /// Il riepilogo è l'ultimo momento per accorgersi di un clic sbagliato
    /// prima di avviare un monitoraggio che gira per ore. Un numero che non
    /// corrisponde a nessun gesto dell'operatore rende quel momento inutile.
    ///
    /// Nessuna prova poteva coglierlo: il prodotto funzionava, e i due numeri
    /// erano entrambi veri — solo, rispondevano a un'altra domanda. L'ha visto
    /// la cattura delle schermate (UX-02).
    #[test]
    fn il_riepilogo_non_conta_gli_elenchi_disponibili() {
        // Il blocco del riepilogo, dal marcatore del passo 5 a quello del 6.
        let Some(inizio) = UI.find("if root.wizard-step == 5:") else {
            panic!("il passo 5 del wizard deve esistere");
        };
        let Some(fine) = UI[inizio..].find("if root.wizard-step == 6:") else {
            panic!("il passo 6 del wizard deve esistere");
        };
        let riepilogo = &UI[inizio..inizio + fine];

        for vietato in ["wizard-sources.length", "wizard-dictionaries.length"] {
            assert!(
                !riepilogo.contains(vietato),
                "il riepilogo usa «{vietato}», che conta gli elenchi DISPONIBILI \
                 e non la scelta dell'operatore"
            );
        }

        assert!(
            riepilogo.contains("wizard-chosen-sources")
                && riepilogo.contains("wizard-chosen-dictionary-count"),
            "il riepilogo deve contare la scelta, che viene dalla macchina a stati"
        );
    }

    /// **Le versioni dei dizionari compaiono nel riepilogo.**
    ///
    /// È la metà che mancava al criterio 39 di M3C. Un nome senza numero dice
    /// quale dizionario, non quale contenuto.
    #[test]
    fn il_riepilogo_mostra_i_dizionari_con_la_loro_versione() {
        let Some(inizio) = UI.find("if root.wizard-step == 5:") else {
            panic!("il passo 5 del wizard deve esistere");
        };
        let Some(fine) = UI[inizio..].find("if root.wizard-step == 6:") else {
            panic!("il passo 6 del wizard deve esistere");
        };
        let riepilogo = &UI[inizio..inizio + fine];

        assert!(
            riepilogo.contains("wizard-chosen-dictionaries"),
            "il riepilogo deve elencare i dizionari scelti con la versione"
        );
        assert!(
            riepilogo.contains("entry.label"),
            "e deve disegnarne l'etichetta, che porta il numero di versione"
        );
    }

    /// **Gli avvisi stanno nel riepilogo, il motivo di blocco accanto ad
    /// «Avanti»: sono due posti diversi perché sono due cose diverse.**
    ///
    /// Se un avviso comparisse dove compare il blocco, un operatore
    /// imparerebbe che quel posto a volte ferma e a volte no — e smetterebbe di
    /// leggerlo. È la stessa ragione per cui il prodotto non chiama «errore»
    /// una condizione che non impedisce nulla.
    #[test]
    fn gli_avvisi_e_il_motivo_di_blocco_non_stanno_nello_stesso_posto() {
        let Some(inizio) = UI.find("if root.wizard-step == 5:") else {
            panic!("il passo 5 del wizard deve esistere");
        };
        let Some(fine) = UI[inizio..].find("if root.wizard-step == 6:") else {
            panic!("il passo 6 del wizard deve esistere");
        };
        let riepilogo = &UI[inizio..inizio + fine];

        assert!(
            riepilogo.contains("wizard-notices"),
            "gli avvisi appartengono al riepilogo"
        );
        assert!(
            !riepilogo.contains("wizard-blocking-reason"),
            "il motivo di blocco NON si ripete dentro il riepilogo: vive accanto \
             al pulsante che spegne"
        );
    }
}

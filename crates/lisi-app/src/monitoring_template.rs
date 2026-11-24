//! La schermata dei modelli di monitoraggio (TEMPLATE-01).
//!
//! # Un modello propone, non applica
//!
//! Il comando si chiama **«Mostra che cosa prepara»**, e non «Applica», perché
//! è quello che fa: mostra le fonti che il modello prepara e dichiara in che
//! cosa le impostazioni della postazione differiscono.
//!
//! La soglia di notifica e la conservazione **non si toccano da qui**. Sono
//! della postazione: cambiarle vale anche per i monitoraggi già conclusi, e la
//! conservazione, abbassata, **cancella**. Un gesto che sembra «preparare un
//! monitoraggio» non può fare questo.
//!
//! Il modo di garantirlo non è l'etichetta del pulsante: il servizio sotto
//! **non ha alcun modo** di scrivere quelle impostazioni, e la funzione che
//! applica non prende nemmeno l'archivio mutabile.
//!
//! # Una fonte che non c'è più si vede
//!
//! Un modello nomina le fonti per identità. Se una viene cancellata, la riga
//! **non si filtra via**: nasconderla direbbe che il modello non l'aveva mai
//! nominata, e chi lo usa crederebbe di guardare ciò che guardava.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use lisi_core::model::monitoring_template::{Prescribed, PrescribedRetention};
use lisi_core::text::{DisplayName, Note};
use lisi_core::{DictionaryId, MonitoringTemplateId, SourceId, Timestamp};
use lisi_services::monitoring_template::{MonitoringTemplateService, TemplateProposal};
use lisi_services::wizard::MonitoringWizard;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::dictionaries::SharedDictionaries;
use crate::sources::SharedSources;
use crate::wizard::SharedWizard;
use crate::{AppWindow, TemplateChoice, TemplateRow, TemplateSourceRow};

/// Servizio dei modelli, condiviso fra i gestori dei comandi.
pub type SharedTemplates = Rc<RefCell<MonitoringTemplateService>>;

/// Ciò che la schermata dei modelli tocca oltre ai modelli (F-07): le fonti e
/// i dizionari fra cui scegliere, e la procedura guidata da compilare.
///
/// Ogni pezzo può mancare, se il suo archivio non si è aperto: la schermata lo
/// dice invece di non aprirsi.
#[derive(Clone, Default)]
pub struct TemplateContext {
    /// Le fonti configurate.
    pub sources: Option<SharedSources>,
    /// La libreria dei dizionari.
    pub dictionaries: Option<SharedDictionaries>,
    /// La procedura guidata del nuovo monitoraggio.
    pub wizard: Option<SharedWizard>,
}

/// Le scelte del modulo, finché non si salva.
#[derive(Default)]
struct FormState {
    sources: BTreeSet<i64>,
    dictionaries: BTreeSet<i64>,
}

type SharedForm = Rc<RefCell<FormState>>;

/// Le voci della tendina della conservazione, nell'ordine dell'interfaccia.
const RETENTION_CHOICES: [PrescribedRetention; 6] = [
    PrescribedRetention::Silent,
    PrescribedRetention::KeepEverything,
    PrescribedRetention::KeepDays(30),
    PrescribedRetention::KeepDays(90),
    PrescribedRetention::KeepDays(180),
    PrescribedRetention::KeepDays(365),
];

/// La soglia scelta nella tendina: la prima voce è «il modello non si esprime».
fn threshold_from_index(index: i32) -> Prescribed<u8> {
    match u8::try_from(index) {
        Ok(livello @ 1..=4) => Prescribed::Value(livello),
        _ => Prescribed::Silent,
    }
}

/// La voce della tendina di una soglia.
fn index_of_threshold(soglia: Prescribed<u8>) -> i32 {
    match soglia {
        Prescribed::Value(livello @ 1..=4) => i32::from(livello),
        _ => 0,
    }
}

/// La conservazione scelta nella tendina.
fn retention_from_index(index: i32) -> PrescribedRetention {
    usize::try_from(index)
        .ok()
        .and_then(|i| RETENTION_CHOICES.get(i).copied())
        .unwrap_or(PrescribedRetention::Silent)
}

/// La voce della tendina di una conservazione, se è fra quelle offerte.
fn index_of_retention(conservazione: PrescribedRetention) -> Option<i32> {
    RETENTION_CHOICES
        .iter()
        .position(|voce| *voce == conservazione)
        .and_then(|i| i32::try_from(i).ok())
}

/// Riporta nel modulo le fonti e i dizionari fra cui scegliere, con le spunte.
fn render_form_choices(window: &AppWindow, context: &TemplateContext, form: &SharedForm) {
    let scelte = form.borrow();
    let fonti: Vec<TemplateChoice> = context
        .sources
        .as_ref()
        .and_then(|s| s.borrow().configured().ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|fonte| fonte.active)
        .map(|fonte| TemplateChoice {
            id: i32::try_from(fonte.id.get()).unwrap_or(0),
            label: SharedString::from(fonte.display_name.as_str()),
            detail: crate::lingua::schermo(fonte.kind.label()),
            chosen: scelte.sources.contains(&fonte.id.get()),
        })
        .collect();
    let dizionari: Vec<TemplateChoice> = context
        .dictionaries
        .as_ref()
        .and_then(|d| d.borrow().usable().ok())
        .unwrap_or_default()
        .into_iter()
        .map(|dizionario| TemplateChoice {
            id: i32::try_from(dizionario.id.get()).unwrap_or(0),
            label: SharedString::from(dizionario.name.as_str()),
            detail: crate::lingua::schermo(dizionario.scope.label()),
            chosen: scelte.dictionaries.contains(&dizionario.id.get()),
        })
        .collect();
    window.set_template_form_sources(ModelRc::from(Rc::new(VecModel::from(fonti))));
    window.set_template_form_dictionaries(ModelRc::from(Rc::new(VecModel::from(dizionari))));
}

/// Apre il modulo vuoto.
fn form_new(window: &AppWindow, context: &TemplateContext, form: &SharedForm) {
    *form.borrow_mut() = FormState::default();
    window.set_template_form_name(SharedString::default());
    window.set_template_form_description(SharedString::default());
    window.set_template_form_threshold_index(0);
    window.set_template_form_retention_index(0);
    window.set_template_form_message(SharedString::default());
    window.set_template_message(SharedString::default());
    close_preparation(window);
    render_form_choices(window, context, form);
    window.set_template_form_open(true);
}

/// Apre il modulo con le scelte di un modello che c'è già (ADR-0142): un
/// modello non si modifica, e da questo ne nasce un altro.
fn form_from(
    window: &AppWindow,
    templates: &SharedTemplates,
    context: &TemplateContext,
    form: &SharedForm,
    id: i32,
) {
    let esito = templates
        .borrow()
        .apply(MonitoringTemplateId::new(i64::from(id)));
    let preparazione = match esito {
        Ok(preparazione) => preparazione,
        Err(errore) => {
            window.set_template_message(crate::lingua::schermo(errore.operator_message()));
            return;
        }
    };
    form_new(window, context, form);
    {
        let mut scelte = form.borrow_mut();
        scelte.sources = preparazione
            .usable_sources()
            .iter()
            .map(|s| s.get())
            .collect();
        scelte.dictionaries = preparazione
            .usable_dictionaries()
            .iter()
            .map(|d| d.get())
            .collect();
    }
    let modello = &preparazione.template;
    window.set_template_form_name(crate::lingua::schermo(format!(
        "{} (nuovo)",
        modello.name.as_str()
    )));
    window.set_template_form_description(SharedString::from(
        modello.description.as_ref().map_or("", Note::as_str),
    ));
    window.set_template_form_threshold_index(index_of_threshold(modello.notification_level));
    let mut avvisi = Vec::new();
    match index_of_retention(modello.retention) {
        Some(indice) => window.set_template_form_retention_index(indice),
        None => avvisi.push(String::from(
            "La conservazione prevista dal modello di partenza non è fra quelle offerte qui: \
             sceglierla di nuovo.",
        )),
    }
    let mancanti = preparazione.missing_sources() + preparazione.unusable_dictionaries();
    if mancanti > 0 {
        avvisi.push(format!(
            "{mancanti} fra fonti e dizionari del modello di partenza non si possono più \
             scegliere, e non sono spuntati."
        ));
    }
    window.set_template_form_message(SharedString::from(avvisi.join(" ")));
    render_form_choices(window, context, form);
}

/// Salva il modello del modulo.
fn form_save(
    window: &AppWindow,
    templates: &SharedTemplates,
    context: &TemplateContext,
    form: &SharedForm,
) {
    let nome = window.get_template_form_name().trim().to_owned();
    let Ok(name) = DisplayName::try_new(&nome) else {
        window.set_template_form_message(crate::lingua::schermo(
            "Un modello ha bisogno di un nome: è il modo in cui lo si ritrova nell'elenco.",
        ));
        return;
    };
    let testo = window.get_template_form_description().trim().to_owned();
    let description = if testo.is_empty() {
        None
    } else {
        match Note::try_new(&testo) {
            Ok(nota) => Some(nota),
            Err(_) => {
                window.set_template_form_message(crate::lingua::schermo(
                    "La descrizione è troppo lunga: bastano poche righe.",
                ));
                return;
            }
        }
    };
    let (sources, dictionaries): (Vec<SourceId>, Vec<DictionaryId>) = {
        let scelte = form.borrow();
        (
            scelte.sources.iter().map(|id| SourceId::new(*id)).collect(),
            scelte
                .dictionaries
                .iter()
                .map(|id| DictionaryId::new(*id))
                .collect(),
        )
    };
    if sources.is_empty() {
        window.set_template_form_message(crate::lingua::schermo(
            "Spuntare almeno una fonte: un modello senza fonti non preparerebbe nulla.",
        ));
        return;
    }
    let Ok(created_by) = crate::operator::audit_actor() else {
        window.set_template_form_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };
    let proposta = TemplateProposal {
        name,
        description,
        sources,
        dictionaries,
        notification_level: threshold_from_index(window.get_template_form_threshold_index()),
        retention: retention_from_index(window.get_template_form_retention_index()),
        created_by,
    };
    let esito = templates.borrow_mut().create_from(&proposta, now());
    match esito {
        Ok(_) => {
            window.set_template_form_open(false);
            *form.borrow_mut() = FormState::default();
            refresh(window, templates);
            window.set_template_message(crate::lingua::schermo(format!(
                "Modello «{nome}» salvato: è nell'elenco qui sotto. «Mostra che cosa prepara» \
                 dice che cosa preparerebbe, e da lì si prepara un nuovo monitoraggio."
            )));
        }
        Err(errore) => {
            window.set_template_form_message(crate::lingua::schermo(errore.operator_message()));
            render_form_choices(window, context, form);
        }
    }
}

/// Compila la procedura guidata con le scelte del modello e la apre al primo
/// passo (ADR-0142).
///
/// # Che cosa questa funzione NON fa
///
/// Non avvia il monitoraggio e non cambia le impostazioni della postazione:
/// spunta fonti e dizionari nella procedura, che chi prepara rivede passo per
/// passo e avvia, se vuole, con «Avvia monitoraggio» all'ultimo.
fn prepare_monitoring(
    window: &AppWindow,
    templates: &SharedTemplates,
    context: &TemplateContext,
    id: i32,
) {
    let (Some(wizard), Some(dictionaries)) =
        (context.wizard.as_ref(), context.dictionaries.as_ref())
    else {
        window.set_template_message(crate::lingua::schermo(
            "La procedura del nuovo monitoraggio non è disponibile in questa esecuzione.",
        ));
        return;
    };
    let esito = templates
        .borrow()
        .apply(MonitoringTemplateId::new(i64::from(id)));
    let preparazione = match esito {
        Ok(preparazione) => preparazione,
        Err(errore) => {
            window.set_template_message(crate::lingua::schermo(errore.operator_message()));
            return;
        }
    };

    // Solo ciò che la procedura può davvero offrire: fonti attive, dizionari
    // utilizzabili adesso. Il resto si conta e si dice.
    let attive: BTreeSet<i64> = context
        .sources
        .as_ref()
        .and_then(|s| s.borrow().configured().ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|fonte| fonte.active)
        .map(|fonte| fonte.id.get())
        .collect();
    let fonti: Vec<SourceId> = preparazione
        .usable_sources()
        .into_iter()
        .filter(|fonte| attive.contains(&fonte.get()))
        .collect();
    let dizionari = preparazione.usable_dictionaries();
    let fonti_fuori = preparazione.sources.len().saturating_sub(fonti.len());
    let dizionari_fuori = preparazione
        .dictionaries
        .len()
        .saturating_sub(dizionari.len());

    {
        let mut composizione = wizard.borrow_mut();
        *composizione = MonitoringWizard::new();
        for fonte in &fonti {
            composizione.toggle_source(*fonte);
        }
        for dizionario in &dizionari {
            composizione.toggle_dictionary(*dizionario);
        }
    }

    let mut nota = format!(
        "Scelte prese dal modello «{}»: {} {} e {} {}.",
        preparazione.template.name.as_str(),
        fonti.len(),
        if fonti.len() == 1 { "fonte" } else { "fonti" },
        dizionari.len(),
        if dizionari.len() == 1 {
            "dizionario"
        } else {
            "dizionari"
        }
    );
    if fonti_fuori + dizionari_fuori > 0 {
        nota.push_str(&format!(
            " {} del modello non {} più disponibili e sono rimasti fuori.",
            fonti_fuori + dizionari_fuori,
            if fonti_fuori + dizionari_fuori == 1 {
                "è"
            } else {
                "sono"
            }
        ));
    }
    nota.push_str(
        " Ogni scelta si rivede e si cambia passo per passo; il monitoraggio parte solo \
         con «Avvia monitoraggio», all'ultimo passo.",
    );
    window.set_wizard_template_note(SharedString::from(nota));
    crate::wizard::refresh(
        window,
        wizard,
        dictionaries,
        context.sources.as_ref(),
        Some(""),
    );
    close_preparation(window);
    window.invoke_open_page(6);
}

/// Costruisce il servizio sull'archivio indicato.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedTemplates> {
    Some(Rc::new(RefCell::new(MonitoringTemplateService::new(
        database,
    ))))
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Rilegge l'elenco dei modelli.
pub fn refresh(window: &AppWindow, templates: &SharedTemplates) {
    let Ok(elenco) = templates.borrow().all() else {
        window.set_template_message(crate::lingua::schermo(
            "I modelli non sono leggibili in questo momento: quello qui sotto non dice che non ce \
             ne siano.",
        ));
        window.set_template_rows(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
        return;
    };

    let righe: Vec<TemplateRow> = elenco
        .iter()
        .map(|modello| TemplateRow {
            id: i32::try_from(modello.id.get()).unwrap_or(i32::MAX),
            name: SharedString::from(modello.name.as_str()),
            // LA FRASE LA COMPONE IL MODELLO (DEC-252).
            sentence: crate::lingua::schermo(modello.as_sentence()),
            description: SharedString::from(modello.description.as_ref().map_or("", Note::as_str)),
        })
        .collect();
    window.set_template_rows(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Mostra che cosa un modello prepara.
///
/// # Che cosa questa funzione non fa
///
/// Non prepara la sessione e **non cambia le impostazioni**. Legge, confronta e
/// mostra: chi guarda decide.
fn show_preparation(window: &AppWindow, templates: &SharedTemplates, id: i32) {
    if id <= 0 {
        return;
    }

    let esito = templates
        .borrow()
        .apply(MonitoringTemplateId::new(i64::from(id)));

    let preparazione = match esito {
        Ok(preparazione) => preparazione,
        Err(errore) => {
            window.set_template_message(crate::lingua::schermo(errore.operator_message()));
            return;
        }
    };

    // OGNI FONTE COMPARE, COMPRESA QUELLA CHE NON C'E' PIU'.
    let fonti: Vec<TemplateSourceRow> = preparazione
        .sources
        .iter()
        .map(|fonte| TemplateSourceRow {
            sentence: crate::lingua::schermo(fonte.as_sentence()),
            present: fonte.is_present(),
        })
        .collect();
    window.set_template_preparation_sources(ModelRc::from(Rc::new(VecModel::from(fonti))));
    // E OGNI DIZIONARIO, con la versione che oggi si userebbe (F-07).
    let dizionari: Vec<TemplateSourceRow> = preparazione
        .dictionaries
        .iter()
        .map(|dizionario| TemplateSourceRow {
            sentence: crate::lingua::schermo(dizionario.as_sentence()),
            present: dizionario.is_usable(),
        })
        .collect();
    window.set_template_preparation_dictionaries(ModelRc::from(Rc::new(VecModel::from(dizionari))));
    window.set_template_preparation_id(id);
    window.set_template_form_open(false);

    // LE DUE FRASI LE COMPONE IL DOMINIO, e dicono i valori.
    window.set_template_notification_sentence(crate::lingua::schermo(
        preparazione.notification.as_sentence("Soglia di notifica"),
    ));
    window.set_template_retention_sentence(crate::lingua::schermo(
        preparazione.retention.as_sentence("Conservazione"),
    ));
    window.set_template_would_delete(preparazione.would_delete());

    window.set_template_preparation_name(SharedString::from(preparazione.template.name.as_str()));
    window.set_template_preparation_open(true);

    // LA FRASE DICE CHE COSA E' APPENA SUCCESSO, cioe' niente.
    //
    // Chi preme un comando si aspetta che qualcosa sia cambiato. Qui non lo e',
    // ed e' deliberato: dirlo evita che qualcuno chiuda la schermata credendo
    // di aver configurato la postazione.
    let mancanti = preparazione.missing_sources();
    let coda = if mancanti == 0 {
        String::new()
    } else {
        format!(
            " {mancanti} delle fonti che il modello nominava non sono pi\u{f9} nell'archivio, e \
             restano elencate qui sotto."
        )
    };
    window.set_template_message(crate::lingua::schermo(format!(
        "Nulla \u{e8} stato cambiato. Qui sotto c'\u{e8} che cosa questo modello prepara, e in \
         che cosa differisce da come \u{e8} configurata adesso la postazione.{coda}"
    )));
}

/// Cancella un modello.
fn delete(window: &AppWindow, templates: &SharedTemplates, id: i32) {
    if id <= 0 {
        return;
    }
    let Ok(attore) = crate::operator::audit_actor() else {
        window.set_template_message(crate::lingua::schermo(
            "Non si riesce a stabilire chi stia agendo su questa postazione.",
        ));
        return;
    };

    match templates
        .borrow()
        .delete(MonitoringTemplateId::new(i64::from(id)), &attore, now())
    {
        Ok(()) => {
            close_preparation(window);
            window.set_template_message(crate::lingua::schermo(
                "Modello cancellato. I monitoraggi che aveva preparato restano come sono. Le \
                 loro fonti e i loro dizionari stanno sul monitoraggio, e non se ne vanno con \
                 il modello.",
            ));
        }
        Err(errore) => {
            window.set_template_message(crate::lingua::schermo(errore.operator_message()));
        }
    }

    refresh(window, templates);
}

/// Chiude la preparazione mostrata.
fn close_preparation(window: &AppWindow) {
    window.set_template_preparation_open(false);
    window.set_template_preparation_name(SharedString::default());
    window.set_template_preparation_sources(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
    window
        .set_template_preparation_dictionaries(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
    window.set_template_preparation_id(0);
    window.set_template_notification_sentence(SharedString::default());
    window.set_template_retention_sentence(SharedString::default());
    window.set_template_would_delete(false);
}

/// Collega i comandi.
pub fn wire(window: &AppWindow, templates: &SharedTemplates, context: &TemplateContext) {
    let form: SharedForm = Rc::new(RefCell::new(FormState::default()));

    {
        let handle = window.as_weak();
        let context = context.clone();
        let form = Rc::clone(&form);
        window.on_template_form_new(move || {
            if crate::lock::refuse_while_locked("template_form_new") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                form_new(&window, &context, &form);
            }
        });
    }
    {
        let handle = window.as_weak();
        let templates = Rc::clone(templates);
        let context = context.clone();
        let form = Rc::clone(&form);
        window.on_template_form_from(move |id| {
            if crate::lock::refuse_while_locked("template_form_from") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                form_from(&window, &templates, &context, &form, id);
            }
        });
    }
    {
        let handle = window.as_weak();
        let context = context.clone();
        let form = Rc::clone(&form);
        window.on_template_form_toggle_source(move |id| {
            if crate::lock::refuse_while_locked("template_form_toggle_source") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut scelte = form.borrow_mut();
                let id = i64::from(id);
                if !scelte.sources.remove(&id) {
                    scelte.sources.insert(id);
                }
            }
            render_form_choices(&window, &context, &form);
        });
    }
    {
        let handle = window.as_weak();
        let context = context.clone();
        let form = Rc::clone(&form);
        window.on_template_form_toggle_dictionary(move |id| {
            if crate::lock::refuse_while_locked("template_form_toggle_dictionary") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            {
                let mut scelte = form.borrow_mut();
                let id = i64::from(id);
                if !scelte.dictionaries.remove(&id) {
                    scelte.dictionaries.insert(id);
                }
            }
            render_form_choices(&window, &context, &form);
        });
    }
    {
        let handle = window.as_weak();
        let templates = Rc::clone(templates);
        let context = context.clone();
        let form = Rc::clone(&form);
        window.on_template_form_save(move || {
            if crate::lock::refuse_while_locked("template_form_save") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                form_save(&window, &templates, &context, &form);
            }
        });
    }
    {
        let handle = window.as_weak();
        let form = Rc::clone(&form);
        window.on_template_form_cancel(move || {
            if crate::lock::refuse_while_locked("template_form_cancel") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                *form.borrow_mut() = FormState::default();
                window.set_template_form_open(false);
                window.set_template_form_message(SharedString::default());
            }
        });
    }
    {
        let handle = window.as_weak();
        let templates = Rc::clone(templates);
        let context = context.clone();
        window.on_template_prepare_monitoring(move |id| {
            if crate::lock::refuse_while_locked("template_prepare_monitoring") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                prepare_monitoring(&window, &templates, &context, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let templates = Rc::clone(templates);
        window.on_templates_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &templates);
            }
        });
    }

    {
        let handle = window.as_weak();
        let templates = Rc::clone(templates);
        window.on_apply_template(move |id| {
            if crate::lock::refuse_while_locked("apply_template") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                show_preparation(&window, &templates, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        let templates = Rc::clone(templates);
        window.on_delete_template(move |id| {
            if crate::lock::refuse_while_locked("delete_template") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                delete(&window, &templates, id);
            }
        });
    }

    {
        let handle = window.as_weak();
        window.on_close_template_preparation(move || {
            if crate::lock::refuse_while_locked("close_template_preparation") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                close_preparation(&window);
                window.set_template_message(SharedString::default());
            }
        });
    }
}

/// Quante righe l'elenco mostra: serve alle prove.
#[cfg(test)]
fn conta_modelli(window: &AppWindow) -> usize {
    use slint::Model as _;
    window.get_template_rows().iter().count()
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use slint::{Model as _, SharedString};

    use super::conta_modelli;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("monitoring_template.rs");

    /// Il file dell'interfaccia.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco della pagina 24, e nient'altro.
    ///
    /// # Perché finisce alla pagina successiva
    ///
    /// Perché un confine scritto a mano — un numero, un commento — smette di
    /// valere il giorno in cui qualcuno inserisce una pagina in mezzo, e la
    /// guardia si mette a leggere due schermate senza dirlo. È successo con
    /// SEARCH-01, e la correzione è questa forma.
    fn pagina_dei_modelli() -> String {
        // L'ESTRATTORE E' UNO SOLO, E DIMOSTRA DI AVER LETTO QUALCOSA.
        //
        // Prima di HARDEN-02 ogni modulo ritagliava il corpo della propria
        // pagina per conto proprio, e un ritaglio che coglieva troppo poco
        // non faceva fallire niente: ogni divieto restava vero perche' non
        // c'era niente da vietare (ADR-0111).
        crate::page_guard::corpo_della_pagina(24)
    }

    /// **La schermata non ha modo di cambiare le impostazioni della
    /// postazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il solo che questa milestone esisteva per impedire. La soglia di
    /// notifica e la conservazione valgono per l'intera postazione, comprese le
    /// sessioni già concluse, e la conservazione **cancella**: un gesto che
    /// sembra «preparare un monitoraggio» non può cambiarle.
    #[test]
    fn la_schermata_non_ha_modo_di_cambiare_le_impostazioni() {
        let codice = codice_senza_commenti();
        for scrittura in [
            "save_retention",
            "save_notification",
            "set_retention_policy",
            "RetentionPolicy",
            "NotificationSettings",
        ] {
            assert!(
                !codice.contains(scrittura),
                "il modulo nomina «{scrittura}»: applicare un modello riconfigurerebbe la \
                 postazione con un gesto che sembra preparare un monitoraggio"
            );
        }
    }

    /// **Il comando dice che cosa fa, e non fa credere di più.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un pulsante «Applica». Chi lo preme crede di aver configurato la
    /// postazione, e non se ne accorge finché la conservazione non fa
    /// quello che il modello prevedeva — cioè mai, perché non l'ha cambiata.
    #[test]
    fn il_comando_dice_che_cosa_fa() {
        let pagina = pagina_dei_modelli();
        assert!(
            crate::surface_text::assegna(&pagina, "label", "Mostra che cosa prepara"),
            "il comando dice che cosa fa"
        );
        assert!(
            !crate::surface_text::assegna(&pagina, "label", "Applica")
                && !crate::surface_text::assegna(&pagina, "label", "Applica il modello"),
            "«Applica» farebbe credere che la postazione sia stata configurata"
        );
    }

    /// **La schermata dice che nulla è stato cambiato.**
    ///
    /// # Perché conta
    ///
    /// Perché chi preme un comando si aspetta che qualcosa sia cambiato. Qui
    /// non lo è, ed è deliberato: dirlo evita che qualcuno chiuda la schermata
    /// credendo di aver configurato la postazione.
    #[test]
    fn la_schermata_dice_che_nulla_e_cambiato() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("Nulla \\u{e8} stato cambiato"),
            "la frase deve dirlo per prima cosa"
        );

        let pagina = pagina_dei_modelli();
        assert!(
            pagina.contains("Non cambia la soglia di notifica né la conservazione"),
            "e la schermata deve spiegarlo prima che qualcuno prema il comando"
        );
    }

    /// **Una fonte che non c'è più resta visibile.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un modello che, applicato, prepara silenziosamente meno fonti di quelle
    /// che nominava. Chi lo usa crede di guardare ciò che guardava.
    #[test]
    fn una_fonte_che_non_c_e_piu_resta_visibile() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("fn show_preparation(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find("\n}\n") else {
            panic!("la funzione deve chiudersi");
        };
        let corpo = &codice[inizio..inizio + fine];
        assert!(
            !corpo.contains(".filter(|fonte| fonte.is_present"),
            "le fonti mancanti non si filtrano: nasconderle direbbe che il modello non le aveva \
             mai nominate"
        );
        assert!(
            corpo.contains("missing_sources()"),
            "e quante ne mancano si dice"
        );

        let pagina = pagina_dei_modelli();
        assert!(
            pagina.contains("fonte.present ? Palette.text : Palette.amber"),
            "la fonte mancante si distingue a vista, e la frase lo dice comunque"
        );
    }

    /// **Solo la differenza che cancella si distingue a vista.**
    ///
    /// # Perché non tutte
    ///
    /// Perché un avviso su ogni differenza si scavalca. Quella che, adottata
    /// senza leggerla, **distrugge qualcosa** è una sola, e va riconosciuta.
    #[test]
    fn solo_la_differenza_che_cancella_si_distingue() {
        let pagina = pagina_dei_modelli();
        assert!(
            pagina.contains("root.template-would-delete"),
            "la differenza che cancella si distingue"
        );
        // E LA SOGLIA NON HA QUEL COLORE: non cancella mai.
        let Some(inizio) = pagina.find("root.template-notification-sentence != \"\": Text {")
        else {
            panic!("la frase della soglia deve esistere");
        };
        let Some(fine) = pagina[inizio..].find("\n                                }") else {
            panic!("il blocco deve chiudersi");
        };
        assert!(
            !pagina[inizio..inizio + fine].contains("template-would-delete"),
            "una soglia non cancella niente: darle il colore dell'allarme insegnerebbe a \
             ignorarlo"
        );
    }

    /// **La schermata non conosce l'archivio.**
    #[test]
    fn la_schermata_non_conosce_l_archivio() {
        assert!(
            !codice_senza_commenti().contains("lisi_storage"),
            "l'interfaccia dipende soltanto dai servizi applicativi (ADR-0010)"
        );
    }

    /// **La schermata esiste, ed è raggiungibile.**
    #[test]
    fn la_schermata_si_raggiunge() {
        assert!(
            crate::surface_text::assegna(UI, "label", "Modelli"),
            "la voce di navigazione deve esistere"
        );
        assert!(
            UI.contains("page == 24) {\n            root.templates-shown();"),
            "aprirla deve rileggere"
        );
    }

    /// **Il ciclo intero sulla finestra vera** (OPERATOR-E2E-REMEDIATION-01,
    /// F-07): nuovo modello → fonti e dizionari spuntati → salva → l'elenco lo
    /// mostra anche rileggendo → «Mostra che cosa prepara» → «Prepara un nuovo
    /// monitoraggio»: la procedura guidata è compilata, aperta al primo passo,
    /// e **nessun monitoraggio è partito**.
    #[test]
    fn crea_salva_riapri_e_prepara_senza_avviare() {
        use lisi_core::model::{NewSource, SourceKind};
        use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

        i_slint_backend_testing::init_no_event_loop();
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("prova.sqlite");
        let apri = || {
            let Ok(archivio) = lisi_services::Database::open(&percorso) else {
                panic!("l'archivio di prova deve aprirsi");
            };
            archivio
        };

        // Una fonte attiva, scritta direttamente: l'interfaccia non conosce il
        // connettore, e la prova non ne ha bisogno.
        let (Ok(nome_fonte), Ok(identificativo), Ok(attore)) = (
            DisplayName::try_new("Canale di prova"),
            SourceIdentifier::try_new("-1001"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(fonte) = apri().insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome_fonte,
                authorized_by: attore,
                active: true,
            },
            lisi_core::Timestamp::from_millis(1_700_000_000_000),
        ) else {
            panic!("la fonte deve potersi scrivere");
        };

        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        let Some(dizionari) = crate::dictionaries::create_service(apri()) else {
            panic!("la libreria deve aprirsi");
        };
        let Some(fonti) = crate::sources::create_service(apri()) else {
            panic!("le fonti devono aprirsi");
        };
        let composizione = crate::wizard::create();
        let Some(modelli) = super::create_service(apri()) else {
            panic!("i modelli devono aprirsi");
        };
        let contesto = super::TemplateContext {
            sources: Some(Rc::clone(&fonti)),
            dictionaries: Some(Rc::clone(&dizionari)),
            wizard: Some(Rc::clone(&composizione)),
        };
        let avvii = Rc::new(std::cell::Cell::new(0_u32));
        {
            let avvii = Rc::clone(&avvii);
            window.on_start_monitoring(move || avvii.set(avvii.get() + 1));
        }
        super::wire(&window, &modelli, &contesto);
        super::refresh(&window, &modelli);
        assert_eq!(conta_modelli(&window), 0);

        // CREA.
        window.invoke_template_form_new();
        assert!(window.get_template_form_open());
        assert_eq!(
            window.get_template_form_sources().row_count(),
            1,
            "il modulo offre la fonte attiva"
        );
        let Some(primo_dizionario) = window.get_template_form_dictionaries().row_data(0) else {
            panic!("il modulo offre i dizionari forniti con il prodotto");
        };

        // Senza nome il modello non si salva, e lo dice.
        window.invoke_template_form_save();
        assert!(window.get_template_form_message().contains("nome"));

        window.set_template_form_name(SharedString::from("Turno di giorno"));
        // Senza fonti nemmeno.
        window.invoke_template_form_save();
        assert!(
            window
                .get_template_form_message()
                .contains("almeno una fonte")
        );

        window.invoke_template_form_toggle_source(i32::try_from(fonte.get()).unwrap_or(0));
        window.invoke_template_form_toggle_dictionary(primo_dizionario.id);
        window.set_template_form_threshold_index(2);

        // SALVA.
        window.invoke_template_form_save();
        assert!(
            !window.get_template_form_open(),
            "salvato, il modulo si chiude: {}",
            window.get_template_form_message()
        );
        assert_eq!(conta_modelli(&window), 1);
        assert!(window.get_template_message().contains("salvato"));

        // RIAPRI: un servizio nuovo sullo stesso archivio, come dopo un riavvio.
        let Some(riaperto) = super::create_service(apri()) else {
            panic!("i modelli devono riaprirsi");
        };
        super::refresh(&window, &riaperto);
        assert_eq!(
            conta_modelli(&window),
            1,
            "il modello resta dopo la riapertura"
        );
        let Some(riga) = window.get_template_rows().row_data(0) else {
            panic!("la riga deve esserci");
        };
        assert_eq!(riga.name.as_str(), "Turno di giorno");

        // Lo stesso nome una seconda volta è rifiutato con una frase che nomina.
        window.invoke_template_form_new();
        window.set_template_form_name(SharedString::from("Turno di giorno"));
        window.invoke_template_form_toggle_source(i32::try_from(fonte.get()).unwrap_or(0));
        window.invoke_template_form_save();
        assert!(window.get_template_form_open(), "il doppione non si salva");
        assert!(!window.get_template_form_message().is_empty());
        window.invoke_template_form_cancel();

        // APPLICA: mostra che cosa prepara, dizionari compresi.
        window.invoke_apply_template(riga.id);
        assert!(window.get_template_preparation_open());
        assert_eq!(
            window.get_template_preparation_dictionaries().row_count(),
            1
        );
        assert_eq!(window.get_template_preparation_id(), riga.id);

        // PREPARA: la procedura è compilata, al primo passo, e nulla è partito.
        window.invoke_template_prepare_monitoring(riga.id);
        assert_eq!(
            window.get_current_page(),
            6,
            "si apre il nuovo monitoraggio"
        );
        assert_eq!(window.get_wizard_step(), 1, "al primo passo");
        assert!(composizione.borrow().has_source(fonte));
        assert!(
            composizione
                .borrow()
                .has_dictionary(lisi_core::DictionaryId::new(i64::from(primo_dizionario.id)))
        );
        assert!(
            window
                .get_wizard_template_note()
                .contains("«Avvia monitoraggio»"),
            "la procedura dice che nulla parte da sola: {}",
            window.get_wizard_template_note()
        );
        assert_eq!(avvii.get(), 0, "preparare non avvia nessun monitoraggio");
    }

    /// **L'elenco parte vuoto.**
    #[test]
    fn l_elenco_parte_vuoto() {
        // L'event loop di winit si crea una volta sola per processo (NOTE-01).
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        assert_eq!(conta_modelli(&window), 0);
    }
}

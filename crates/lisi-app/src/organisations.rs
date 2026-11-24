//! Collegamento fra le Impostazioni e l'elenco delle organizzazioni sorvegliate.
//!
//! # Perché questa sezione esiste
//!
//! DEC-235 aveva lasciato la tassonomia dei settori NIS2 costruita e scollegata,
//! perché «collegarla richiede una regola che assegni un settore a un contenuto,
//! e nessuna regola verificata esiste».
//!
//! La regola è questa sezione: un amministratore dichiara quali organizzazioni
//! sorveglia e in quale settore ricadono, e da quel momento un contenuto che le
//! nomina porta quel settore — con il nome di chi l'ha dichiarato accanto.
//!
//! **Senza questa schermata la regola sarebbe una capacità costruita e mai
//! raggiungibile**, che è il difetto che CY-01 esisteva per chiudere e che
//! questo progetto ha già ricreato una volta.
//!
//! # Che cosa questa schermata non fa
//!
//! Non propone organizzazioni. Non deduce settori. Non contiene alcun elenco di
//! enti: quello lo scrive chi amministra, e finisce nell'archivio della
//! postazione — mai nel sorgente.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::WatchedOrganisationId;
use lisi_core::model::organisation::{
    NewWatchedOrganisation, OrganisationAlias, OrganisationDomain, WatchedOrganisation,
};
use lisi_core::model::relevance::Sector;
use lisi_core::text::DisplayName;
use lisi_services::organisations::OrganisationService;
use lisi_services::station;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, WatchedOrganisationEntry};

/// Servizio condiviso fra i gestori dei comandi.
pub type SharedOrganisations = Rc<RefCell<OrganisationService>>;

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Crea il servizio sull'archivio indicato.
///
/// Restituisce `None` quando l'archivio non è disponibile: senza, la sezione
/// resta vuota e lo dichiara, invece di far credere che l'elenco sia vuoto.
#[must_use]
pub fn create_service(database: lisi_services::Database) -> Option<SharedOrganisations> {
    // La modalita' e' quella persistita per la postazione, la stessa che
    // governa la libreria dei dizionari: due letture diverse della stessa
    // impostazione sono due letture che un giorno divergono.
    let mode = station::persisted_mode_or_restricted();
    Some(Rc::new(RefCell::new(OrganisationService::new(
        database, mode,
    ))))
}

/// Collega i comandi della sezione al servizio.
pub fn wire(window: &AppWindow, organisations: &SharedOrganisations) {
    // L'elenco dei settori si compone **una volta**: è la tassonomia, e non
    // cambia mentre la finestra è aperta.
    window.set_organisation_sectors(ModelRc::from(Rc::new(VecModel::from(
        Sector::ALL
            .iter()
            .map(|settore| crate::lingua::schermo(settore.label()))
            .collect::<Vec<SharedString>>(),
    ))));

    {
        let handle = window.as_weak();
        let organisations = Rc::clone(organisations);
        window.on_organisations_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &organisations, None);
            }
        });
    }

    {
        let handle = window.as_weak();
        let organisations = Rc::clone(organisations);
        window.on_organisation_declare(move || {
            if crate::lock::refuse_while_locked("organisation_declare") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let messaggio = declare(&window, &organisations);
            refresh(&window, &organisations, Some(&messaggio));
        });
    }

    {
        let handle = window.as_weak();
        let organisations = Rc::clone(organisations);
        window.on_organisation_toggle(move |id, attiva| {
            if crate::lock::refuse_while_locked("organisation_toggle") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let messaggio = toggle(&organisations, id, attiva);
            refresh(&window, &organisations, Some(&messaggio));
        });
    }

    {
        let handle = window.as_weak();
        let organisations = Rc::clone(organisations);
        window.on_organisation_remove(move |id, motivo| {
            if crate::lock::refuse_while_locked("organisation_remove") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let messaggio = remove(&organisations, id, motivo.as_str());
            // Il modulo del motivo si chiude solo se l'organizzazione è stata
            // tolta: un rifiuto lascia il motivo dove l'operatore l'ha scritto.
            if messaggio.starts_with("Organizzazione tolta") {
                window.set_organisation_removing(0);
                window.set_organisation_remove_reason(SharedString::new());
            }
            refresh(&window, &organisations, Some(&messaggio));
        });
    }
}

/// Riporta nell'interfaccia l'elenco dichiarato.
pub fn refresh(window: &AppWindow, organisations: &SharedOrganisations, message: Option<&str>) {
    if let Some(testo) = message {
        window.set_organisations_message(SharedString::from(testo));
    }

    // Chi può scrivere lo decide il **servizio**, non l'interfaccia: un pulsante
    // nascosto non è un controllo. Qui si nasconde ciò che il servizio
    // rifiuterebbe comunque, per non offrire un comando che finirebbe in un
    // errore.
    let scrivibile = organisations.borrow().can_declare();
    window.set_organisations_writable(scrivibile);

    let elenco = match organisations.borrow().organisations() {
        Ok(elenco) => elenco,
        Err(errore) => {
            window.set_organisations_message(crate::lingua::schermo(errore.operator_message()));
            window.set_organisations(ModelRc::from(Rc::new(VecModel::from(Vec::new()))));
            return;
        }
    };

    let voci: Vec<WatchedOrganisationEntry> = elenco.iter().map(entry_of).collect();
    window.set_organisations(ModelRc::from(Rc::new(VecModel::from(voci))));
}

/// Compone la riga che l'amministratore rilegge.
fn entry_of(organisation: &WatchedOrganisation) -> WatchedOrganisationEntry {
    // Nomi e domini in una riga sola: sono ciò che fa scattare il riscontro, e
    // chi rilegge la propria dichiarazione deve poterli verificare senza aprire
    // un dettaglio.
    let mut ancore = Vec::new();
    if !organisation.aliases.is_empty() {
        ancore.push(format!(
            "nomi: {}",
            organisation
                .aliases
                .iter()
                .map(OrganisationAlias::written)
                .collect::<Vec<&str>>()
                .join(", ")
        ));
    }
    if !organisation.domains.is_empty() {
        ancore.push(format!(
            "domini: {}",
            organisation
                .domains
                .iter()
                .map(OrganisationDomain::as_str)
                .collect::<Vec<&str>>()
                .join(", ")
        ));
    }

    let stato = if organisation.active {
        String::new()
    } else {
        String::from(" — sospesa, non produce riscontri")
    };

    WatchedOrganisationEntry {
        id: i32::try_from(organisation.id.get()).unwrap_or(0),
        name: SharedString::from(organisation.name.as_str()),
        sector: crate::lingua::schermo(organisation.sector.label()),
        anchors: SharedString::from(ancore.join(" · ")),
        active: organisation.active,
        declared: crate::lingua::schermo(format!(
            "Dichiarata da {} il {}{stato}",
            organisation.declared_by.as_str(),
            organisation.declared_at.to_readable_local()
        )),
    }
}

/// Dichiara l'organizzazione composta nel modulo.
fn declare(window: &AppWindow, organisations: &SharedOrganisations) -> String {
    let Ok(nome) = DisplayName::try_new(window.get_organisation_name_input().as_str()) else {
        return String::from("Il nome dell'organizzazione non è utilizzabile.");
    };

    let indice = usize::try_from(window.get_organisation_sector_index()).unwrap_or(0);
    let Some(settore) = Sector::ALL.get(indice) else {
        return String::from("Scegliere un settore.");
    };

    // Il nome dell'organizzazione entra **anche** fra i nomi cercati: chi
    // dichiara «Ente Alfa» si aspetta che un contenuto che scrive «Ente Alfa»
    // riscontri, e chiederglielo due volte sarebbe una trappola.
    //
    // Puo' fallire — un nome di due lettere non e' un alias utilizzabile — e in
    // quel caso non e' un errore: significa che serve un dominio, e la
    // dichiarazione lo dira' se non ce n'e' nessuno.
    let mut alias = Vec::new();
    if let Ok(voce) = OrganisationAlias::try_new(nome.as_str()) {
        alias.push(voce);
    }

    for grezzo in window.get_organisation_aliases_input().split(',') {
        if grezzo.trim().is_empty() {
            continue;
        }
        match OrganisationAlias::try_new(grezzo) {
            Ok(voce) => alias.push(voce),
            Err(errore) => return errore.to_string(),
        }
    }

    let mut domini = Vec::new();
    for grezzo in window.get_organisation_domains_input().split(',') {
        if grezzo.trim().is_empty() {
            continue;
        }
        match OrganisationDomain::try_new(grezzo) {
            Ok(voce) => domini.push(voce),
            Err(errore) => return errore.to_string(),
        }
    }

    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let adesso = now();

    let dichiarazione = match NewWatchedOrganisation::try_new(
        nome, *settore, alias, domini, None, attore, adesso,
    ) {
        Ok(valore) => valore,
        Err(errore) => return errore.to_string(),
    };

    match organisations.borrow_mut().declare(&dichiarazione, adesso) {
        Ok(_) => {
            // Il modulo si svuota solo quando la dichiarazione e' riuscita: chi
            // ha sbagliato un dominio non deve ridigitare anche il resto.
            window.set_organisation_name_input(SharedString::new());
            window.set_organisation_aliases_input(SharedString::new());
            window.set_organisation_domains_input(SharedString::new());
            String::new()
        }
        Err(errore) => errore.operator_message(),
    }
}

/// Sospende o riattiva un'organizzazione.
/// Toglie un'organizzazione dichiarata, con il motivo (FINAL-REVIEW-01, FR-048).
///
/// Il servizio esisteva, con il motivo obbligatorio, e nessun comando lo
/// raggiungeva, mentre il manuale dell'amministratore diceva che si può fare.
/// Un motivo vuoto lo rifiuta il servizio, non questa funzione.
fn remove(organisations: &SharedOrganisations, id: i32, motivo: &str) -> String {
    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    match organisations.borrow_mut().remove(
        WatchedOrganisationId::new(i64::from(id)),
        motivo,
        &attore,
        now(),
    ) {
        Ok(()) => {
            String::from("Organizzazione tolta. Il motivo resta nel registro delle operazioni.")
        }
        Err(errore) => errore.operator_message(),
    }
}

fn toggle(organisations: &SharedOrganisations, id: i32, attiva: bool) -> String {
    let Ok(attore) = crate::operator::audit_actor() else {
        return String::from(crate::account::NON_SI_SA_CHI_OPERA);
    };
    let adesso = now();

    match organisations.borrow_mut().set_active(
        WatchedOrganisationId::new(i64::from(id)),
        attiva,
        &attore,
        adesso,
    ) {
        Ok(()) => String::new(),
        Err(errore) => errore.operator_message(),
    }
}

#[cfg(test)]
mod tests {
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **Un'organizzazione si toglie dall'interfaccia, con il motivo**
    /// (FINAL-REVIEW-01, FR-048): il manuale dell'amministratore lo dice, e il
    /// servizio esisteva senza un comando che lo raggiungesse.
    #[test]
    fn an_organisation_can_be_removed_with_a_reason() {
        const QUESTO_FILE: &str = include_str!("organisations.rs");
        assert!(UI.contains("callback organisation-remove(int, string);"));
        assert!(UI.contains("root.organisation-remove("));
        assert!(UI.contains("enabled: root.organisation-remove-reason != \"\";"));
        let Some((produzione, _)) = QUESTO_FILE.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        assert!(produzione.contains("window.on_organisation_remove("));
        assert!(produzione.contains("organisations.borrow_mut().remove("));
    }

    /// **La sezione dice che il settore non alza la gravità.**
    ///
    /// È la confusione più probabile su questa schermata: chi dichiara
    /// un'organizzazione della sanità potrebbe credere di aver alzato la
    /// priorità di ciò che la nomina. Non lo ha fatto, e va detto dove si
    /// dichiara — non dopo (ADR-0035 Decisione 10).
    #[test]
    fn la_sezione_dichiara_che_il_settore_non_e_una_gravita() {
        assert!(
            UI.contains("non rende grave nulla"),
            "la sezione deve dire che un settore critico non alza la gravita'"
        );
        assert!(
            UI.contains("Il livello 0-4 lo decidono i dizionari"),
            "la sezione deve dire chi decide davvero il livello"
        );
    }

    /// **La sezione dice che senza elenco il settore non compare.**
    ///
    /// Un elenco vuoto non è un difetto: è lo stato di ogni postazione appena
    /// installata. Ma chi lo trova vuoto deve sapere che cosa manca, e che cosa
    /// **non** manca — Cyber Watch continua a funzionare senza.
    #[test]
    fn la_sezione_dichiara_che_cosa_succede_con_lelenco_vuoto() {
        assert!(
            UI.contains("Nessuna organizzazione dichiarata"),
            "la sezione deve avere uno stato vuoto esplicito"
        );
        // Il testo dell'interfaccia e' concatenato su piu' righe, quindi la
        // frase intera non esiste come sequenza contigua nel file: si verificano
        // i due pezzi. E' un limite di una guardia testuale, e va dichiarato
        // invece di essere aggirato con un'asserzione piu' debole di quanto
        // sembri.
        assert!(
            UI.contains("«Segnali cyber» continua a "),
            "lo stato vuoto deve dire che cosa NON smette di funzionare"
        );
        assert!(
            UI.contains("Solo il settore non comparirà"),
            "lo stato vuoto deve dire che cosa manca davvero"
        );
    }

    /// **In modalità operatore l'elenco si legge e non si scrive.**
    ///
    /// Chi vede un settore su un avviso deve poter sapere da dove viene:
    /// negargli l'elenco renderebbe l'attribuzione incontestabile.
    #[test]
    fn in_modalita_operatore_lelenco_resta_leggibile() {
        assert!(
            UI.contains("if !root.organisations-writable:"),
            "la sezione deve dichiarare perche' i comandi non ci sono"
        );
        assert!(
            UI.contains("In modalità operatore resta leggibile"),
            "la sezione deve dire che l'elenco si legge comunque"
        );
        // I comandi di scrittura stanno tutti dentro il ramo scrivibile.
        assert!(
            UI.contains("if root.organisations-writable: Rectangle"),
            "il modulo di dichiarazione deve stare dentro il ramo scrivibile"
        );
    }

    /// **Ogni riga dice chi ha dichiarato l'organizzazione.**
    ///
    /// È ciò che rende contestabile un'attribuzione: senza, l'elenco sarebbe un
    /// insieme di regole senza autore.
    #[test]
    fn ogni_riga_mostra_la_provenienza_della_dichiarazione() {
        assert!(
            UI.contains("organisation.declared"),
            "la riga deve mostrare chi ha dichiarato e quando"
        );
        assert!(
            UI.contains("organisation.anchors"),
            "la riga deve mostrare i nomi e i domini che fanno scattare il riscontro"
        );
    }

    /// **Il sorgente dell'interfaccia non contiene alcun elenco di enti.**
    ///
    /// Sarebbe una lista arbitraria che nessuno ha approvato e che, su ogni
    /// postazione, direbbe a chiunque la legga quali enti l'ufficio considera
    /// bersagli. I segnaposto dei campi devono restare **descrizioni**, non
    /// esempi riconoscibili.
    #[test]
    fn i_segnaposto_non_contengono_organizzazioni_reali() {
        // «esempio.it» e' un dominio riservato agli esempi per convenzione, e
        // non e' un ente. Qualunque altro dominio nei segnaposto lo sarebbe.
        assert!(
            UI.contains("placeholder: @tr(\"esempio.it\")"),
            "il segnaposto del dominio deve restare un esempio convenzionale"
        );
        assert!(
            UI.contains("placeholder: @tr(\"sigle, denominazioni abbreviate\")"),
            "il segnaposto dei nomi deve descrivere, non esemplificare"
        );
    }
}

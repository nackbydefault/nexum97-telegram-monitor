#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
// `deny` e non `forbid`: il codice generato da Slint e incluso da `include_modules!`
// contiene macro `ItemTreeVTable_static!` che emettono `#[allow(unsafe_code)]` per le
// proprie vtable. `forbid` non è derogabile e renderebbe il crate non compilabile.
// `deny` mantiene il divieto su tutto il codice scritto a mano di questo crate.
// Il crate `lisi-core`, privo di codice generato, conserva `forbid(unsafe_code)`.
#![deny(unsafe_code)]

// Solo verifiche: il testo che l'operatore legge deve usare gli accenti
// italiani, e i commenti restano liberi di scrivere in ASCII (DEC-231).
#[cfg(test)]
mod accents_guard;
// Solo verifiche: il modulo non contribuisce al binario, legge il file
// dell'interfaccia e ne controlla le proprieta' di accessibilita'.
#[cfg(test)]
mod accessibility;
mod account;
mod acquisition;
#[cfg(test)]
mod animation_guard;
mod attachment;
mod backup;
mod backup_schedule;
mod bookmark;
// Solo verifiche: le attribuzioni personali stanno nella sola pagina
// «Informazioni e licenze», non nelle schermate operative (DEC-089).
#[cfg(test)]
mod branding_guard;
mod contrast_guard;
// Solo verifiche: i comandi condivisi provati col puntatore e con la tastiera,
// su una finestra vera del backend di prova (UX-EXCELLENCE-02, SIM3-01).
#[cfg(test)]
mod controls_guard;
// Che cosa stavamo guardando: la copertura in barre e in parole (PR-05,
// ADR-0121).
mod closing;
mod configurazione;
mod consultations;
mod conversation;
mod coverage;
mod cross_search;
mod cyber;
mod cyber_recurring;
mod cyber_search;
mod dashboard;
mod diagnostics;
mod dialogs;
mod dictionaries;
mod discovery;
// Solo verifiche: i documenti correnti devono dichiarare numeri veri. Contano
// dalla fonte — interfaccia, piano di implementazione, lockfile — invece di
// fidarsi di un numero scritto a mano (PF-01, DOC-02). Legge i documenti
// interni: sta soltanto nell'archivio (ADR-0210).
// Il pacchetto di evidenze, nella schermata del workspace (PR-11, ADR-0127).
mod evidence;
// L'Esercitazione: la fascia, il ricominciare, l'insieme sintetico (PR-13).
mod exercise;
// «Perché vedo questo?»: il pannello unico, con la risposta in tre parti
// (PR-02, ADR-0119).
mod explain;
mod fonts;
// Il segnale che un comando ha cambiato l'archivio dei contenuti (E2E01-05).
mod freshness;
// Il passaggio di consegne, nel cruscotto (PR-12, ADR-0128).
mod handover;
#[cfg(test)]
mod page_guard;
// Solo verifiche: lega la voce di menu «Guida» alla pagina che apre, così che un
// rinumero delle pagine non le disallinei in silenzio.
mod graph;
// Il registro delle guardie: nessuna sparisce in silenzio (PR-15, ADR-0131).
// Il registro sta fra i documenti interni: soltanto nell'archivio (ADR-0210).
#[cfg(test)]
mod guide_guard;
// I periodi non coperti prioritari nella Coda di lavoro (PR-06, ADR-0122).
mod gaps;
mod history;
// Solo verifiche: la decisione 3 di ADR-0082. La verifica TLS non ha una chiave
// di scorta, ne' nel prodotto ne' nelle prove.
#[cfg(test)]
mod destructive_guard;
#[cfg(test)]
mod focus_guard;
// Solo verifiche: la guardia per lingua (I18N-01, ADR-0197).
#[cfg(test)]
mod hub_trust_guard;
#[cfg(test)]
mod i18n_guard;
mod ioc_resolve;
#[cfg(test)]
mod keyboard_guard;
// La lingua dell'interfaccia (I18N-01, ADR-0197).
mod lingua;
mod links;
mod lock;
#[cfg(test)]
mod lock_guard;
mod logging;
mod members;
mod monitoring;
mod monitoring_template;
// «Scopri che cosa è cambiato» (NEWS-01, ADR-0169).
mod news;
mod note;
mod notification_center;
mod office_account;
// Solo verifiche: il vincolo permanente di ADR-0048. La guardia forte non e' un
// elenco, e' l'assenza di una capacita' di rete nel codice Rust del prodotto.
#[cfg(test)]
mod no_ai_guard;
mod operator;
mod organisations;
mod outcomes;
// Solo verifiche: chi dice ogni dato che l'interfaccia mostra (PR-03, ADR-0118).
#[cfg(test)]
mod origin_guard;
mod participants;
mod profile_media;
// «Pronto per lavorare»: il controllo di avvio, in una riga (PR-04, ADR-0120).
mod preflight;
// Solo verifiche: le voci di NEXUM97-MINOR-FIX-01 nell'interfaccia (ADR-0155).
#[cfg(test)]
mod minor_fix_guard;
// Solo verifiche: il linguaggio che l'operatore legge (PR-01, ADR-0117).
mod person;
#[cfg(test)]
mod plain_italian_guard;
mod recipient_copy;
mod recovery;
// Il WHOIS dal PC (WHOIS-01, ADR-0205).
mod registrazione;
mod report;
// Le schermate: quante sono, e come si apre la prima (PR-14, ADR-0130).
mod navigation;
mod references;
mod resolver;
mod retention;
mod rule_lab;
mod saved_search;
// Gli elenchi non stanno in una fessura (COLLAUDO-FIX-01, CU01-014).
#[cfg(test)]
mod scroll_guard;
mod servizio;
mod servizio_installazione;
mod servizio_stato;
mod settings;
mod signing;
mod source_reliability;
mod source_suggestion;
mod sources;
// Solo verifiche: il testo mostrato, estratto in un posto solo per tutte le
// guardie che lo leggono.
#[cfg(test)]
mod surface_text;
// Solo verifiche: nulla entra nella catena di fornitura in silenzio. Un'advisory
// accettata dev'essere spiegata, un componente nativo dev'essere sorvegliato
// (DEP-01).
mod accesso;
mod author_subject;
mod interruption;
// I marcatori della copia pubblica sono in coppia (ADR-0210, DEC-522).
mod export_markers_guard;
// Le due guardie seguenti leggono gli script, i flussi della CI e i documenti
// interni: stanno soltanto nell'archivio (ADR-0210).
mod team;
mod team_live;
mod team_review;
mod team_shared;
// «Scopri NEXUM», il tour guidato (TOUR-01, ADR-0134).
mod toast;
mod tour;
mod tray;
mod update;
mod verification;
// La veglia della postazione, che segue chi riceve (E2E01-22).
mod wakefulness;
mod why_subject;
mod wizard;
mod work_queue;
mod workspace;

use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;

use lisi_core::branding;
use lisi_core::{AppMetadata, PRODUCT_LICENSE, THIRD_PARTY_COMPONENTS};
use lisi_services::hub_live::HubLivePublisher;
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};

slint::include_modules!();

/// Traduce l'elenco delle attribuzioni nel modello atteso dall'interfaccia.
///
/// L'elenco non è scritto nel file `.slint`: per Slint l'attribuzione è una
/// condizione della licenza royalty-free, quindi il dato deve stare dove un test
/// può verificarlo. Vedere `docs/adr/ADR-0005-SLINT-LICENSING.md`.
fn third_party_model() -> ModelRc<ThirdPartyEntry> {
    let entries: Vec<ThirdPartyEntry> = THIRD_PARTY_COMPONENTS
        .iter()
        .map(|component| ThirdPartyEntry {
            component: SharedString::from(component.name),
            version: SharedString::from(component.version),
            license: SharedString::from(component.license),
            note: SharedString::from(component.note),
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Spezza un corpo della guida in due capoversi, **senza cambiare una parola**.
///
/// # Perche' qui e non nel testo
///
/// Il contenuto della guida vive in `lisi-core`, dove una prova verifica che
/// otto affermazioni compaiano **testuali**: sono quelle che impediscono alla
/// guida di sovrapromettere. Riscrivere quei corpi per aerarli significherebbe
/// mettere le mani su un testo sorvegliato per una ragione di impaginazione.
///
/// Andare a capo e' una scelta di PRESENTAZIONE, e sta dove la presentazione si
/// decide. Le parole restano quelle che la prova custodisce.
///
/// # Dove si spezza
///
/// Al confine di frase **piu' vicino alla meta'**. Su corpi di tre o quattro
/// frasi quel punto cade quasi sempre dove cadrebbe a mano, e quando non ci
/// cade il risultato resta leggibile: due capoversi sbilanciati si leggono
/// comunque meglio di un blocco unico.
///
/// I corpi brevi non si toccano: spezzare tre righe in due capoversi da una riga
/// e mezzo non aera niente, allunga soltanto.
fn in_capoversi(body: &str) -> String {
    /// Sotto questa lunghezza un corpo si legge tutto d'un fiato.
    const SOGLIA: usize = 240;

    if body.chars().count() <= SOGLIA {
        return body.to_owned();
    }

    let meta = body.len() / 2;
    let mut migliore: Option<usize> = None;

    // Un confine di frase e' un punto seguito da uno spazio. Il punto
    // interrogativo e quello esclamativo non compaiono in questa guida, e
    // aggiungerli significherebbe scrivere codice per un caso che non esiste.
    let bytes = body.as_bytes();
    for indice in 0..bytes.len().saturating_sub(1) {
        if bytes[indice] != b'.' || bytes[indice + 1] != b' ' {
            continue;
        }
        // Il taglio cade DOPO lo spazio, che sparisce con il capoverso.
        let taglio = indice + 2;
        if taglio >= body.len() {
            continue;
        }
        let distanza = taglio.abs_diff(meta);
        if migliore.is_none_or(|attuale: usize| distanza < attuale.abs_diff(meta)) {
            migliore = Some(taglio);
        }
    }

    match migliore {
        Some(taglio) => format!("{}\n\n{}", &body[..taglio - 1], &body[taglio..]),
        // Nessun confine di frase: e' un corpo di una frase sola, e resta tale.
        None => body.to_owned(),
    }
}

/// Il glossario, in ordine alfabetico, per la schermata Guida (PR-01, ADR-0117).
///
/// # Perché qui e non solo nelle prove
///
/// Un glossario che vivesse solo nella guardia fisserebbe le parole senza
/// spiegarle a nessuno. La Guida è dove l'operatore cerca che cosa vuol dire
/// una parola: il glossario ci sta per intero, con i termini tecnici e la frase
/// semplice che li sostituisce.
fn glossary_model() -> ModelRc<GlossaryRow> {
    let mut voci: Vec<&lisi_core::glossary::GlossaryEntry> =
        lisi_core::glossary::GLOSSARY.iter().collect();
    voci.sort_by_key(|voce| voce.term.to_lowercase());
    let righe: Vec<GlossaryRow> = voci
        .into_iter()
        .map(|voce| GlossaryRow {
            term: SharedString::from(voce.term),
            plain: SharedString::from(match voce.kind {
                lisi_core::glossary::EntryKind::Concept => String::from(voce.plain),
                // Di un termine tecnico la frase semplice e' la parola che lo
                // sostituisce: la voce lo dice per intero.
                lisi_core::glossary::EntryKind::Technical => {
                    format!("Nel programma si dice: {}.", voce.plain)
                }
            }),
            detail: SharedString::from(voce.technical_detail),
        })
        .collect();
    ModelRc::new(VecModel::from(righe))
}

/// Traduce la guida nel modello atteso dall'interfaccia.
///
/// Il contenuto vive in `lisi-core`, dove un test verifica che dichiari i
/// limiti invece di sovrapprometterli. Qui si traduce soltanto.
fn guide_model() -> ModelRc<GuideEntry> {
    let entries: Vec<GuideEntry> = lisi_core::guide::GUIDE
        .iter()
        .map(|section| GuideEntry {
            title: SharedString::from(section.title),
            body: SharedString::from(&in_capoversi(section.body)),
        })
        .collect();

    ModelRc::from(Rc::new(VecModel::from(entries)))
}

/// Apre l'archivio per un servizio dipendente: quello persistente se
/// apribile, altrimenti il ripiego condiviso in memoria (M3B.2).
///
/// Un archivio non apribile non deve disabilitare un servizio in silenzio: le
/// schermate che ne hanno bisogno restano utilizzabili in modalità
/// dimostrativa invece di restare vuote senza spiegazione. Il ripiego è lo
/// stesso per l'intera esecuzione, cosi' i servizi che degradano insieme
/// osservano gli stessi dati invece di un archivio isolato ciascuno — vedere
/// [`lisi_services::sources::open_fallback_database`].
struct StorageFallback {
    /// Vero se, almeno una volta in questa esecuzione, è stato usato il
    /// ripiego condiviso invece dell'archivio persistente.
    used: bool,
}

impl StorageFallback {
    const fn new() -> Self {
        Self { used: false }
    }

    /// Apre l'archivio persistente dell'applicazione, o il ripiego condiviso
    /// in memoria se non è apribile.
    fn open(&mut self) -> Option<lisi_services::Database> {
        self.open_with(lisi_services::sources::open_application_database)
    }

    /// Come [`Self::open`], ma con l'apertura dell'archivio persistente
    /// indicata dal chiamante: il seam che i test usano per simulare un
    /// guasto dell'archivio reale senza toccarlo davvero.
    fn open_with(
        &mut self,
        open_persistent: impl FnOnce() -> lisi_services::ServiceResult<lisi_services::Database>,
    ) -> Option<lisi_services::Database> {
        match open_persistent() {
            Ok(database) => Some(database),
            Err(error) => {
                // **Il messaggio, non solo la categoria.** Fino al 2026-08-18
                // qui finiva il solo `kind()`: sulla prima installazione reale
                // l'archivio non si e' aperto e il registro diceva soltanto
                // «errore_persistenza», che e' vero e non serve a nessuno. Chi
                // deve capire perche' un archivio non si apre ha bisogno di
                // sapere CHE COSA ha risposto SQLite, e quel testo era gia'
                // disponibile: veniva buttato via un passo prima di essere
                // scritto.
                tracing::error!(
                    errore = error.kind(),
                    motivo = %error,
                    "archivio locale non apribile: uso il ripiego condiviso in memoria"
                );
                match lisi_services::sources::open_fallback_database() {
                    Ok(database) => {
                        self.used = true;
                        Some(database)
                    }
                    Err(fallback_error) => {
                        tracing::error!(
                            errore = fallback_error.kind(),
                            motivo = %fallback_error,
                            "ripiego condiviso in memoria non disponibile"
                        );
                        None
                    }
                }
            }
        }
    }
}

/// Prende il file dell'istanza; se lo tiene il servizio in background, gli dà
/// il tempo di lasciarlo (SERVICE-01, ADR-0203).
///
/// Il servizio guarda ogni due secondi se la persona è rientrata, poi chiude i
/// client: trenta secondi bastano con margine. Senza il servizio si chiede una
/// volta sola, come prima.
fn attendi_il_servizio()
-> lisi_services::ServiceResult<Option<lisi_services::instance::InstanceGuard>> {
    use lisi_platform::background_service::{ServiceState, state};
    let primo = lisi_services::instance::acquire()?;
    if primo.is_some()
        || !matches!(
            state(lisi_core::model::background::SERVICE_NAME),
            Ok(ServiceState::Running | ServiceState::Changing)
        )
    {
        return Ok(primo);
    }
    let fine = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < fine {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if let Some(istanza) = lisi_services::instance::acquire()? {
            return Ok(Some(istanza));
        }
    }
    Ok(None)
}

fn run() -> Result<(), Box<dyn Error>> {
    // IL MODO DEL PROCESSO SI STABILISCE PER PRIMO (PR-13, ADR-0129): la
    // cartella del registro, dell'archivio e dei file protetti ne dipende, e
    // dopo non cambia. In Esercitazione il testimone operativo non esiste, e
    // con lui l'autorità di acquisire da Telegram.
    let modo = lisi_services::run_mode::establish(
        lisi_core::model::run_mode::RunMode::from_arguments(std::env::args()),
    )?;
    let esercitazione_attiva = modo.mode().is_exercise();

    // UNA SOLA ISTANZA PER CARTELLA DATI (OPERATOR-E2E-REMEDIATION-01, F-01).
    //
    // Lo stato del blocco vive nel processo che l'ha fatto scattare: una
    // seconda copia, aperta dal menu Start, nasceva sbloccata sullo stesso
    // archivio e mostrava a chi passava ciò che la prima nascondeva. La cartella
    // e' quella del modo: l'Esercitazione ha la propria e puo' stare accanto a
    // quella operativa. Se il file dell'istanza non si apre si parte comunque e
    // lo si scrive nel registro: un programma che non parte per un file di
    // servizio sarebbe peggio del rischio che il file sorveglia.
    let _istanza = match attendi_il_servizio() {
        Ok(Some(istanza)) => Some(istanza),
        Ok(None) => {
            // Un'informazione, non un guasto: l'icona e' quella dell'avviso, e
            // la finestra di Windows la mostra `rfd` senza codice nostro.
            rfd::MessageDialog::new()
                .set_level(rfd::MessageLevel::Info)
                .set_title(lisi_core::branding::PRODUCT_NAME)
                .set_description(format!(
                    "{nome} è già aperto su questa postazione. Si ritrova dalla barra delle \
                     applicazioni o dall'icona accanto all'orologio. Se è bloccato, si sblocca \
                     con la parola di sblocco.\n\nUna seconda copia non si apre: vedrebbe lo \
                     stesso archivio senza il blocco della prima.",
                    nome = lisi_core::branding::PRODUCT_NAME
                ))
                .set_buttons(rfd::MessageButtons::Ok)
                .show();
            return Ok(());
        }
        Err(errore) => {
            eprintln!("istanza non verificata: {errore}");
            None
        }
    };

    // L'OROLOGIO SI LEGGE SUBITO DOPO, E UNA VOLTA SOLA
    // (FINAL-FPR-ALL-16, FPR-10).
    //
    // Fino al 2026-10-11 nessuno lo leggeva per primo: trentadue punti del
    // prodotto chiedevano l'istante corrente e, se l'orologio non si leggeva,
    // scrivevano **1970-01-01** in silenzio — nell'audit, nei monitoraggi,
    // nei documenti. In un prodotto costruito intorno alla provenienza e
    // all'ora era l'unica cosa non vera che venisse scritta senza dirlo.
    //
    // Ora la decisione è una, e sta qui: **se l'orologio non si legge, il
    // programma non si avvia**, e la finestra di Windows dice perché e che
    // cosa fare. Un monitoraggio senza istanti attendibili non è un atto, e
    // un atto con istanti inventati è peggio di un programma che non parte.
    //
    // Se l'orologio smette di leggersi **dopo** l'avvio, l'istante si ricava
    // dall'ancora fissata qui più il tempo monotono trascorso: non è un
    // valore inventato, è lo stesso istante contato in un altro modo
    // (`lisi_core::time::anchored_now`).
    let avviato_alle = lisi_core::time::anchor_clock().map_err(|errore| {
        format!(
            "l'orologio di questa postazione non è leggibile ({errore}). Ogni istante che il \
             programma registrerebbe adesso sarebbe falso, e un monitoraggio senza istanti \
             attendibili non è un atto. Correggere la data e l'ora da Impostazioni di Windows \
             › Ora e lingua › Data e ora, poi riaprire il programma."
        )
    })?;

    // L'ORA DELL'OROLOGIO SULLO SCHERMO, L'UTC ACCANTO (ADR-0136, SIM3-05).
    //
    // Il fuso lo dice Windows, istante per istante e con l'ora legale: lo
    // schermo scrive prima l'ora che l'operatore ha sotto gli occhi e poi
    // quella UTC. Nulla di conservato cambia, e i documenti probatori restano
    // in UTC. Se Windows non risponde, lo schermo resta in UTC, dichiarato.
    lisi_core::time::install_local_offset(lisi_platform::local_time::utc_offset_minutes);

    let logging_guard = logging::initialize();
    if logging_guard.degraded() {
        tracing::warn!("registro applicativo non persistente in questa esecuzione");
    }
    let metadata = AppMetadata::current();

    tracing::info!(
        application = metadata.name,
        version = metadata.version,
        avviato_alle = %avviato_alle.to_readable_utc(),
        log_directory = %logging_guard.log_directory().display(),
        "Avvio della shell grafica"
    );

    // Va dichiarata **prima** che la finestra esista: dopo, Windows ha gia'
    // deciso come raggruppare l'applicazione sulla barra delle applicazioni, e
    // una dichiarazione tardiva non sposta il raggruppamento gia' fatto.
    // Senza, il toast nativo non ha a chi essere attribuito.
    if let Err(error) = lisi_platform::app_identity::declare() {
        tracing::warn!(errore = %error, "identita' dell'applicazione non dichiarata");
    }

    // I caratteri li incorpora il compilatore di Slint; qui si dice soltanto
    // quale dei due casi e' avvenuto. Chi guarda una schermata e la trova
    // diversa dal riferimento deve poterlo capire dal registro, invece di
    // cercare il difetto altrove.
    match fonts::status() {
        fonts::Fonts::Embedded => {
            tracing::info!("caratteri del prodotto incorporati nel binario");
        }
        fonts::Fonts::Fallback => {
            tracing::warn!(
                "caratteri non incorporati: il testo usa la catena di ripiego \
                 (scripts/fetch-fonts.ps1 li incorpora)"
            );
        }
    }

    // Se la finestra non si crea (driver grafico, sessione remota) lo si scrive
    // nel registro QUI, finché il registro è aperto (FINAL-REVIEW-01, FR-033).
    let window = AppWindow::new().inspect_err(|errore| {
        tracing::error!(errore = %errore, "la finestra principale non si è creata");
    })?;
    // Il nome pubblico arriva da Rust e non è scritto nel file `.slint`: sta in
    // `lisi-core` accanto agli identificatori persistenti che non cambiano con
    // esso, dove un test impedisce di rinominarli insieme.
    window.set_product_name(branding::PRODUCT_NAME.into());
    window.set_product_subtitle(branding::PRODUCT_SUBTITLE.into());
    window.set_product_description(branding::PRODUCT_DESCRIPTION.into());
    window.set_app_version(metadata.version.into());
    window.set_status_text(metadata.state.operator_message().into());
    window.set_attribution(metadata.attribution.into());
    window.set_product_license(PRODUCT_LICENSE.into());
    window.set_third_party_components(third_party_model());
    window.set_guide_sections(guide_model());
    window.set_glossary_entries(glossary_model());

    let mut storage = StorageFallback::new();

    // La schermata Account passa dai servizi applicativi: l'interfaccia non
    // conosce TDLib, la persistenza o i segreti (ADR-0010). La sessione possiede
    // il servizio degli account (profili, account, persistenza) ed e' la fonte
    // unica dello stato di accesso. Se l'archivio persistente non e' apribile si
    // ripiega sul ripiego condiviso in memoria, cosi' la schermata resta
    // utilizzabile in Mock.
    // L'azzeramento richiesto dall'operatore avviene **qui**, prima che
    // qualunque servizio apra l'archivio. Farlo mentre le connessioni sono
    // aperte - ogni servizio ne tiene una propria sullo stesso file SQLite -
    // lascerebbe meta' applicazione a scrivere su un archivio cancellato.
    // In Esercitazione: ricominciare se chiesto, poi caricare l'insieme
    // sintetico in un archivio vuoto, **prima** che i servizi lo aprano.
    if let lisi_services::run_mode::EstablishedMode::Exercise(testimone) = &modo {
        exercise::prepare(&window, testimone);
        exercise::seed_if_empty(&window, testimone, storage.open());
        exercise::wire(&window);
    } else {
        exercise::wire_launcher(&window);
    }
    outcomes::wire(&window);

    let continuity = account::data_root().and_then(|root| {
        let record = lisi_services::reset::apply_pending_reset(&root);
        if record.is_some() {
            tracing::info!("azzeramento dell'archivio eseguito all'avvio");
        }
        record
    });

    // LA LINGUA DELLA POSTAZIONE (I18N-01, ADR-0197). Dopo l'azzeramento,
    // prima che una schermata si componga. Si applica anche quando è
    // l'italiano: Slint sceglie da solo la lingua di Windows, se ne trova una
    // incorporata, e la scelta della postazione deve prevalere.
    let lingua_della_postazione = storage
        .open()
        .and_then(|database| database.interface_language().ok())
        .unwrap_or_default();
    lingua::applica(lingua_della_postazione);

    // La configurazione dell'applicazione arrivata con la distribuzione si
    // consuma prima di aprire gli account (APP-CREDENTIALS-01, ADR-0204).
    configurazione::importa(storage.open());
    let session = storage.open().map(account::create_service);

    // La prima riga del nuovo audit dichiara che cosa e' stato chiuso: quante
    // voci sono state archiviate e con quale impronta. E' cio' che tiene la
    // catena: se il file archiviato venisse distrutto, l'audit vivo
    // continuerebbe a dire che esisteva e che impronta aveva.
    if let (Some(record), Some(session)) = (continuity.as_ref(), session.as_ref()) {
        session.borrow().record_continuity(record);
    }

    // UN MONITORAGGIO CHE RISULTA IN CORSO ALL'AVVIO E' UN MONITORAGGIO
    // INTERROTTO, e il prodotto lo dice invece di continuare ad affermare che
    // sta osservando (ADR-0064).
    //
    // Il rilevamento sta QUI, dopo l'azzeramento e prima che una qualunque
    // schermata si componga: scoprirlo dopo significherebbe mostrare «In corso»
    // per un istante, e un istante basta a essere letto. Stava più in basso, e
    // il Cruscotto e il Monitoraggio, composti prima, contavano l'interrotto
    // fra quelli che ricevono: «In corso … man mano che arrivano» accanto
    // all'avviso dell'interruzione, e una frase che prometteva i messaggi
    // nuovi appena collegato l'account (BUG-UX-5, BUG-UX-6).
    //
    // MA NON IN ESERCITAZIONE (FINAL-REVIEW-01, FR-032). Lì l'autorità di
    // acquisire non esiste (ADR-0129): nulla acquisisce, quindi nulla può
    // essere interrotto. L'insieme sintetico ha un monitoraggio «in corso», e
    // fino al 2026-10-07 ogni primo avvio annunciava che era stato interrotto:
    // una frase falsa al primo contatto di chi si esercita.
    if !esercitazione_attiva {
        interruption::wire(&window, &mut storage);
    }
    // GLI ACCOUNT CHE IL SERVIZIO TENEVA (SERVICE-01, ADR-0203): la finestra li
    // riprende dalla sessione salvata, senza chiedere nulla.
    if let Some(session) = session.as_ref() {
        let ripresi = session
            .borrow_mut()
            .resume_linked(&interruption::accounts_to_resume());
        if ripresi > 0 {
            tracing::info!(ripresi, "account ripresi dal servizio in background");
        }
    }

    // Il timer che pompa gli eventi del connettore vive quanto `run()`, cioe'
    // quanto la finestra: un timer locale a un blocco piu' interno verrebbe
    // distrutto - e quindi fermato - alla fine di quel blocco (si veda la
    // documentazione di `slint::Timer`). Senza questo pompaggio periodico la
    // modalita' reale non apprende mai gli aggiornamenti di TDLib e resta
    // bloccata nello stato in cui l'avvio l'ha lasciata (incidente M3B del
    // 2026-07-26: la macchina di autorizzazione non avanzava mai oltre
    // "non ancora inizializzata", e il campo del numero non compariva).
    // Blocco della postazione. Lo stato vive quanto la finestra: riavviando, la
    // postazione non e' bloccata, perche' una serratura che chi riavvia il
    // programma apre non protegge nulla e in cambio chiuderebbe fuori chi ha
    // dimenticato la parola.
    // Lo stato si crea qui perche' il ciclo di pompaggio, poco sotto, deve
    // poterlo seguire; il collegamento dei comandi avviene invece **dopo** la
    // creazione del servizio delle impostazioni, che gli serve per l'audit.
    let lock_state = lock::create_state();
    // Il vassoio si installa PIU' TARDI, perche' gli serve l'handle nativo
    // della finestra, che non esiste ancora: lo scompartimento viene riempito
    // dalla stessa attesa che rende scura la barra del titolo, perche' le due
    // cose aspettano la stessa cosa e due attese avrebbero due cadenze.
    let tray_slot: Rc<RefCell<Option<tray::SharedTray>>> = Rc::new(RefCell::new(None));
    // La fascia di prontezza si ricontrolla quando un prerequisito cambia (F-08): il
    // ciclo periodico la trova qui, riempita piu' sotto quando il controllo nasce.
    let preflight_slot: Rc<RefCell<Option<preflight::SharedPreflight>>> =
        Rc::new(RefCell::new(None));
    // Anche il recupero si crea qui: la ricognizione avanza **una fonte per
    // volta** dallo stesso ciclo periodico, così la schermata può ridisegnarsi
    // fra un passo e l'altro e dire a che punto è. Eseguirla tutta dentro il
    // comando bloccherebbe l'interfaccia, e il messaggio d'attesa non
    // comparirebbe mai — perché la schermata non si ridisegna finché il comando
    // non è tornato.
    let recovery_screen = match (storage.open(), storage.open(), storage.open()) {
        (Some(first), Some(second), Some(third)) => recovery::create_service(first, second, third),
        _ => {
            tracing::warn!("recupero della cronologia non disponibile in questa esecuzione");
            None
        }
    };

    // Segnale che il pompaggio ha ingerito qualcosa.
    //
    // PERCHE' ESISTE. Il ciclo che pompa gli eventi del connettore ridisegna
    // Account, blocco e recupero, e **non** Storico, Monitoraggio e Notifiche:
    // quelle tre si ridisegnavano solo aprendole. Chi restava a guardare lo
    // Storico durante un monitoraggio vedeva numeri fermi mentre i contenuti
    // arrivavano davvero, e li trovava soltanto cambiando pagina e tornando
    // indietro. Non era un difetto visibile in un test: i servizi funzionavano,
    // l'archivio si popolava, e nessuno stava guardando.
    //
    // PERCHE' UN SEGNALE E NON UNA CHIAMATA DIRETTA. Quelle tre schermate
    // nascono piu' avanti in questa funzione, dopo il pompaggio: il pompaggio
    // non puo' chiamarle perche' quando viene scritto non esistono ancora. Il
    // segnale le disaccoppia, e in piu' evita di rileggere l'archivio a ogni
    // giro da 200 ms quando non e' arrivato nulla - che e' il caso normale.
    let fresh_content = Rc::new(std::cell::Cell::new(false));
    // Segnale che un monitoraggio si e' concluso per durata (E2E01-01). A
    // differenza di `fresh_content` ridisegna il Monitoraggio **qualunque sia
    // la pagina aperta**: e' quel ridisegno che riallinea la veglia della
    // postazione e il marchio animato, e non deve aspettare che qualcuno apra
    // la schermata (E2E01-22).
    let concluded_signal = Rc::new(std::cell::Cell::new(false));

    // Il timer si dichiara qui e si avvia in fondo, quando le schermate che
    // deve ridisegnare esistono. Dichiararlo dentro quel blocco lo farebbe
    // distruggere - e quindi fermare - alla fine del blocco stesso: e' lo
    // stesso motivo per cui il pompaggio vive qui e non piu' in basso.
    let live_refresh_timer = Timer::default();

    let account_pump_timer = Timer::default();
    // L'occasione al minuto della ricerca ricorrente E (ADR-0162): dichiarato
    // qui per la stessa ragione degli altri due, e avviato con la sua schermata.
    let recurring_timer = Timer::default();
    // Il controllo delle copie pianificate (BACKUP-SCHEDULE-01, ADR-0191):
    // dichiarato qui per la stessa ragione, e avviato con la firma.
    let backup_schedule_timer = Timer::default();
    if let Some(session) = session.as_ref() {
        // Prima del collegamento, cosi' la prima lettura della schermata lo mostra.
        session.borrow_mut().preselect_single_account();
        account::wire(&window, session);

        // Lo stesso pompaggio che fa avanzare l'accesso consegna anche i
        // contenuti all'acquisizione. Deve essere lo stesso, e non un secondo
        // ciclo: `poll_event` ha un solo consumatore per costruzione, perche'
        // due consumatori della stessa coda perderebbero eventi in silenzio
        // (si veda `crate::acquisition`).
        let mut acquisition = acquisition::create_service(
            storage.open(),
            storage.open(),
            storage.open(),
            storage.open(),
        )
        .map(|pump| {
            // IL LIVE CONDIVISO LO PRODUCE L'HUB, e soltanto lui (ADR-0093):
            // su una postazione Standalone o su un client il produttore non
            // esiste, e la tornata non pubblica nulla.
            let live = if team_live::questa_postazione_e_un_hub() {
                storage.open().map(HubLivePublisher::new)
            } else {
                None
            };
            pump.with_hub_live(live)
        })
        .or_else(|| {
            tracing::warn!("acquisizione non disponibile in questa esecuzione");
            None
        });

        let weak = window.as_weak();
        let pump_session = Rc::clone(session);
        let pump_lock = lock_state.clone();
        let pump_tray = Rc::clone(&tray_slot);
        let pump_recovery = recovery_screen.clone();
        let pump_fresh = Rc::clone(&fresh_content);
        let pump_concluded = Rc::clone(&concluded_signal);
        let pump_preflight = Rc::clone(&preflight_slot);
        let ultimo_accesso: std::cell::Cell<Option<bool>> = std::cell::Cell::new(None);
        // IL SEGNO DI VITA DELLA FINESTRA (SERVICE-01, ADR-0203): se la persona
        // esce da Windows, il servizio in background continua da qui.
        let pump_segno = storage.open();
        let ultimo_segno: std::cell::Cell<Option<std::time::Instant>> = std::cell::Cell::new(None);
        account_pump_timer.start(
            TimerMode::Repeated,
            std::time::Duration::from_millis(200),
            move || {
                let Some(window) = weak.upgrade() else {
                    return;
                };
                {
                    let mut session = pump_session.borrow_mut();
                    session.pump();
                    let adesso = account::now();
                    if let Some(acquisition) = acquisition.as_mut() {
                        // TUTTI GLI ACCOUNT APERTI, OGNUNO AI SUOI
                        // MONITORAGGI (ADR-0173). Anche con nessun account
                        // aperto si chiama: la durata scade lo stesso
                        // (E2E01-01), e un inizio in orario senza il suo
                        // account è mancato, e lo si dice (SCHEDULE-01).
                        let mut runtimes = session.runtimes_for_acquisition();
                        if acquisition.ingest_all(&mut runtimes, adesso) > 0 {
                            // Il numero era gia' calcolato e veniva buttato
                            // via. E' l'unico punto del programma che sa che
                            // l'archivio e' cambiato mentre qualcuno guardava.
                            pump_fresh.set(true);
                        }
                        if acquisition.take_concluded() {
                            pump_concluded.set(true);
                            pump_fresh.set(true);
                        }
                    }
                    if !esercitazione_attiva
                        && let Some(archivio) = pump_segno.as_ref()
                        && ultimo_segno.get().is_none_or(|prima| {
                            prima.elapsed().as_millis()
                                >= u128::from(
                                    lisi_core::model::background::HEARTBEAT_INTERVAL_MS
                                        .unsigned_abs(),
                                )
                        })
                    {
                        ultimo_segno.set(Some(std::time::Instant::now()));
                        if let Err(errore) = lisi_services::background::sign(
                            archivio,
                            lisi_core::model::background::Keeper::Window,
                            adesso,
                            &session.linked_live_accounts(),
                        ) {
                            tracing::warn!(kind = errore.kind(), "segno di vita non scritto");
                        }
                    }
                }
                account::refresh(&window, &pump_session, None);

                // L'ACCESSO E' CAMBIATO: la fascia si ricontrolla una volta (F-08).
                // Il primo giro registra soltanto lo stato di partenza: il controllo
                // dell'avvio parte comunque, poco dopo.
                let collegato = window.get_auth_authenticated();
                let prima = ultimo_accesso.replace(Some(collegato));
                if prima.is_some() && prima != Some(collegato) {
                    preflight::mark_stale();
                }
                if let Some(controllo) = pump_preflight.borrow().as_ref() {
                    preflight::run_if_stale(&window, controllo);
                }

                // Il blocco segue l'account attivo: e' la sua identita' che
                // decide quale parola sblocca. Il fatto mostrato a schermo
                // bloccato si ricompone qui, cosi' chi rientra legge un numero
                // aggiornato invece di quello di quando ha bloccato.
                if let Some(state) = pump_lock.as_ref() {
                    let uuid = account::active_account_uuid(&pump_session);
                    state.borrow_mut().set_account(uuid);
                    lock::refresh(&window, state);
                    lock::engage_if_idle(&window, state);
                    lock::refresh_fact(&window);
                }

                // Il vassoio si aggiorna DOPO il blocco, e dallo stesso giro:
                // cio' che mostra e' il fatto che la schermata di blocco ha
                // appena ricomposto, e leggerlo prima significherebbe mostrare
                // quello del giro precedente (ADR-0063).
                if let Some(state) = pump_tray.borrow().as_ref() {
                    tray::refresh(&window, state, pump_lock.as_ref());
                }

                if let Some(screen) = pump_recovery.as_ref()
                    && let Some(message) = recovery::advance(screen, &pump_session)
                {
                    recovery::refresh(&window, screen, Some(&message));
                }

                if let Some(screen) = pump_recovery.as_ref()
                    && let Some(message) = recovery::advance_search(screen, &pump_session)
                {
                    window.set_retro_message(SharedString::from(message));
                    recovery::refresh(&window, screen, None);
                }

                // Il recupero di un periodo deciso (PR-07): la lettura
                // preparata dal comando si esegue qui, al giro dopo, così la
                // schermata ha già detto che sta leggendo.
                if let Some(screen) = pump_recovery.as_ref()
                    && let Some(message) = recovery::advance_interval(screen, &pump_session)
                {
                    window.set_interval_message(SharedString::from(message));
                    recovery::refresh(&window, screen, None);
                }

                // Lo storico precedente all'avvio (PR-08): una pagina per giro,
                // così la schermata dice a che punto è e si può interrompere.
                if let Some(screen) = pump_recovery.as_ref()
                    && let Some(message) = recovery::advance_history(screen, &pump_session)
                {
                    window.set_prior_history_message(SharedString::from(message));
                    recovery::refresh(&window, screen, None);
                }

                // L'archiviazione confermata (E2E01-08): si esegue qui, al giro
                // dopo la conferma, così la schermata ha già detto che archivia.
                if let Some(screen) = pump_recovery.as_ref()
                    && let Some(message) = recovery::advance_history_apply(screen)
                {
                    window.set_prior_history_message(SharedString::from(message));
                    recovery::refresh(&window, screen, None);
                }
            },
        );
    } else {
        tracing::error!("servizio degli account non disponibile in questa esecuzione");
    }

    // La schermata Fonti usa lo stesso account autorizzato dell'accesso: elenca
    // le chat accessibili attraverso il runtime dell'account, senza un secondo
    // connettore che potrebbe divergere. L'archivio delle fonti e' una
    // connessione propria allo stesso archivio (reale o di ripiego): ogni
    // servizio apre la sua.
    // Il recupero legge la cronologia attraverso il connettore dell'account e
    // archivia passando dall'inbox durevole. I comandi si collegano qui; la
    // ricognizione la fa avanzare il ciclo periodico, poco sopra.
    if let Some(screen) = recovery_screen.as_ref() {
        recovery::wire(&window, screen);
        // I periodi decisi chiedono l'autorità di acquisizione, che vive con
        // la sessione dell'account: senza sessione il comando non si collega.
        if let Some(session) = session.as_ref() {
            recovery::wire_interval(&window, screen, session);
            recovery::wire_history(&window, screen, session);
        }
        recovery::refresh(&window, screen, Some(""));
    }

    // La ricerca puntuale (PR-09) chiede l'autorità e il connettore
    // dell'account: senza sessione il comando non si collega, e non parte nulla
    // da solo — la schermata ricarica soltanto il registro quando si apre.
    // Il collegamento di un «Trovato» a un soggetto (PR-10) usa i servizi dei
    // legami e delle persone, ciascuno con la sua connessione.
    if let (Some(archivio), Some(legami), Some(persone), Some(session)) = (
        storage.open(),
        storage.open(),
        storage.open(),
        session.as_ref(),
    ) {
        let screen = resolver::create_service(archivio, legami, persone);
        resolver::wire(&window, &screen, session);
        resolver::refresh(&window, &screen);
    } else {
        tracing::warn!("ricerca puntuale non disponibile in questa esecuzione");
    }

    // LA RICERCA NEI MESSAGGI, B, C E D (ADR-0154, ADR-0161): una connessione propria, e i
    // comandi si collegano soltanto con la sessione dell'account.
    if let (Some(archivio), Some(session)) = (storage.open(), session.as_ref()) {
        let screen = cyber_search::create_service(archivio);
        cyber_search::wire(&window, &screen, session);
    }

    // LA RICERCA SU PIÙ RAMI (ADR-0163): due connessioni proprie, una per lo
    // Storico, e il comando si collega soltanto con la sessione dell'account.
    if let (Some(archivio), Some(storico), Some(session)) =
        (storage.open(), storage.open(), session.as_ref())
    {
        let screen = cross_search::create_service(archivio, storico);
        cross_search::wire(&window, &screen, session);
    }

    // LA RICERCA RICORRENTE E (ADR-0162): una connessione propria, e il timer
    // si avvia soltanto con la sessione dell'account.
    if let (Some(archivio), Some(session)) = (storage.open(), session.as_ref()) {
        let screen = cyber_recurring::create_service(archivio);
        cyber_recurring::wire(&window, &screen);
        cyber_recurring::refresh(&window, &screen);
        cyber_recurring::start(&recurring_timer, &window, &screen, session);
    }

    // L'ACCOUNT D'UFFICIO SECONDO TELEGRAM (ADR-0153): una connessione propria,
    // e il comando si collega soltanto con la sessione dell'account.
    if let (Some(archivio), Some(session)) = (storage.open(), session.as_ref()) {
        let archivio = std::rc::Rc::new(std::cell::RefCell::new(archivio));
        office_account::wire(&window, &archivio, session);
        office_account::refresh(&window, &archivio);
    }

    // I riferimenti informatici (PR-14, ADR-0130): STIX, ATT&CK, CVE e KEV,
    // sopra i servizi della Fase 8. Nessuna richiesta a Telegram e nessuna
    // rete: importano file locali e leggono l'archivio.
    if let Some(screen) = references::create_service(storage.open()) {
        references::wire(&window, &screen);
    } else {
        tracing::warn!("riferimenti informatici non disponibili in questa esecuzione");
    }

    // L'elenco delle persone si ricava dall'archivio: nessuna richiesta a
    // Telegram, quindi nessun connettore. Serve solo una connessione propria.
    if let Some(service) = participants::create_service(
        storage.open(),
        storage.open(),
        storage.open(),
        storage.open(),
    ) {
        participants::wire(&window, &service);
    } else {
        tracing::warn!("elenco delle persone non disponibile in questa esecuzione");
    }

    // La scheda «Foto, biografia e stato» (PERSON-MEDIA-01, ADR-0174): una
    // connessione propria; la richiesta chiede l'autorità e il connettore
    // dell'account, e senza sessione lo dice invece di tacere.
    if let Some(screen) = profile_media::create_service(storage.open()) {
        profile_media::wire(&window, &screen, session.as_ref());
    } else {
        tracing::warn!("scheda del profilo non disponibile in questa esecuzione");
    }
    // Gli iscritti delle fonti (MEMBERS-01, ADR-0201): un archivio suo; la
    // richiesta chiede l'autorità e il connettore dell'account.
    members::install(storage.open());
    members::wire(&window, session.as_ref());
    members::refresh(&window);
    // La risoluzione degli indicatori dal PC (IOC-RESOLVE-01, ADR-0202): un
    // archivio suo; la richiesta parte dal risolutore di Windows.
    ioc_resolve::install(storage.open());
    ioc_resolve::wire(&window);
    ioc_resolve::refresh(&window);
    // Il WHOIS dal PC (WHOIS-01, ADR-0205): un archivio suo; la richiesta parte
    // da WinHTTP o dalla porta 43, verso i registri che indica IANA.
    registrazione::install(storage.open());
    registrazione::wire(&window);
    registrazione::refresh(&window);
    // Il monitoraggio con Windows chiuso (SERVICE-01, ADR-0203): lo stato lo
    // dice Windows, i passaggi di mano l'archivio.
    servizio_stato::install(storage.open());
    servizio_stato::wire(&window);
    servizio_stato::refresh(&window);
    // LA SCHEDA «CONSERVARE L'ALLEGATO» (ATTACH-01, ADR-0177), come quella del
    // profilo: connessione propria, autorità e connettore dell'account.
    if let Some(screen) = attachment::create_service(storage.open()) {
        attachment::wire(&window, &screen, session.as_ref());
    } else {
        tracing::warn!("scheda dell'allegato non disponibile in questa esecuzione");
    }

    let source_service = storage.open().and_then(sources::create_service);
    // La salute delle fonti ha un archivio proprio: SCRIVE le osservazioni, e
    // scrivere vuole l'archivio senza contenderlo a chi compone l'elenco.
    let health_service = storage.open().and_then(sources::create_health_service);
    if health_service.is_none() {
        tracing::warn!("salute delle fonti non disponibile in questa esecuzione");
    }
    if let (Some(service), Some(session)) = (source_service.as_ref(), session.as_ref()) {
        sources::wire(&window, service, health_service.as_ref(), session);
        sources::refresh(&window, service, health_service.as_ref(), session, None);
    } else {
        tracing::warn!("configurazione delle fonti non disponibile in questa esecuzione");
    }

    // I SUGGERIMENTI DI FONTI DALL'ARCHIVIO (ADR-0164): due connessioni proprie,
    // e l'aggiunta passa dalla stessa strada della pagina Fonti.
    if let (Some(service), Some(session), Some(decisioni), Some(storico)) = (
        source_service.as_ref(),
        session.as_ref(),
        storage.open(),
        storage.open(),
    ) {
        let screen = source_suggestion::create_service(decisioni, storico);
        source_suggestion::wire(&window, &screen, service, health_service.as_ref(), session);
        source_suggestion::refresh(&window, &screen);
    }

    // L'AFFIDABILITÀ DELLE FONTI, A MANO (ADR-0167): una connessione propria.
    if let Some(archivio) = storage.open() {
        let screen = source_reliability::create_service(archivio);
        source_reliability::wire(&window, &screen);
        source_reliability::refresh(&window, &screen);
    }

    // Il centro diagnostico ha un archivio proprio, come ogni altro servizio:
    // legge gli account, l'ultima copia di sicurezza e la dimensione
    // dell'archivio, e non deve contendere la connessione a chi scrive.
    //
    // La salute delle fonti gli arriva GIA' COMPOSTA dal servizio che la
    // compone: ricomporla qui creerebbe una seconda derivazione, e la
    // diagnostica potrebbe dire delle fonti una cosa diversa da quella che la
    // schermata Fonti dice nello stesso istante (DEC-252).
    let diagnostics_service = storage.open().and_then(diagnostics::create_service);
    if let Some(service) = diagnostics_service.as_ref() {
        diagnostics::wire(&window, service, health_service.as_ref());
        diagnostics::refresh(&window, service, health_service.as_ref());
    } else {
        tracing::warn!("centro diagnostico non disponibile in questa esecuzione");
    }

    // La coda di lavoro attraversa tutte le sessioni: ha bisogno di una
    // connessione propria perche' compone mentre altre schermate scrivono.
    let queue_service = storage.open().and_then(work_queue::create_service);
    if let Some(service) = queue_service.as_ref() {
        work_queue::wire(&window, service);
        work_queue::refresh(&window, service);
    } else {
        tracing::warn!("coda di lavoro non disponibile in questa esecuzione");
    }

    // IL RULE LAB. Tre connessioni: una per i dizionari, una per i contenuti,
    // una per le decisioni delle persone (FEEDBACK-01).
    //
    // Ne' il confronto ne' l'aggregazione del riscontro ne ricevono alcuna:
    // non conoscono l'archivio, e non possono scrivere perche' non hanno con
    // che cosa (LAB-01 DEC-258, FEEDBACK-01 DEC-262).
    if let Some(service) = storage
        .open()
        .zip(storage.open())
        .zip(storage.open())
        .and_then(|((dizionari, contenuti), revisioni)| {
            rule_lab::create_service(dizionari, contenuti, revisioni)
        })
    {
        rule_lab::wire(&window, &service);
        rule_lab::refresh(&window, &service);
    } else {
        tracing::warn!("Rule Lab non disponibile in questa esecuzione");
    }

    // IL CRUSCOTTO. Non compone alcuna risposta: le raccoglie dai servizi che
    // le compongono gia'. La connessione propria gli serve per i soli due
    // conteggi che nessun altro fa — i contenuti recenti e i grappoli delle
    // sessioni attive di recente.
    let dashboard_database = storage.open().and_then(dashboard::create_service);
    dashboard::wire(
        &window,
        health_service.as_ref(),
        queue_service.as_ref(),
        diagnostics_service.as_ref(),
        dashboard_database.as_ref(),
    );
    dashboard::refresh(
        &window,
        &dashboard::Sources {
            health: health_service.as_ref(),
            queue: queue_service.as_ref(),
            diagnostics: diagnostics_service.as_ref(),
            database: dashboard_database.as_ref(),
        },
    );

    // Le tre schermate che l'acquisizione fa cambiare vivono oltre il blocco
    // che le crea: il ciclo di aggiornamento dal vivo, in fondo a questa
    // funzione, deve poterle ridisegnare quando arriva un contenuto.
    let mut monitoring_screen = None;
    let mut history_screens = None;
    let mut notification_screen = None;
    // Persone: la scheda dei soggetti segue le acquisizioni mentre la si guarda
    // (CA02-01).
    let mut person_screen = None;

    // Il tour guidato legge la modalita' dal servizio dei dizionari, che la
    // possiede: l'interfaccia non la ricava da se' (TOUR-01, ADR-0134 §12).
    let mut dizionari_per_il_tour: Option<dictionaries::SharedDictionaries> = None;
    // La procedura guidata serve anche ai Modelli, che la compilano (F-07).
    let mut composizione_del_wizard: Option<wizard::SharedWizard> = None;

    // La libreria dei dizionari non dipende dall'accesso: si compone e si
    // rivede anche senza un account configurato, ed e' bene che sia cosi'.
    if let Some(dictionary_service) = storage.open().and_then(dictionaries::create_service) {
        dictionaries::wire(&window, &dictionary_service);
        dictionaries::refresh(&window, &dictionary_service, None);
        dizionari_per_il_tour = Some(Rc::clone(&dictionary_service));

        // Il wizard attinge a entrambi: le fonti da monitorare e i dizionari
        // con cui farlo. Vive quanto la finestra, cosi' che tornando alla
        // pagina si ritrovi la composizione lasciata a meta'.
        let composition = wizard::create();
        composizione_del_wizard = Some(Rc::clone(&composition));
        wizard::wire(
            &window,
            &composition,
            &dictionary_service,
            source_service.as_ref(),
        );
        wizard::refresh(
            &window,
            &composition,
            &dictionary_service,
            source_service.as_ref(),
            None,
        );

        // Il monitoraggio parte dalla composizione del wizard: e' il wizard a
        // comporre fonti e termini, e il monitoraggio a metterli in corso e a
        // mostrarne lo stato. Vive quanto la composizione da cui dipende.
        if let Some(monitoring) = storage.open().and_then(monitoring::create_service) {
            monitoring::wire(&window, &monitoring, &composition, session.as_ref());
            monitoring::refresh(&window, &monitoring, None);
            monitoring_screen = Some(monitoring);
        } else {
            tracing::warn!("monitoraggio non disponibile in questa esecuzione");
        }
    } else {
        tracing::warn!("libreria dei dizionari non disponibile in questa esecuzione");
    }

    // Storico e Alert leggono lo stesso archivio dei servizi precedenti: sono
    // la parte visibile del motore di analisi, e senza di esse un contenuto
    // registrato non lo vedrebbe nessuno.
    // Il sesto archivio e' quello del percorso del risultato: legge soltanto,
    // ma i servizi non condividono una connessione, e leggere la spiegazione
    // mentre lo Storico compone l'elenco non deve contendere la stessa.
    if let Some(screens) = history::create_service(
        storage.open(),
        storage.open(),
        storage.open(),
        storage.open(),
        storage.open(),
        storage.open(),
    ) {
        history::wire(&window, &screens, session.as_ref());
        // La pagina della conversazione (ADR-0151) legge gli stessi archivi:
        // la prova e le fotografie stanno dove lo Storico le trova.
        conversation::wire(&window, &screens, session.as_ref());
        // Dall'autore al soggetto (GAP-12): due comandi che portano a Persone.
        author_subject::wire(&window);
        history::refresh(&window, &screens, None);
        // Cyber Watch legge gli stessi servizi: un grappolo si compone dai
        // contenuti di una sessione, che sono gli stessi che lo Storico mostra.
        // Aprire un sesto archivio per rileggere le stesse righe non
        // aggiungerebbe nulla se non un'altra connessione da tenere allineata.
        cyber::wire(&window, &screens);
        graph::wire(&window, &screens);
        history_screens = Some(screens);
    } else {
        tracing::warn!("storico non disponibile in questa esecuzione");
    }

    // «Perché vedo questo?» (PR-02) e il pannello di PROV-02 a cui porta. Non
    // dipendono dallo Storico: la tendenza, il grafo e la coda di lavoro si
    // spiegano con ciò che la loro schermata sta già mostrando.
    why_subject::wire(&window);
    explain::wire(&window);

    // La scoperta pubblica legge un archivio proprio perche' RILEGGE SOLTANTO:
    // non scrive, non registra nulla nell'audit e non esegue niente. Prestarle
    // una connessione condivisa con chi scrive non aggiungerebbe una capacita',
    // aggiungerebbe soltanto una contesa.
    //
    // E non c'e' un servizio che cerchi: non puo' esistere finche' non esiste
    // una politica validata, e la schermata lo dichiara invece di tacerlo
    // (ADR-0079).
    //
    // E LE DECISIONI HANNO UN ARCHIVIO LORO, perche' SCRIVONO: audit, riga di
    // decisione e - per «Aggiungi» - una fonte nuova. Aggiungere la scrittura
    // dove c'era la lettura avrebbe reso falsa la guardia che verifica che il
    // servizio di rilettura non scriva, senza che nessuna prova lo dicesse
    // (ADR-0080).
    match (storage.open(), storage.open()) {
        (Some(per_rileggere), Some(per_decidere)) => {
            let scoperte = discovery::create_service(per_rileggere);
            let decisioni = discovery::create_decision_service(per_decidere);
            discovery::wire(&window, &scoperte, &decisioni);
            discovery::refresh(&window, &scoperte);
        }
        _ => {
            tracing::warn!("scoperte pubbliche non disponibili in questa esecuzione");
        }
    }

    // Le organizzazioni sorvegliate hanno un archivio proprio perche' la
    // dichiarazione SCRIVE, e scrivere vuole l'archivio mutabile: condividerlo
    // con i servizi in sola lettura significherebbe prestarlo mutabile a tutti.
    //
    // Senza questa sezione la regola che assegna un settore sarebbe una
    // capacita' costruita e mai raggiungibile — il difetto che CY-01 esisteva
    // per chiudere, e che questo progetto ha gia' ricreato una volta.
    // I workspace hanno un archivio proprio per la stessa ragione delle
    // organizzazioni: aprire, raccogliere e chiudere SCRIVONO, e scrivere vuole
    // l'archivio mutabile.
    //
    // Senza questa sezione tutto WS-01 sarebbe una capacita' costruita e mai
    // raggiungibile â il debito che WS-01 stesso aveva dichiarato da chiudere
    // subito.
    if let Some(workspaces) = storage.open().and_then(workspace::create_service) {
        workspace::wire(&window, &workspaces);
        workspace::refresh(&window, &workspaces);
    } else {
        tracing::warn!("workspace non collegati: archivio non disponibile");
    }

    // Il pacchetto di evidenze (PR-11) vuole l'autorità di acquisizione, che
    // vive con la sessione dell'account: chi ha i fatti produce i documenti.
    if let (Some(lettura), Some(scrittura), Some(session)) =
        (storage.open(), storage.open(), session.as_ref())
    {
        let screen = evidence::create_service(lettura, scrittura);
        evidence::wire(&window, &screen, session);
        evidence::refresh(&window, &screen);
    } else {
        tracing::warn!("pacchetto di evidenze non collegato in questa esecuzione");
    }

    // Il passaggio di consegne (PR-12) legge l'archivio e registra ogni foglio
    // esportato: si compone soltanto quando l'operatore lo chiede.
    if let Some(archivio) = storage.open() {
        let screen = handover::create_service(archivio);
        handover::wire(&window, &screen);
    } else {
        tracing::warn!("passaggio di consegne non collegato: archivio non disponibile");
    }

    // I segnalibri hanno un archivio proprio per la stessa ragione: segnare,
    // spostare e togliere SCRIVONO.
    //
    // Senza questa sezione tutto BOOK-01 sarebbe una capacita' costruita e mai
    // raggiungibile, e in particolare il comando «Segna» dello Storico non
    // farebbe nulla: la lezione di LAB-01, ricreata.
    let bookmarks = storage.open().and_then(bookmark::create_service);
    if let Some(bookmarks) = bookmarks.as_ref() {
        bookmark::wire(&window, bookmarks);
        bookmark::refresh(&window, bookmarks);
    } else {
        tracing::warn!("segnalibri non collegati: archivio non disponibile");
    }

    // Le note hanno un archivio proprio per la stessa ragione: scrivere e
    // ritirare SCRIVONO.
    //
    // Senza questa sezione il pannello delle note comparirebbe vuoto e i suoi
    // comandi non farebbero nulla: una capacita' costruita e mai raggiungibile.
    let notes = storage.open().and_then(note::create_service);
    if let Some(notes) = notes.as_ref() {
        note::wire(&window, notes);
        note::refresh(&window, notes);
    } else {
        tracing::warn!("note non collegate: archivio non disponibile");
    }

    // I MODELLI HANNO UN ARCHIVIO PROPRIO (TEMPLATE-01).
    //
    // Crearli e cancellarli SCRIVONO. Applicarli no — e la funzione che li
    // applica non prende nemmeno l'archivio mutabile: e' la garanzia che un
    // gesto che sembra «preparare un monitoraggio» non riconfiguri la
    // postazione.
    if let Some(templates) = storage.open().and_then(monitoring_template::create_service) {
        monitoring_template::wire(
            &window,
            &templates,
            &monitoring_template::TemplateContext {
                sources: source_service.clone(),
                dictionaries: dizionari_per_il_tour.clone(),
                wizard: composizione_del_wizard.clone(),
            },
        );
        monitoring_template::refresh(&window, &templates);
    } else {
        tracing::warn!("modelli di monitoraggio non collegati: archivio non disponibile");
    }

    // I SOGGETTI HANNO UN ARCHIVIO PROPRIO (PERS-01).
    //
    // Aprire e chiudere SCRIVONO. Il servizio non ha alcun modo di raggiungere
    // le osservazioni: nessun soggetto nasce da una riga di un elenco.
    // I QUATTRO ARCHIVI DEL FASCICOLO (PERS-07) si aprono prima: comporre un
    // fascicolo legge i legami, le associazioni, le cronologie e le sessioni, e
    // ciascuna lettura vuole la sua connessione.
    let fascicolo = match (
        storage.open(),
        storage.open(),
        storage.open(),
        storage.open(),
    ) {
        (Some(uno), Some(due), Some(tre), Some(quattro)) => Some([uno, due, tre, quattro]),
        _ => None,
    };
    if let Some(persons) = storage.open().and_then(|db| {
        person::create_service(
            db,
            storage.open(),
            storage.open(),
            fascicolo,
            storage.open(),
        )
    }) {
        person::wire(&window, &persons);
        person::refresh(&window, &persons);
        person_screen = Some(persons);
    } else {
        tracing::warn!("soggetti non collegati: archivio non disponibile");
    }

    // LE RICERCHE SALVATE HANNO DUE ARCHIVI (SEARCH-01).
    //
    // Uno per scrivere — salvare e cancellare una ricerca — e uno per
    // rieseguirla, che LEGGE lo storico. E' la stessa disciplina di tutto il
    // resto: un servizio che scrive e uno che legge non si prestano la stessa
    // connessione.
    //
    // Senza lo Storico collegato non c'e' dove rifare una ricerca, e questa
    // sezione non fa nulla: meglio non offrirla che offrirla inerte.
    if let Some(history) = history_screens.as_ref() {
        if let Some(searches) = saved_search::create_service(storage.open(), storage.open()) {
            saved_search::wire(&window, &searches, history);
            saved_search::refresh(&window, &searches);
        } else {
            tracing::warn!("ricerche salvate non collegate: archivio non disponibile");
        }
    } else {
        tracing::warn!("ricerche salvate non collegate: storico non disponibile");
    }

    // SCEGLIERE UNA RIGA DELLO STORICO FA DUE DOMANDE, E QUI SI COMPONGONO.
    //
    // «E' gia' segnata?» la sa rispondere il modulo dei segnalibri; «che cosa
    // ci hanno annotato?» quello delle note. In Slint un callback ha UN
    // gestore solo: se ciascun modulo registrasse il suo, il secondo
    // sostituirebbe il primo **in silenzio** — e uno dei due pannelli
    // continuerebbe a mostrare la riga precedente senza che nulla lo dica.
    //
    // Percio' la composizione sta qui, dove entrambi i servizi sono noti, e
    // non dentro un modulo che dovrebbe conoscere l'altro.
    {
        let handle = window.as_weak();
        let bookmarks = bookmarks.clone();
        let notes = notes.clone();
        window.on_history_content_chosen(move |content_id| {
            if crate::lock::refuse_while_locked("history_content_chosen") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            if let Some(bookmarks) = bookmarks.as_ref() {
                bookmark::refresh_content_mark(&window, bookmarks, content_id);
            }
            if let Some(notes) = notes.as_ref() {
                note::refresh_content(&window, notes, content_id);
            }
        });
    }

    if let Some(organisations) = storage.open().and_then(organisations::create_service) {
        organisations::wire(&window, &organisations);
        organisations::refresh(&window, &organisations, None);
    } else {
        tracing::warn!("organizzazioni sorvegliate non collegate: archivio non disponibile");
    }

    // Le impostazioni delle notifiche vivono nell'archivio (DEC-103): la
    // schermata le legge e le salva. Il motore che le consuma durante
    // l'acquisizione dal vivo arriverà con M3B.
    // La conservazione ha un archivio suo perche' applicarla CANCELLA, e
    // cancellare vuole l'archivio in scrittura: condividerlo con i servizi in
    // sola lettura significherebbe prestarlo mutabile a tutti.
    // Il fascicolo condivisibile ha un archivio suo perche' l'importazione
    // scrive, e deve poterlo fare senza contendere con i servizi in lettura.
    // In Esercitazione nulla dell'Hub e nessun fascicolo condiviso: sarebbe un
    // passaggio di dati fra i due mondi (PR-13, ADR-0129).
    if esercitazione_attiva {
        tracing::info!("esercitazione: configurazione condivisa non collegata");
    } else if let Some(team) = storage.open().and_then(team::create_service) {
        team::wire(&window, &team);
    } else {
        tracing::warn!("configurazione condivisa non collegata: archivio non disponibile");
    }

    if let Some(retention) = storage.open().and_then(retention::create_service) {
        retention::wire(&window, &retention);
        retention::refresh(&window, &retention, None);
    } else {
        tracing::warn!("conservazione non collegata: archivio non disponibile");
    }

    // La copia di sicurezza ha un archivio suo perche' registra nell'audit che
    // e' stata prodotta, e registrare scrive: condividere l'archivio con i
    // servizi in sola lettura significherebbe prestarlo mutabile a tutti.
    // La firma dell'ufficio ha un archivio suo: scrive il registro delle
    // firme e l'audit, e la usano il Report, i Dizionari e Impostazioni
    // (SIGN-01 parte 4, DEC-465).
    signing::install(storage.open());
    // La copia cifrata per chi riceve ha un archivio suo, per la stessa
    // ragione: scrive il registro delle copie e l'audit (ENCRYPT-02).
    recipient_copy::install(storage.open());
    signing::wire(&window);
    signing::refresh(&window);
    // Le copie pianificate hanno un archivio loro: scrivono il registro dei
    // tentativi e l'audit (BACKUP-SCHEDULE-01, ADR-0191).
    backup_schedule::install(storage.open());
    // Il registro delle consultazioni ha un archivio suo (AUDIT-VIEW-01,
    // ADR-0193): all'avvio toglie le righe oltre la conservazione.
    consultations::install(storage.open());
    consultations::wire(&window);
    consultations::refresh(&window);
    backup_schedule::wire(&window);
    backup_schedule::refresh(&window);
    {
        let handle = window.as_weak();
        backup_schedule_timer.start(
            slint::TimerMode::Repeated,
            backup_schedule::CHECK_EVERY,
            move || {
                if let Some(window) = handle.upgrade() {
                    backup_schedule::tick(&window);
                }
            },
        );
    }

    if let Some(backup) = storage.open().and_then(backup::create_service) {
        backup::wire(&window, &backup);
    } else {
        tracing::warn!("copia di sicurezza non collegata: archivio non disponibile");
    }

    // L'esame di un aggiornamento ha un archivio suo perche' registra
    // nell'audit che e' stato esaminato, e registrare scrive.
    // Il servizio sopravvive al blocco perche' la schermata ne ha bisogno due
    // volte: per collegare i comandi e per leggere il canale della postazione.
    let update_service = storage.open().and_then(update::create_service);
    if let Some(update) = update_service.as_ref() {
        update::wire(&window, update);
    } else {
        tracing::warn!("esame degli aggiornamenti non collegato: archivio non disponibile");
    }
    // La riga della postazione si scrive comunque: senza archivio il canale non
    // si legge, e la schermata dice cio' che sa invece di inventarlo.
    update::refresh(&window, update_service.as_ref());

    let settings_service = storage.open().and_then(settings::create_service);
    if let Some(settings) = settings_service.as_ref() {
        settings::wire(&window, settings);
        settings::refresh(&window, settings, None);
    } else {
        tracing::warn!("impostazioni non disponibili in questa esecuzione");
    }

    // IL BLOCCO SI COLLEGA SEMPRE (OPERATOR-E2E-REMEDIATION-01, F-01). Si
    // collegava solo con il servizio delle impostazioni, che porta l'audit del
    // cambio di parola: senza archivio la postazione si bloccava da sola per
    // inattivita' e «Sblocca» non faceva nulla. Ora sblocco, blocco e segnale
    // di attivita' ci sono sempre; senza archivio non si cambia soltanto la
    // parola, perche' quel cambio va registrato.
    if let Some(state) = lock_state.as_ref() {
        lock::wire(&window, state, settings_service.as_ref());
        lock::refresh(&window, state);
    }

    // La schermata Verifica elenca ogni rapporto esportato con il suo verdetto
    // (DEC-104). Riusa il servizio di esportazione, che sa già verificare i
    // manifest; qui possiede la propria connessione, e da qui parte anche la
    // scorciatoia «Verifica esportati» della schermata Storico.
    if let Some(verification) = storage.open().and_then(verification::create_service) {
        verification::wire(&window, &verification);
    } else {
        tracing::warn!("verifica non disponibile in questa esecuzione");
    }

    // La schermata Report è il **solo** punto da cui il sottosistema del
    // reporting si raggiunge: senza questa riga il generatore `.docx` esiste,
    // è collaudato e non entra nemmeno nel binario, perché il linker scarta ciò
    // che non si raggiunge. È stato il caso per tutta MP-18C e MP-18F, ed era
    // dichiarato; qui smette di esserlo.
    if let Some(reports) = report::create_service(storage.open(), storage.open()) {
        report::wire(&window, &reports);
        recipient_copy::wire(&window, &reports);
        if let Some(session) = session.as_ref() {
            report::attach_session(&reports, session);
        }
        // Il profilo documentale si porta a schermo **prima** del resto: da
        // esso dipende se la Dashboard mostri il benvenuto del primo avvio.
        report::refresh_profile(&window, &reports, Some(""));
        // I dati dell'ufficio entrano nei campi della relazione: è il punto
        // della conservazione, e l'operatore li ritocca solo se vuole.
        report::publish_fields(&window, &reports);
        report::refresh(&window, &reports, Some(""));
    } else {
        tracing::warn!("schermata Report non disponibile in questa esecuzione");
    }

    // Il centro notifiche elenca le notifiche emesse (DEC-105). È di sola
    // lettura; dal 2026-07-31 si popola davvero, perché il ciclo di
    // acquisizione sottopone al motore ogni contenuto appena ingerito
    // (`crate::acquisition::AcquisitionPump::notify`).
    // La revisione condivisa: una connessione propria per il recupero che
    // scrive il cursore (TEAM-REVIEW-01).
    // L'ACCESSO E' UNO SOLO, e lo condividono le schermate che ne hanno
    // bisogno: due accessi vorrebbero dire entrare due volte per fare due cose
    // dello stesso lavoro (TEAM-WS-01, ADR-0097 decisione 6).
    let accesso = accesso::Accesso::new();

    if esercitazione_attiva {
        tracing::info!("esercitazione: revisione condivisa non collegata");
    } else if let Some(team_review) =
        team_review::create_service(storage.open(), storage.open(), &accesso)
    {
        team_review::wire(&window, &team_review);
        team_review::refresh(&window, &team_review);
    } else {
        tracing::warn!("revisione condivisa non disponibile in questa esecuzione");
    }

    // I raccoglitori dell'ufficio: una connessione propria, letture brevi
    // (TEAM-WS-01).
    if esercitazione_attiva {
        tracing::info!("esercitazione: raccoglitori dell'ufficio non collegati");
    } else if let Some(team_shared) = team_shared::create_service(storage.open(), &accesso) {
        team_shared::wire(&window, &team_shared);
        team_shared::refresh(&window, &team_shared);
    } else {
        tracing::warn!("raccoglitori dell'ufficio non disponibili in questa esecuzione");
    }

    // Il live condiviso: due connessioni proprie, una per la proiezione che si
    // mostra e una per il recupero che scrive il cursore (TEAM-LIVE-01).
    if esercitazione_attiva {
        tracing::info!("esercitazione: live condiviso e Hub non collegati");
    } else if let (Some(team_live), Some(session)) = (
        team_live::create_service(
            storage.open(),
            storage.open(),
            storage.open(),
            storage.open(),
        ),
        session.as_ref(),
    ) {
        // La sessione dell'account serve al collegamento all'Hub: una postazione
        // ammessa rinuncia subito all'autorità di acquisire (FR-003).
        team_live::wire(&window, &team_live, session);
        team_live::refresh(&window, &team_live);
    } else {
        tracing::warn!("live condiviso non disponibile in questa esecuzione");
    }

    if let Some(notifications) = storage.open().and_then(notification_center::create_service) {
        notification_center::wire(&window, &notifications);
        notification_center::refresh(&window, &notifications);
        notification_screen = Some(notifications);
    } else {
        tracing::warn!("centro notifiche non disponibile in questa esecuzione");
    }

    // ------------------------------------------------- aggiornamento dal vivo
    //
    // Ridisegna Storico, Monitoraggio, Notifiche e Persone quando il pompaggio ha
    // ingerito qualcosa, e **solo allora**: se non arriva nulla - il caso
    // normale - non tocca l'archivio.
    //
    // Un secondo, non duecento millisecondi come il pompaggio: qui si rileggono
    // tre schermate dall'archivio, e farlo cinque volte al secondo
    // consumerebbe la postazione per mostrare numeri che cambiano molto piu'
    // lentamente di cosi'. Un secondo e' gia' immediato per chi guarda.
    {
        let weak = window.as_weak();
        let fresh = Rc::clone(&fresh_content);
        let concluded = Rc::clone(&concluded_signal);
        let monitoring = monitoring_screen.clone();
        let screens = history_screens.clone();
        let notifications = notification_screen.clone();
        let persons = person_screen.clone();

        live_refresh_timer.start(
            TimerMode::Repeated,
            std::time::Duration::from_millis(1000),
            move || {
                // `replace` e non `get` + `set`: fra le due letture il
                // pompaggio potrebbe alzare di nuovo il segnale, e quel
                // contenuto resterebbe fuori dal prossimo giro.
                //
                // Anche cio' che entra per un comando (E2E01-05): si ritirano
                // entrambi i segnali, senza cortocircuito, perche' uno lasciato
                // alzato farebbe un ridisegno in piu' al giro dopo.
                let pompato = fresh.replace(false);
                let comandato = freshness::take();
                if !pompato && !comandato {
                    return;
                }

                let Some(window) = weak.upgrade() else {
                    return;
                };

                // UN MONITORAGGIO CONCLUSO PER DURATA si ridisegna sempre
                // (E2E01-01, E2E01-22): la veglia della postazione e il
                // marchio seguono il ridisegno del Monitoraggio, e chi sta
                // sullo Storico non deve tenere sveglia la macchina.
                if concluded.replace(false)
                    && window.get_current_page() != 9
                    && let Some(monitoring) = monitoring.as_ref()
                {
                    monitoring::refresh(&window, monitoring, None);
                }

                // Nessun messaggio: chi guarda non ha chiesto niente, e un
                // riscontro che compare da solo verrebbe letto come la
                // risposta a un comando che non e' stato dato.
                //
                // SOLO LA SCHERMATA CHE SI GUARDA (FINAL-REVIEW-01, FR-035).
                // Fino al 2026-10-07 si rileggevano tutte e tre a ogni secondo
                // di acquisizione, anche chiuse: lo Storico in «Tutte le
                // sessioni» carica ogni contenuto con il suo testo, e su un
                // archivio grande la finestra si fermava proprio mentre il
                // monitoraggio era vivo. Le altre si ridisegnano quando si
                // aprono: ognuna ha il suo `*-shown`.
                match window.get_current_page() {
                    7 | 8 => {
                        if let Some(screens) = screens.as_ref() {
                            history::refresh(&window, screens, None);
                        }
                    }
                    9 => {
                        if let Some(monitoring) = monitoring.as_ref() {
                            monitoring::refresh(&window, monitoring, None);
                        }
                    }
                    14 => {
                        if let Some(persons) = persons.as_ref() {
                            person::refresh(&window, persons);
                        }
                    }
                    13 => {
                        if let Some(notifications) = notifications.as_ref() {
                            notification_center::refresh(&window, notifications);
                        }
                    }
                    _ => {}
                }
            },
        );
    }

    // L'apertura sicura degli URL (ADR-0018): lo storico e il centro notifiche
    // vi passano l'URL, il servizio lo valida, lo apre nel browser e lo registra.
    if let Some(links) = storage.open().and_then(links::create_service) {
        links::wire(&window, &links);
    } else {
        tracing::warn!("apertura dei collegamenti non disponibile in questa esecuzione");
    }

    // Un solo avviso, mostrato una volta sola a fine avvio se almeno un
    // servizio ha dovuto usare il ripiego condiviso in memoria: nessun
    // percorso, nessun errore tecnico, solo cio' che serve all'operatore.
    // **PERCHE' si e' ripiegato, non solo CHE si e' ripiegato.**
    //
    // Il 2026-08-18 l'archivio dell'operatore non si apriva: ventidue
    // fallimenti per avvio, ripiego silenzioso in memoria, e tutto perduto
    // alla chiusura. La causa erano i permessi sulla cartella dati, e ci sono
    // volute ore per arrivarci perche' il prodotto non lo diceva: falliva
    // ventidue volte, ognuna con un messaggio tecnico diverso, e nessuno di
    // quei messaggi diceva «non posso scrivere qui».
    //
    // La verifica si esegue **soltanto quando il ripiego e' scattato**: e' una
    // scrittura su disco, e farla a ogni avvio anche quando tutto funziona
    // sarebbe lavoro inutile su ogni postazione sana.
    if storage.used {
        let cartella = lisi_services::data_directory::check();
        if !cartella.is_writable() {
            tracing::error!(
                motivo = cartella.technical_reason(),
                "la cartella dati non e' scrivibile: e' la causa del ripiego"
            );
        }
    }

    if storage.used {
        // **AL CERTO SI DICE CERTO.**
        //
        // Fino al 2026-08-19 questo avviso diceva che i dati «potrebbero non
        // essere conservati». Non e' un rischio: con l'archiviazione in
        // memoria i dati **sono** perduti alla chiusura, sempre. Un avviso
        // che attenua un fatto certo si legge come un'eventualita' remota, e
        // chi lo legge continua a lavorare — che e' esattamente cio' che e'
        // successo sulla prima installazione reale.
        //
        // Dice anche che cosa fare. Un avviso che descrive un guaio senza
        // indicare un gesto lascia chi lo riceve nella stessa posizione di
        // prima, con in piu' l'ansia.
        // Il messaggio dice la CAUSA quando la verifica l'ha trovata, e
        // resta generico quando non l'ha trovata: dire «i permessi sono
        // sbagliati» dove il problema e' un altro manderebbe chi legge a
        // cercare nel posto sbagliato.
        let causa = lisi_services::data_directory::check();
        let avviso = if causa.is_writable() {
            String::from(
                "ARCHIVIAZIONE TEMPORANEA. L'archivio permanente non si e' aperto: \
                 tutto cio' che si inserisce adesso - account, fonti, dizionari, \
                 monitoraggi - SARA' PERDUTO alla chiusura del programma. Non e' \
                 un rischio, e' cio' che accadra'. Chiudere il programma e \
                 riaprirlo; se l'avviso torna, il motivo e' scritto nel registro, \
                 accanto ai dati.",
            )
        } else {
            causa.operator_message()
        };
        window.set_storage_fallback_notice(SharedString::from(avviso));
    }

    // Partito da una chiavetta, il programma lo dice in cima a ogni schermata
    // (PORTABLE-01, ADR-0176). Si chiede una volta: l'eseguibile non cambia
    // volume mentre gira.
    if let Some(fascia) = lisi_platform::launch_volume::of_current_executable().station_notice() {
        window.set_launch_volume_notice(SharedString::from(fascia));
    }

    // Un azzeramento eseguito a questo avvio va **detto**. Fino al 2026-08-04
    // l'unica traccia era una riga INFO nel registro: chi riapriva il prodotto
    // trovava account, profili, fonti e dizionari spariti e nessuna
    // spiegazione, indistinguibile da una perdita di dati. Rilevato in campo,
    // sulla configurazione di un operatore.
    if continuity.is_some() {
        window.set_archive_reset_notice(SharedString::from(
            "L'azzeramento dell'archivio richiesto in precedenza e' stato eseguito all'avvio: monitoraggi, storico, account, profili, fonti e dizionari sono stati cancellati. L'audit precedente e' stato archiviato in un file accanto ai dati.",
        ));
    } else if account::data_root().is_some_and(|root| lisi_services::reset::reset_is_pending(&root))
    {
        // Richiesto e non ancora avvenuto: si compie alla prossima apertura.
        window.set_archive_reset_pending_notice(SharedString::from(
            "Un azzeramento dell'archivio e' stato richiesto e non e' ancora avvenuto: alla prossima apertura dell'applicazione monitoraggi, storico, account, profili, fonti e dizionari saranno cancellati.",
        ));
    }

    // CHIUDERE CON UN MONITORAGGIO IN CORSO CHIEDE PRIMA (OPERATOR-UX-REMEDIATION-01,
    // OS-09). Non in Esercitazione, per la stessa ragione qui sopra: lì
    // l'archivio non si passa, e la finestra si chiude senza domanda. Il
    // gestore si collega però sempre, perché a postazione bloccata la finestra
    // non si chiude in nessun modo (OPERATOR-E2E-REMEDIATION-01, F-01).
    closing::wire(
        &window,
        if esercitazione_attiva {
            None
        } else {
            storage.open()
        },
    );

    // PRONTO PER LAVORARE (PR-04, ADR-0120). Il controllo di avvio viene DOPO
    // il rilevamento delle interruzioni, che deve averle già registrate, e
    // parte DOPO che la finestra è comparsa: un controllo che la trattenesse
    // prima di mostrarla sembrerebbe un programma che non parte. Il suo
    // archivio è proprio, come quello di ogni altro servizio, e ne ha un
    // secondo per il collegamento all'Hub, che legge la propria configurazione.
    if let Some(controllo) = preflight::create(
        storage.open(),
        storage.open(),
        diagnostics_service.as_ref(),
        health_service.as_ref(),
    ) {
        preflight::wire(&window, &controllo);
        *preflight_slot.borrow_mut() = Some(Rc::clone(&controllo));
        let handle = window.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(400), move || {
            if let Some(window) = handle.upgrade() {
                preflight::run(&window, &controllo);
            }
        });
    } else {
        tracing::warn!("controllo di avvio non disponibile in questa esecuzione");
    }

    // La cornice della finestra la disegna Windows, e senza questa richiesta la
    // disegna bianca sopra un'interfaccia blu notte.
    //
    // La richiesta parte al PRIMO GIRO del ciclo di eventi, non subito dopo
    // `show()`. Slint documenta che l'handle nativo «puo' diventare disponibile
    // solo dopo che la finestra e' stata creata dal gestore delle finestre,
    // cosa che avviene tipicamente dopo almeno un'iterazione del ciclo di
    // eventi»: chiamando prima, l'handle non c'e' e la richiesta non parte.
    //
    // E' esattamente cio' che e' successo alla prima stesura, e non se n'era
    // accorto nessuno perche' quel caso veniva registrato a livello `debug`,
    // filtrato in esercizio. Ora ogni esito e' a livello `info`.
    // Il vassoio aspetta lo stesso handle, e aspetta insieme: due attese
    // avrebbero due cadenze da tenere allineate (ADR-0063).
    schedule_native_window_work(
        window.as_weak(),
        Rc::clone(&tray_slot),
        Rc::new(RefCell::new(StorageFallback::new())),
        12,
    );

    // «SCOPRI NEXUM» (TOUR-01, ADR-0134). I fatti da cui dipende il percorso
    // si leggono quando servono: la modalità può cambiare a programma aperto.
    // In Esercitazione la squadra non è collegata, e il tour non si propone
    // da sé.
    let contesto_del_tour: tour::ContextSource = {
        let dizionari = dizionari_per_il_tour.clone();
        Rc::new(move || lisi_services::tour::TourContext {
            administrator: dizionari.as_ref().is_some_and(|servizio| {
                servizio.borrow().mode() == lisi_core::OperatingMode::Administrator
            }),
            exercise: esercitazione_attiva,
            team_services: !esercitazione_attiva,
        })
    };
    let tour_screen = tour::create(storage.open(), contesto_del_tour);
    if let Some(tour_screen) = tour_screen.as_ref() {
        tour::wire(&window, tour_screen);
        tour::refresh(&window, tour_screen);
        tour::propose_if_due(&window, tour_screen);
    } else {
        tracing::warn!("tour guidato non disponibile in questa esecuzione");
    }

    // «SCOPRI CHE COSA È CAMBIATO» (NEWS-01, ADR-0169): una volta per
    // edizione, sulla Dashboard, mai in Esercitazione. Legge lo stato del tour
    // prima che la proposta del primo avvio lo registri.
    if let Some(news_screen) = news::create(storage.open()) {
        news::wire(&window, &news_screen);
        news::propose_if_due(&window, &news_screen, esercitazione_attiva);
    } else {
        tracing::warn!("novità non disponibili in questa esecuzione");
    }

    // L'avvio su una schermata (PR-14, ADR-0130): `--pagina=N` la apre con
    // `open-page`, come una voce del menu, e non fa altro. Serve alle catture
    // senza mouse; un numero che non è una schermata si ignora.
    if let Some(pagina) = navigation::start_page(std::env::args()) {
        window.invoke_open_page(pagina);
    }

    // `--tour=N` o `--tour=pannello`: apre il tour come lo aprirebbe la sua
    // voce, per la verifica a vista e per la coda umana (TOUR-01).
    if let (Some(richiesta), Some(tour_screen)) =
        (tour::start_request(std::env::args()), tour_screen.as_ref())
    {
        tour::apply_start_request(&window, tour_screen, richiesta);
    }

    // LA FINESTRA COM'ERA (ADR-0195). Ingrandita alla chiusura ordinata,
    // ingrandita alla riapertura: il collaudo la ritrovava ogni volta ridotta.
    if storage
        .open()
        .is_some_and(|archivio| archivio.window_was_maximized().unwrap_or(false))
    {
        window.window().set_maximized(true);
    }

    window.run().inspect_err(|errore| {
        tracing::error!(errore = %errore, "il ciclo della finestra si è interrotto");
    })?;

    // LA CHIUSURA ORDINATA SI SCRIVE (ADR-0195): il primo avvio dopo la legge
    // come l'istante fino al quale la postazione guardava (OBS-RST-1). Se la
    // scrittura non riesce, l'avviso dira' l'ultimo contenuto, come prima.
    if let Some(archivio) = storage.open()
        && let Err(errore) = archivio.record_orderly_closure(
            lisi_core::time::anchored_now(),
            window.window().is_maximized(),
        )
    {
        tracing::warn!(errore = %errore, "chiusura ordinata non registrata");
    }

    // IL PASSAGGIO DI MANO (SERVICE-01, ADR-0203). Se la persona esce da
    // Windows il segno di vita resta, e il servizio in background continua; se
    // ha chiuso il programma, nessuno continua da sé.
    if !esercitazione_attiva && let Some(archivio) = storage.open() {
        let esito = if lisi_platform::background_service::session_is_ending() {
            let collegati = session
                .as_ref()
                .map(|session| session.borrow().linked_live_accounts())
                .unwrap_or_default();
            lisi_services::background::sign(
                &archivio,
                lisi_core::model::background::Keeper::Window,
                lisi_core::time::anchored_now(),
                &collegati,
            )
        } else {
            lisi_services::background::release_without_handover(
                &archivio,
                lisi_core::model::background::Keeper::Window,
                lisi_core::time::anchored_now(),
            )
        };
        if let Err(errore) = esito {
            tracing::warn!(kind = errore.kind(), "uscita della finestra non registrata");
        }
    }

    tracing::info!("Chiusura ordinata della shell grafica");
    Ok(())
}

/// Riprova a rendere scura la barra del titolo finché l'handle non esiste.
///
/// Slint documenta che l'handle nativo «può diventare disponibile solo dopo che
/// la finestra è stata creata dal gestore delle finestre, cosa che avviene
/// tipicamente dopo almeno un'iterazione del ciclo di eventi». In pratica un
/// solo tentativo al primo giro **non basta**: misurato, l'handle non c'era
/// ancora a 56 ms dall'avvio.
///
/// Si riprova a intervalli brevi per meno di un secondo in tutto. Non è
/// un'attesa attiva: fra un tentativo e l'altro il ciclo di eventi lavora
/// normalmente, e la finestra è già visibile e usabile.
///
/// Esaurititi i tentativi si rinuncia e lo si scrive. La barra resta chiara: è
/// un difetto estetico, non una ragione per insistere all'infinito.
fn schedule_native_window_work(
    window: slint::Weak<AppWindow>,
    tray_slot: Rc<RefCell<Option<tray::SharedTray>>>,
    tray_storage: Rc<RefCell<StorageFallback>>,
    remaining: u8,
) {
    let next = window.clone();
    let next_slot = Rc::clone(&tray_slot);
    let next_storage = Rc::clone(&tray_storage);

    slint::Timer::single_shot(std::time::Duration::from_millis(60), move || {
        let Some(shown) = window.upgrade() else {
            return;
        };

        if apply_dark_title_bar(&shown) {
            // L'handle c'e': e' anche il momento del vassoio, che aspettava lo
            // stesso. Se non si installa non e' un guasto, e l'applicazione
            // prosegue senza icona.
            *tray_slot.borrow_mut() = tray::create_state(
                native_window_handle(&shown),
                tray_storage.borrow_mut().open(),
            );
            return;
        }

        if remaining > 0 {
            schedule_native_window_work(next, next_slot, next_storage, remaining - 1);
            return;
        }

        tracing::info!(
            "handle nativo della finestra mai disponibile: barra del titolo lasciata al sistema"
        );
    });
}

/// Chiede al gestore delle finestre la barra del titolo scura.
///
/// Restituisce `true` quando la richiesta è partita — riuscita o rifiutata dal
/// sistema — e `false` quando l'handle non è ancora disponibile, che è l'unico
/// caso in cui vale la pena riprovare.
///
/// L'handle nativo si legge dalla finestra di Slint; il confine con il sistema
/// resta in `lisi-platform`, che e' l'unico crate autorizzato all'`unsafe`
/// (ADR-0003, ADR-0020). Qui non c'e' alcuna FFI: solo la lettura di un handle
/// e il passaggio del suo valore.
/// L'handle nativo della finestra, o zero se non è ancora disponibile.
///
/// Qui non c'è alcuna FFI: solo la lettura di un handle e il passaggio del suo
/// valore. Il confine con il sistema resta in `lisi-platform` (ADR-0003).
fn native_window_handle(window: &AppWindow) -> isize {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    // Il fornitore va tenuto in una variabile: e' lui a possedere l'handle.
    let provider = window.window().window_handle();
    let Ok(handle) = provider.window_handle() else {
        return 0;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return 0;
    };
    isize::from(win32.hwnd)
}

fn apply_dark_title_bar(window: &AppWindow) -> bool {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    // Il fornitore dell'handle va tenuto in una variabile: e' lui a possedere
    // l'handle, e leggerlo da un temporaneo lo farebbe cadere mentre lo si sta
    // ancora usando. Il compilatore lo rifiuta, ed e' giusto che lo faccia.
    let provider = window.window().window_handle();

    // L'handle non ancora disponibile e' l'unico caso che merita un altro
    // tentativo, e non si registra: sarebbe una riga per ogni tentativo.
    // L'esito definitivo, invece, e' sempre a livello `info`.
    //
    // Nella prima stesura anche il successo stava a `debug`, che in esercizio
    // e' filtrato: la richiesta non partiva e il registro taceva. Una riga sola
    // all'avvio non e' rumore, ed e' la differenza fra «non funziona e non so
    // perche'» e «non funziona, ecco perche'».
    let Ok(handle) = provider.window_handle() else {
        return false;
    };

    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        // Fuori da Windows non c'e' alcuna barra del titolo da rendere scura.
        return true;
    };

    let handle = isize::from(win32.hwnd);

    match lisi_platform::use_dark_title_bar(handle) {
        Ok(()) => tracing::info!("barra del titolo resa scura"),
        // Si registra e si prosegue. Il messaggio non porta l'handle: e' un
        // valore del sistema, non un'informazione per chi legge un registro.
        Err(error) => tracing::info!(
            errore = %error,
            "barra del titolo lasciata nella resa predefinita del sistema"
        ),
    }

    install_product_title_bar(window, handle);
    true
}

/// Sostituisce la didascalia di sistema con quella del prodotto.
///
/// # Perché resta scura anche così
///
/// La chiamata qui sopra non diventa inutile: se l'installazione fallisce, la
/// finestra torna ad avere la didascalia di Windows, e quella deve essere scura
/// come prima. Le due cose si sommano, non si escludono.
///
/// # Le misure vengono dall'interfaccia
///
/// Altezza della fascia e larghezza dei comandi stanno in `Shell` dentro
/// `tokens.slint`, che è il posto in cui il sistema grafico definisce la
/// geometria del guscio. Passarle da qui invece di riscriverle in
/// `lisi-platform` evita che un giorno le due copie dicano cose diverse — e
/// quel giorno il difetto sarebbe che premere «chiudi» inizia un trascinamento.
#[cfg(windows)]
fn install_product_title_bar(window: &AppWindow, handle: isize) {
    let metrics = lisi_platform::TitleBarMetrics {
        height: window.global::<Shell>().get_titlebar_height() as i32,
        commands_width: window.global::<Shell>().get_titlebar_commands_width() as i32,
        // Lo spessore su cui si afferra per ridimensionare. Non viene dal
        // sistema grafico perché non è una misura estetica: è quanto deve
        // essere largo un bersaglio perché una mano lo prenda.
        border: 8,
    };

    // L'icona della FINESTRA, che non è quella del file. Alt+Tab la chiede alla
    // finestra con `WM_GETICON`, e senza questa riga la finestra rispondeva
    // zero: il prodotto compariva nel commutatore con l'icona generica di
    // Windows accanto a un titolo che diceva NEXUM/97 (voce B4 del pilot).
    //
    // Non è fatale, come la barra: senza, si perde l'icona in un elenco, non
    // una funzione.
    match lisi_platform::title_bar::set_icon_from_executable(handle) {
        Ok(()) => tracing::info!("icona della finestra presa dall'eseguibile"),
        Err(error) => tracing::warn!(
            errore = %error,
            "icona della finestra non impostata: in Alt+Tab comparirà quella generica"
        ),
    }

    match lisi_platform::title_bar::install(handle, metrics) {
        Ok(()) => tracing::info!("barra del titolo del prodotto installata"),
        // Non è fatale: senza, resta la didascalia di Windows, già resa scura.
        // Il prodotto è meno riconoscibile e funziona uguale.
        Err(error) => tracing::warn!(
            errore = %error,
            "barra del titolo del prodotto non installata: resta quella di sistema"
        ),
    }

    let closing = handle;
    window.on_close_window(move || {
        if crate::lock::refuse_while_locked("close_window") {
            return;
        }
        // Si CHIEDE la chiusura, non si distrugge la finestra: il messaggio
        // percorre la stessa strada del comando di sistema, e chi ha qualcosa
        // da salvare o da chiedere può intercettarlo.
        if let Err(error) = lisi_platform::title_bar::request_close(closing) {
            tracing::warn!(errore = %error, "chiusura richiesta e non accolta");
        }
    });

    let minimising = handle;
    window.on_minimise_window(move || {
        if crate::lock::refuse_while_locked("minimise_window") {
            return;
        }
        if let Err(error) = lisi_platform::title_bar::minimise(minimising) {
            tracing::warn!(errore = %error, "riduzione a icona non riuscita");
        }
    });

    let maximising = handle;
    window.on_toggle_maximise_window(move || {
        if crate::lock::refuse_while_locked("toggle_maximise_window") {
            return;
        }
        if let Err(error) = lisi_platform::title_bar::toggle_maximised(maximising) {
            tracing::warn!(errore = %error, "ingrandimento non riuscito");
        }
    });
}

/// Fuori da Windows non c'è alcuna didascalia da sostituire.
#[cfg(not(windows))]
fn install_product_title_bar(_window: &AppWindow, _handle: isize) {}

fn main() {
    // L'INSTALLAZIONE DEL SERVIZIO (SERVICE-01 parte 2, ADR-0203): chiesta
    // dall'installatore o dalle Impostazioni, senza finestra del programma.
    // L'esito è il codice di uscita.
    let argomenti: Vec<String> = std::env::args().collect();
    if let Some(comando) = servizio_installazione::comando(&argomenti) {
        std::process::exit(servizio_installazione::esegui(&comando));
    }
    // IL SERVIZIO IN BACKGROUND (SERVICE-01, ADR-0203): Windows lo avvia con il
    // suo argomento, e non ha finestra. Un errore va soltanto nel registro di
    // Windows: non c'è nessuno davanti a uno schermo a cui dirlo.
    if std::env::args().any(|argomento| argomento == lisi_core::model::background::SERVICE_ARGUMENT)
    {
        if let Err(errore) = servizio::run() {
            eprintln!("servizio in background non avviato: {errore}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = run() {
        // In Windows la console è nascosta: stderr resta per gli ambienti di
        // sviluppo, e a chi ha fatto doppio clic lo dice una finestra di
        // Windows (FINAL-REVIEW-01, FR-033). Fino al 2026-10-07 un avvio fallito
        // chiudeva il programma senza una parola: il commento prometteva la
        // finestra «in M1».
        let frase = format!(
            "{} non si è avviato: {error}\n\nIl registro del programma, se è stato aperto, \
             contiene i dettagli. Se il problema si ripete, segnalarlo a chi amministra la \
             postazione.",
            lisi_core::branding::PRODUCT_NAME
        );
        eprintln!("{frase}");
        lisi_platform::window_chrome::show_fatal_message(lisi_core::branding::PRODUCT_NAME, &frase);
        std::process::exit(1);
    }
}

/// Questo stesso file, letto a tempo di compilazione.
///
/// Serve alla guardia strutturale sull'aggiornamento dal vivo: quel
/// collegamento non è verificabile a runtime da un test — richiederebbe una
/// finestra, un connettore e un archivio reali — ma la sua **assenza** sì.
#[cfg(test)]
const THIS_FILE: &str = include_str!("main.rs");

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::text::{Actor, DisplayName};
    use lisi_services::AccountService;

    use super::StorageFallback;

    /// Il codice di questo file senza il modulo di prova e senza i commenti.
    ///
    /// Il taglio del modulo di prova non è pignoleria: le stringhe cercate
    /// compaiono qui sotto, e senza il taglio il test **si soddisferebbe da
    /// solo** e resterebbe verde dopo aver cancellato il collegamento vero.
    fn production_code() -> String {
        let Some((production, _)) = super::THIS_FILE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo di prova deve essere riconoscibile per poterlo escludere");
        };

        production
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//") && !line.starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Un avvio fallito si dice a schermo e nel registro** (FINAL-REVIEW-01,
    /// FR-033): il programma non ha console, e `eprintln!` da solo non lo
    /// legge nessuno.
    #[test]
    fn a_failed_start_is_shown_and_logged() {
        let codice = production_code();
        let Some((_, principale)) = codice.split_once("fn main() {") else {
            panic!("main deve esistere");
        };
        assert!(principale.contains("lisi_platform::window_chrome::show_fatal_message("));
        assert!(codice.contains("let window = AppWindow::new().inspect_err(|errore| {"));
        assert!(codice.contains("window.run().inspect_err(|errore| {"));
    }

    /// **Durante l'acquisizione si ridisegna soltanto la schermata che si
    /// guarda** (FINAL-REVIEW-01, FR-035): le altre si ridisegnano quando si
    /// aprono.
    #[test]
    fn the_live_refresh_redraws_only_the_visible_screen() {
        let codice = production_code();
        let Some((_, dopo)) = codice.split_once("let pompato = fresh.replace(false);") else {
            panic!("il ciclo dell'aggiornamento dal vivo deve esistere");
        };
        let Some((ciclo, _)) = dopo.split_once("links::create_service") else {
            panic!("il ciclo deve finire");
        };
        assert!(ciclo.contains("match window.get_current_page() {"));
        assert!(ciclo.contains("7 | 8 => {"));
        assert!(ciclo.contains("9 => {"));
        assert!(ciclo.contains("13 => {"));
        // Persone si ridisegna mentre la si guarda (CA02-01).
        assert!(ciclo.contains("14 => {"));
        // Anche cio' che entra per comando ridisegna (E2E01-05).
        assert!(ciclo.contains("let comandato = freshness::take();"));
    }

    /// **In Esercitazione non si annunciano interruzioni** (FINAL-REVIEW-01,
    /// FR-032): nulla acquisisce, quindi nulla si interrompe.
    #[test]
    fn the_exercise_never_announces_an_interruption() {
        assert!(
            production_code()
                .contains("if !esercitazione_attiva {\ninterruption::wire(&window, &mut storage);"),
            "il rilevamento delle interruzioni deve restare fuori dall'Esercitazione"
        );
    }

    /// **L'interruzione si registra prima che le schermate si compongano**
    /// (BUG-UX-5, BUG-UX-6). Stava dopo: il Cruscotto e il Monitoraggio,
    /// composti prima, contavano l'interrotto fra quelli che ricevono e
    /// dicevano «In corso … man mano che arrivano» accanto al suo avviso.
    #[test]
    fn l_interruzione_si_registra_prima_delle_schermate() {
        let codice = production_code();
        let Some(rilevamento) = codice.find("interruption::wire(&window, &mut storage);") else {
            panic!("il rilevamento delle interruzioni deve esistere");
        };
        let Some(azzeramento) = codice.find("apply_pending_reset(&root)") else {
            panic!("l'azzeramento all'avvio deve esistere");
        };
        assert!(
            azzeramento < rilevamento,
            "l'interruzione si registra dopo l'azzeramento, non in un archivio che sta per sparire"
        );
        for composizione in [
            "dashboard::refresh(",
            "monitoring::refresh(&window, &monitoring, None)",
        ] {
            let Some(posizione) = codice.find(composizione) else {
                panic!("«{composizione}» deve esistere");
            };
            assert!(
                rilevamento < posizione,
                "«{composizione}» viene prima del rilevamento delle interruzioni"
            );
        }
    }

    /// Guardia strutturale sull'aggiornamento dal vivo.
    ///
    /// **Il difetto da cui protegge.** Il ciclo che pompa gli eventi
    /// ridisegnava Account, blocco e recupero, e non Storico, Monitoraggio e
    /// Notifiche: quelle tre si ridisegnavano solo aprendole. Chi restava a
    /// guardare lo Storico durante un monitoraggio vedeva numeri fermi mentre
    /// i contenuti arrivavano davvero. Nessun test lo coglieva, perché i
    /// servizi funzionavano, l'archivio si popolava, e il difetto stava
    /// **nell'assenza di una chiamata**.
    ///
    /// È lo stesso difetto già registrato quattro volte in questa serie — un
    /// motore costruito, collaudato e mai invocato — e la stessa forma di
    /// guardia che `crate::acquisition` usa contro di esso.
    ///
    /// **Che cosa prova e che cosa no.** Prova che il collegamento esiste, cioè
    /// esattamente ciò che mancava. Non prova che scatti al momento giusto:
    /// quello richiede un monitoraggio vero, ed è una voce del pilot.
    #[test]
    fn la_guida_riceve_ogni_voce_del_glossario() {
        use slint::Model;
        let modello = super::glossary_model();
        assert_eq!(
            modello.row_count(),
            lisi_core::glossary::GLOSSARY.len(),
            "ogni voce del glossario deve arrivare alla Guida"
        );
        for riga in modello.iter() {
            assert!(
                !riga.detail.is_empty(),
                "«{}» arriva senza dettaglio tecnico",
                riga.term
            );
            assert!(
                !riga.plain.is_empty(),
                "«{}» arriva senza frase semplice",
                riga.term
            );
        }
    }

    /// Spezzare in capoversi non deve cambiare **una parola**.
    ///
    /// Togliendo i capoversi si deve riottenere il testo di partenza, carattere
    /// per carattere. Se cosi' non fosse, l'interfaccia mostrerebbe una guida
    /// diversa da quella che `lisi-core` sorveglia.
    #[test]
    fn spezzare_in_capoversi_non_cambia_una_parola() {
        for section in lisi_core::guide::GUIDE {
            let spezzato = super::in_capoversi(section.body);
            assert_eq!(
                spezzato.replace("\n\n", " "),
                section.body,
                "il testo della sezione «{}» e' cambiato",
                section.title
            );
        }
    }

    /// **La prova che serve davvero.**
    ///
    /// Che le parole non cambino NON basta: un taglio potrebbe cadere in mezzo
    /// a una delle affermazioni che impediscono alla guida di sovrapromettere,
    /// e il testo resterebbe identico mentre la frase sorvegliata sparisce
    /// spezzata in due. La prova precedente passerebbe lo stesso.
    ///
    /// Qui si verifica cio' che conta: dopo la trasformazione le otto
    /// affermazioni si leggono ancora intere. L'elenco viene da `lisi-core`,
    /// non e' ricopiato: una seconda copia divergerebbe, e a divergere sarebbe
    /// proprio quella che sorveglia meno.
    #[test]
    fn le_affermazioni_sorvegliate_sopravvivono_ai_capoversi() {
        let testo: String = lisi_core::guide::GUIDE
            .iter()
            .map(|section| super::in_capoversi(section.body))
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();

        for claim in lisi_core::guide::DECLARED_LIMITS {
            assert!(
                testo.contains(claim),
                "spezzando in capoversi si e' perso «{claim}»: la guida non \
                 dichiarerebbe piu' quel limite"
            );
        }
    }

    /// I corpi lunghi guadagnano un capoverso, i brevi restano interi.
    ///
    /// Senza questa, la trasformazione potrebbe non fare nulla e le due prove
    /// qui sopra resterebbero verdi: sarebbero verdi per il motivo sbagliato.
    #[test]
    fn i_corpi_lunghi_si_spezzano_e_i_brevi_no() {
        let lunghi = lisi_core::guide::GUIDE
            .iter()
            .filter(|section| section.body.chars().count() > 240)
            .count();
        let spezzati = lisi_core::guide::GUIDE
            .iter()
            .filter(|section| super::in_capoversi(section.body).contains("\n\n"))
            .count();

        assert!(lunghi > 0, "la guida deve avere corpi lunghi da spezzare");
        assert_eq!(
            spezzati, lunghi,
            "ogni corpo lungo deve guadagnare un capoverso, e nessun altro"
        );

        // Un capoverso solo: due tagli farebbero tre blocchi, e la regola
        // dichiarata e' che se ne inserisce uno.
        for section in lisi_core::guide::GUIDE {
            let spezzato = super::in_capoversi(section.body);
            assert!(
                spezzato.matches("\n\n").count() <= 1,
                "la sezione «{}» ha piu' di un capoverso",
                section.title
            );
        }
    }

    #[test]
    fn what_arrives_while_someone_is_watching_gets_redrawn() {
        let code = production_code();

        assert!(
            code.contains("pump_fresh.set(true)"),
            "il pompaggio non segnala piu' di aver ingerito qualcosa: le \
             schermate resterebbero ferme mentre i contenuti arrivano"
        );

        for (screen, call) in [
            ("Storico", "history::refresh(&window, screens, None)"),
            (
                "Monitoraggio",
                "monitoring::refresh(&window, monitoring, None)",
            ),
            (
                "Notifiche",
                "notification_center::refresh(&window, notifications)",
            ),
        ] {
            assert!(
                code.contains(call),
                "la schermata {screen} non viene piu' ridisegnata quando arriva \
                 un contenuto: mostrerebbe numeri fermi finche' non la si riapre"
            );
        }
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn actor() -> Actor {
        let Ok(value) = Actor::try_new("responsabile.ufficio") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    /// Simula un archivio persistente non apribile, senza toccare quello
    /// reale dell'operatore.
    fn persistent_archive_unavailable() -> lisi_services::ServiceResult<lisi_services::Database> {
        Err(lisi_services::ServiceError::SessionUnavailable {
            reason: String::from("simulato per il test: archivio persistente non disponibile"),
        })
    }

    #[test]
    fn when_the_persistent_archive_opens_the_shared_fallback_is_never_used() {
        let mut storage = StorageFallback::new();

        let database = storage.open_with(lisi_services::sources::open_in_memory_database);

        assert!(database.is_some());
        assert!(!storage.used);
    }

    #[test]
    fn when_the_persistent_archive_fails_dependent_services_share_the_fallback() {
        // Solo questo test, in tutto il binario, apre il ripiego condiviso
        // con il suo nome fisso (attraverso l'archivio persistente simulato
        // come non disponibile): una seconda chiamata concorrente da un altro
        // test lo contaminerebbe.
        let mut storage = StorageFallback::new();

        let Some(for_account) = storage.open_with(persistent_archive_unavailable) else {
            panic!(
                "il ripiego condiviso deve aprirsi anche quando l'archivio persistente non lo e'"
            );
        };
        let Some(for_sources) = storage.open_with(persistent_archive_unavailable) else {
            panic!(
                "il ripiego condiviso deve aprirsi anche quando l'archivio persistente non lo e'"
            );
        };

        assert!(
            storage.used,
            "il ricorso al ripiego condiviso deve essere tracciato"
        );

        // Le due connessioni vedono lo stesso archivio: un profilo scritto
        // attraverso la prima e' leggibile dalla seconda, esattamente come
        // accadrebbe con due connessioni allo stesso file reale. E' la stessa
        // coppia di aperture che `run()` userebbe per Account e Fonti.
        let writer = AccountService::new(for_account);
        let Ok(label) = DisplayName::try_new("Profilo condiviso di prova") else {
            panic!("l'etichetta di prova deve essere valida");
        };
        let Ok(profile_id) = writer.create_api_profile(&label, &actor(), now()) else {
            panic!("il profilo di prova deve potersi creare");
        };

        let reader = AccountService::new(for_sources);
        let Ok(profiles) = reader.api_profiles() else {
            panic!("i profili devono potersi rileggere");
        };
        assert!(
            profiles.iter().any(|profile| profile.id == profile_id),
            "la seconda connessione al ripiego deve vedere il profilo scritto dalla prima"
        );
    }
}

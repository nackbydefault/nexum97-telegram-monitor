//! «Riferimenti informatici»: STIX, ATT&CK, CVE e KEV (PR-14, ADR-0130,
//! DEC-357).
//!
//! Rende raggiungibili **soltanto** le funzioni che i servizi della Fase 8 già
//! fanno: l'anteprima e il pacchetto STIX di un monitoraggio, le fotografie
//! ATT&CK con le associazioni dichiarate da una persona e il loro ritiro, la
//! risoluzione di un identificativo CVE e la presenza nel catalogo KEV. Ogni
//! risposta dice **da quale fotografia** viene, e le frasi le compone il
//! dominio: questo modulo non ne scrive di sue, e non calcola nulla.
//!
//! Dal 2026-11-05 (TAXII-01 parte 3, ADR-0179, DEC-460) il riquadro del
//! pacchetto STIX ha accanto «Mandare a TAXII»: si prepara l'invio, si vede
//! dove va e quanti osservabili escono, e soltanto dopo si conferma. La
//! destinazione e la parola d'ordine si scrivono qui, in modalità
//! amministratore; chi può scriverle lo decide il servizio.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use lisi_core::model::attack::AttackTechniqueId;
use lisi_core::model::attack_association::{
    AssociatedTerm, AttackAssociationWithdrawal, NewAttackAssociation,
};
use lisi_core::model::cve::CveId;
use lisi_core::text::Actor;
use lisi_core::{OperatingMode, SessionId, Timestamp};
use lisi_services::attack_mapping::AttackMappingService;
use lisi_services::attack_snapshot::AttackSnapshotService;
use lisi_services::cve_snapshot::{CVE_ATTRIBUTION, CveSnapshotService};
use lisi_services::history::HistoryService;
use lisi_services::kev_snapshot::KevSnapshotService;
use lisi_services::stix_export::StixExportService;
use lisi_services::taxii::{StoredTaxiiSubmission, TaxiiDestination, TaxiiPreview, TaxiiService};
use lisi_services::{Database, ServiceError, station};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, ReferenceAssociationRow, ReferenceSnapshotRow, StixPlanRow};

/// La schermata: l'archivio, i monitoraggi nell'ordine del selettore, e il
/// monitoraggio di cui si è vista l'anteprima.
pub struct ReferencesScreen {
    history: HistoryService,
    sessions: Vec<SessionId>,
    previewed: Option<SessionId>,
    /// Il file protetto della parola d'ordine TAXII, se la cartella dei dati
    /// si trova.
    taxii_password: Option<PathBuf>,
    /// Il monitoraggio di cui si è preparato l'invio a TAXII.
    taxii_previewed: Option<SessionId>,
}

impl ReferencesScreen {
    fn database(&self) -> &Database {
        self.history.database()
    }

    fn database_mut(&mut self) -> &mut Database {
        self.history.database_mut()
    }
}

/// Schermata condivisa fra i gestori.
pub type SharedReferences = Rc<RefCell<ReferencesScreen>>;

/// Crea la schermata sull'archivio indicato.
#[must_use]
pub fn create_service(database: Option<Database>) -> Option<SharedReferences> {
    Some(Rc::new(RefCell::new(ReferencesScreen {
        history: HistoryService::new(database?),
        sessions: Vec::new(),
        previewed: None,
        taxii_password: lisi_services::taxii::default_password_path(),
        taxii_previewed: None,
    })))
}

fn model<T: Clone + 'static>(righe: Vec<T>) -> ModelRc<T> {
    ModelRc::from(Rc::new(VecModel::from(righe)))
}

fn testo(valore: impl Into<String>) -> SharedString {
    SharedString::from(valore.into())
}

/// Rilegge i monitoraggi e le fotografie.
pub fn refresh(window: &AppWindow, screen: &SharedReferences) {
    let mut screen = screen.borrow_mut();
    let sessioni = screen.history.sessions().unwrap_or_default();
    screen.sessions = sessioni
        .iter()
        .map(|sessione| sessione.session.id)
        .collect();
    window.set_references_sessions(model(
        sessioni
            .iter()
            .map(|sessione| testo(sessione.label()))
            .collect(),
    ));
    if screen.previewed.is_none() {
        window.set_references_stix_ready(false);
    }

    let database = screen.database_mut();
    let attack = AttackMappingService::new(database)
        .snapshots()
        .unwrap_or_default()
        .into_iter()
        .map(|fotografia| ReferenceSnapshotRow {
            key: i32::try_from(fotografia.id.get()).unwrap_or_default(),
            source: testo(format!(
                "MITRE ATT&CK {} {}",
                fotografia.domain, fotografia.attack_version
            )),
            when: testo(fotografia.imported_at.to_readable_local()),
            who: testo(fotografia.imported_by.as_str()),
            content: testo(format!("Specifica {}.", fotografia.spec_version)),
        })
        .collect();
    window.set_references_attack_snapshots(model(attack));

    let cve = CveSnapshotService::new(database)
        .snapshots()
        .unwrap_or_default()
        .into_iter()
        .map(|fotografia| ReferenceSnapshotRow {
            key: i32::try_from(fotografia.id.get()).unwrap_or_default(),
            source: testo(format!("NVD, {}", fotografia.source)),
            when: testo(fotografia.imported_at.to_readable_local()),
            who: testo(fotografia.imported_by.as_str()),
            content: testo(format!(
                "{} voci. {}",
                fotografia.record_count,
                fotografia.coverage.as_sentence()
            )),
        })
        .collect();
    window.set_references_cve_snapshots(model(cve));

    let kev = KevSnapshotService::new(database)
        .snapshots()
        .unwrap_or_default()
        .into_iter()
        .map(|fotografia| ReferenceSnapshotRow {
            key: i32::try_from(fotografia.id.get()).unwrap_or_default(),
            source: testo(format!(
                "CISA KEV {} del {}",
                fotografia.catalog.version(),
                fotografia.catalog.released_at()
            )),
            when: testo(fotografia.imported_at.to_readable_local()),
            who: testo(fotografia.imported_by.as_str()),
            content: testo(format!(
                "{} voci, {} omesse.",
                fotografia.entry_count, fotografia.omitted_count
            )),
        })
        .collect();
    window.set_references_kev_snapshots(model(kev));
}

/// Chi agisce, o la frase che dice perché non si sa.
fn chi() -> Result<lisi_core::text::Actor, String> {
    crate::operator::audit_actor().map_err(|_| String::from(crate::account::NON_SI_SA_CHI_OPERA))
}

/// Le parti della schermata in cui un esito si mostra.
///
/// L'esito stava in cima alla pagina, e i comandi di CVE e KEV sono in fondo:
/// chi importava non vedeva la risposta e ripeteva (F-09). Ora l'esito si
/// mostra nel riquadro del comando che l'ha prodotto.
const AREA_STIX: i32 = 1;
const AREA_ATTACK: i32 = 2;
const AREA_CVE: i32 = 3;
const AREA_KEV: i32 = 4;
const AREA_TAXII: i32 = 5;

/// Mostra un esito nel riquadro indicato.
fn say(window: &AppWindow, area: i32, frase: impl AsRef<str>) {
    window.set_references_message(SharedString::from(frase.as_ref()));
    window.set_references_message_area(area);
}

/// L'anteprima STIX del monitoraggio scelto.
fn stix_preview(window: &AppWindow, screen: &SharedReferences) {
    let mut screen = screen.borrow_mut();
    let indice = usize::try_from(window.get_references_session()).unwrap_or_default();
    let Some(sessione) = screen.sessions.get(indice).copied() else {
        say(window, AREA_STIX, testo("Nessun monitoraggio scelto."));
        return;
    };
    match StixExportService::new(screen.database()).preview(sessione) {
        Ok(piano) => {
            let mut righe: Vec<StixPlanRow> = piano
                .exported
                .iter()
                .map(|voce| StixPlanRow {
                    value: testo(voce.indicator.value.clone()),
                    kind: testo(voce.indicator.kind.label()),
                    contents: testo(format!("{} contenuti", voce.mentioning_contents)),
                    outcome: testo("entra nel pacchetto"),
                })
                .collect();
            righe.extend(piano.omitted.iter().map(|voce| StixPlanRow {
                value: testo(voce.indicator.value.clone()),
                kind: testo(voce.indicator.kind.label()),
                contents: testo(format!("{} contenuti", voce.mentioning_contents)),
                outcome: testo(format!("resta fuori: {}", voce.reason.as_sentence())),
            }));
            window.set_references_stix_summary(testo(format!(
                "Entrano {} indicatori, ne restano fuori {}.",
                piano.exported.len(),
                piano.omitted.len()
            )));
            window.set_references_stix_plan(model(righe));
            window.set_references_stix_ready(!piano.is_empty());
            screen.previewed = (!piano.is_empty()).then_some(sessione);
            say(window, AREA_STIX, SharedString::default());
        }
        Err(errore) => say(window, AREA_STIX, testo(errore.operator_message())),
    }
}

/// Il pacchetto STIX del monitoraggio di cui si è vista l'anteprima.
fn stix_export(window: &AppWindow, screen: &SharedReferences) {
    let screen = screen.borrow();
    let Some(sessione) = screen.previewed else {
        say(window, AREA_STIX, testo("Prima si guarda l'anteprima."));
        return;
    };
    let frase = match (
        chi(),
        lisi_services::export::resolved_destination(screen.database()),
    ) {
        (Err(frase), _) => frase,
        (_, Err(errore)) => errore.operator_message(),
        (Ok(attore), Ok(cartella)) => match StixExportService::new(screen.database()).export(
            sessione,
            &cartella,
            &attore,
            crate::account::now(),
        ) {
            Ok(esito) => format!("Pacchetto STIX prodotto in «{}».", esito.bundle.display()),
            Err(errore) => errore.operator_message(),
        },
    };
    say(window, AREA_STIX, testo(frase));
}

/// Quanti invii mostra il registro sulla schermata.
const SHOWN_SUBMISSIONS: usize = 10;

/// Il servizio TAXII sull'archivio della schermata.
///
/// Senza cartella dei dati non si sa dove stia la parola d'ordine: si dice,
/// invece di cercarla altrove.
fn taxii(screen: &mut ReferencesScreen) -> Result<TaxiiService<'_>, String> {
    let Some(file) = screen.taxii_password.clone() else {
        return Err(String::from(
            "Non si trova la cartella dei dati: la parola d'ordine TAXII non ha dove stare.",
        ));
    };
    Ok(TaxiiService::with_password_file(
        screen.database_mut(),
        file,
    ))
}

/// La frase di un rifiuto del servizio, con il genere nel registro tecnico.
fn rifiuto(errore: &ServiceError) -> String {
    tracing::warn!(kind = errore.kind(), "scambio TAXII rifiutato");
    errore.operator_message()
}

/// La frase sotto i campi: che cosa succede premendo, con ciò che c'è scritto.
fn taxii_note(
    destination: Option<&TaxiiDestination>,
    has_password: bool,
    administrator: bool,
) -> String {
    let stato = match destination {
        None => "Senza destinazione il programma non manda niente a TAXII.",
        Some(destinazione) if destinazione.username.is_none() || !has_password => {
            "Destinazione indicata. Senza nome e parola d'ordine il programma non manda niente."
        }
        Some(_) => "Destinazione indicata, con nome e parola d'ordine.",
    };
    let mut nota =
        format!("{stato} La parola d'ordine vale soltanto per questo utente di Windows.");
    if !administrator {
        nota.push_str(
            " La destinazione e la parola d'ordine si scrivono in modalità amministratore.",
        );
    }
    nota
}

/// Riporta nella schermata la destinazione, la nota e il registro.
///
/// È separata da [`refresh`]: quella corre dopo ogni comando, e riscrivere i
/// campi a ogni comando cancellerebbe ciò che l'amministratore sta scrivendo.
/// Il campo della parola d'ordine si vuota sempre: non si rilegge mai.
fn refresh_taxii(window: &AppWindow, screen: &SharedReferences) {
    let amministratore = station::persisted_mode_or_restricted() == OperatingMode::Administrator;
    window.set_references_taxii_password(SharedString::default());
    let mut screen = screen.borrow_mut();
    let servizio = match taxii(&mut screen) {
        Ok(servizio) => servizio,
        Err(frase) => {
            window.set_references_taxii_note(testo(frase));
            return;
        }
    };
    // Un errore di lettura non diventa «nessuna destinazione»: un campo vuoto
    // inviterebbe a riscrivere ciò che forse c'è già.
    match servizio.destination() {
        Ok(destinazione) => {
            let campo = |scelta: fn(&TaxiiDestination) -> Option<&str>| {
                testo(destinazione.as_ref().and_then(scelta).unwrap_or_default())
            };
            window.set_references_taxii_root(campo(|d| Some(d.api_root.as_str())));
            window.set_references_taxii_collection(campo(|d| Some(d.collection_id.as_str())));
            window.set_references_taxii_username(campo(|d| d.username.as_deref()));
            window.set_references_taxii_note(testo(taxii_note(
                destinazione.as_ref(),
                servizio.has_password(),
                amministratore,
            )));
        }
        Err(errore) => {
            window.set_references_taxii_root(SharedString::default());
            window.set_references_taxii_collection(SharedString::default());
            window.set_references_taxii_username(SharedString::default());
            window.set_references_taxii_note(testo(rifiuto(&errore)));
        }
    }
    let registro = match servizio.submissions() {
        Ok(righe) => submissions_text(&righe),
        Err(errore) => rifiuto(&errore),
    };
    window.set_references_taxii_submissions(testo(registro));
}

/// Ciò che l'amministratore ha scritto nei campi della destinazione.
///
/// Non è `Debug`: porta la parola d'ordine.
struct TaxiiFields<'a> {
    root: &'a str,
    collection: &'a str,
    username: &'a str,
    password: &'a str,
}

/// Scrive la destinazione e, se scritta, la parola d'ordine.
///
/// Lasciata vuota, la parola di prima resta. Svuotando la destinazione si
/// toglie anche la parola: senza destinazione non serve a niente.
fn save_taxii(
    screen: &mut ReferencesScreen,
    campi: &TaxiiFields<'_>,
    mode: OperatingMode,
    actor: &Actor,
    now: Timestamp,
) -> Result<&'static str, String> {
    let mut servizio = taxii(screen)?;
    servizio
        .set_destination(
            Some(campi.root),
            Some(campi.collection),
            Some(campi.username),
            mode,
            actor,
            now,
        )
        .map_err(|errore| rifiuto(&errore))?;
    if servizio
        .destination()
        .map_err(|errore| rifiuto(&errore))?
        .is_none()
    {
        if servizio.has_password() {
            servizio
                .set_password(None, mode, actor, now)
                .map_err(|errore| rifiuto(&errore))?;
        }
        return Ok(
            "Destinazione svuotata: il programma non manda niente a TAXII, e la parola \
                   d'ordine non c'è più.",
        );
    }
    if campi.password.is_empty() {
        return Ok("Destinazione salvata.");
    }
    servizio
        .set_password(Some(campi.password), mode, actor, now)
        .map_err(|errore| rifiuto(&errore))?;
    Ok("Destinazione e parola d'ordine salvate.")
}

/// La frase dell'anteprima: dove va e quanti osservabili escono.
fn preview_sentence(anteprima: &TaxiiPreview) -> String {
    if anteprima.observables == 0 {
        return format!(
            "Non c'è niente da mandare: nessun osservabile entra nel pacchetto, {} restano fuori.",
            anteprima.omitted
        );
    }
    format!(
        "Andranno {} osservabili a «{}». Ne restano fuori {}. Non parte niente finché non \
         si preme «Conferma e manda».",
        anteprima.observables, anteprima.url, anteprima.omitted
    )
}

/// Prepara l'invio del monitoraggio scelto: la frase e se si può confermare.
fn prepare_taxii(screen: &mut ReferencesScreen, sessione: Option<SessionId>) -> (String, bool) {
    screen.taxii_previewed = None;
    let Some(sessione) = sessione else {
        return (String::from("Nessun monitoraggio scelto."), false);
    };
    let anteprima = taxii(screen).and_then(|servizio| {
        servizio
            .preview(sessione)
            .map_err(|errore| rifiuto(&errore))
    });
    match anteprima {
        Ok(anteprima) => {
            let pronto = anteprima.observables > 0;
            screen.taxii_previewed = pronto.then_some(sessione);
            (preview_sentence(&anteprima), pronto)
        }
        Err(frase) => (frase, false),
    }
}

/// Manda il monitoraggio preparato, se è ancora quello scelto.
///
/// Si manda soltanto ciò che si è visto: un altro monitoraggio scelto dopo
/// l'anteprima si rifiuta, e l'anteprima va rifatta. In ogni caso la
/// conferma vale una volta.
fn send_prepared(
    screen: &mut ReferencesScreen,
    scelta: Option<SessionId>,
    now: Timestamp,
) -> String {
    let Some(preparata) = screen.taxii_previewed.take() else {
        return String::from("Prima si prepara l'invio, per vedere dove va e che cosa esce.");
    };
    if scelta != Some(preparata) {
        return String::from(
            "Il monitoraggio scelto non è quello preparato: si prepara di nuovo l'invio.",
        );
    }
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    match taxii(screen) {
        Ok(mut servizio) => match servizio.send(preparata, &attore, now) {
            Ok(esito) => esito.operator_message(),
            Err(errore) => rifiuto(&errore),
        },
        Err(frase) => frase,
    }
}

/// Il registro degli invii, dal più recente, in righe da leggere.
fn submissions_text(rows: &[StoredTaxiiSubmission]) -> String {
    if rows.is_empty() {
        return String::from("Nessun invio a TAXII finora.");
    }
    let mut righe = vec![String::from("Ultimi tentativi:")];
    for riga in rows.iter().take(SHOWN_SUBMISSIONS) {
        let esito = if riga.outcome == "consegnato" {
            "preso"
        } else {
            "non preso"
        };
        let mut testo = format!(
            "{} — {}: {} oggetti, {esito}",
            riga.requested_at.to_readable_local(),
            riga.requested_by,
            riga.objects
        );
        if let (Some(presi), Some(rifiutati), Some(in_attesa)) =
            (riga.success_count, riga.failure_count, riga.pending_count)
        {
            testo.push_str(&format!(
                " ({presi} accettati, {rifiutati} rifiutati, {in_attesa} in attesa)"
            ));
        } else if let Some(perche) = &riga.outcome_detail {
            testo.push_str(&format!(" ({perche})"));
        }
        righe.push(testo);
    }
    righe.join("\n")
}

/// Il monitoraggio scelto nel selettore.
fn scelto(window: &AppWindow, screen: &ReferencesScreen) -> Option<SessionId> {
    let indice = usize::try_from(window.get_references_session()).ok()?;
    screen.sessions.get(indice).copied()
}

/// Collega i comandi dello scambio TAXII.
fn wire_taxii(window: &AppWindow, screen: &SharedReferences) {
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_references_taxii_preview(move || {
            if crate::lock::refuse_while_locked("references_taxii_preview") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let mut schermata = screen.borrow_mut();
            let sessione = scelto(&window, &schermata);
            let (frase, pronto) = prepare_taxii(&mut schermata, sessione);
            window.set_references_taxii_summary(testo(frase));
            window.set_references_taxii_ready(pronto);
            say(&window, AREA_TAXII, SharedString::default());
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_references_taxii_send(move || {
            if crate::lock::refuse_while_locked("references_taxii_send") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            window.set_references_taxii_ready(false);
            let frase = {
                let mut schermata = screen.borrow_mut();
                let sessione = scelto(&window, &schermata);
                send_prepared(&mut schermata, sessione, crate::account::now())
            };
            window.set_references_taxii_summary(SharedString::default());
            refresh_taxii(&window, &screen);
            say(&window, AREA_TAXII, frase);
        });
    }
    // La destinazione e la parola d'ordine. Il servizio decide chi può
    // scriverle: in modalità operatore il pulsante non c'è, e se ci fosse il
    // rifiuto verrebbe comunque dal servizio.
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_references_taxii_save(move || {
            if crate::lock::refuse_while_locked("references_taxii_save") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let radice = window.get_references_taxii_root().to_string();
            let collezione = window.get_references_taxii_collection().to_string();
            let nome = window.get_references_taxii_username().to_string();
            let parola = window.get_references_taxii_password().to_string();
            let esito = chi().and_then(|attore| {
                save_taxii(
                    &mut screen.borrow_mut(),
                    &TaxiiFields {
                        root: &radice,
                        collection: &collezione,
                        username: &nome,
                        password: &parola,
                    },
                    station::persisted_mode_or_restricted(),
                    &attore,
                    crate::account::now(),
                )
            });
            refresh_taxii(&window, &screen);
            match esito {
                Ok(frase) => say(&window, AREA_TAXII, frase),
                // Rifiutati, i valori scritti restano nei campi, da correggere;
                // la parola d'ordine no, si riscrive.
                Err(frase) => {
                    window.set_references_taxii_root(testo(radice));
                    window.set_references_taxii_collection(testo(collezione));
                    window.set_references_taxii_username(testo(nome));
                    say(&window, AREA_TAXII, frase);
                }
            }
        });
    }
}

/// Importa la fotografia ATT&CK fissata da `attack.lock.json`.
fn attack_import(window: &AppWindow, screen: &SharedReferences) -> String {
    let cartella = window.get_references_attack_folder().to_string();
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    let fissato = match lisi_services::attack_snapshot::pinned() {
        Ok(fissato) => fissato,
        Err(errore) => return errore.operator_message(),
    };
    let (pacchetto, licenza) = fissato.paths_in(Path::new(cartella.trim()));
    let mut screen = screen.borrow_mut();
    match AttackSnapshotService::new(screen.database_mut()).import(
        &pacchetto,
        &licenza,
        &fissato.sha256,
        &attore,
        crate::account::now(),
    ) {
        Ok(esito) => attack_sentence(&esito),
        Err(errore) => errore.operator_message(),
    }
}

/// L'esito di una fotografia ATT&CK importata, da cartella o dalla fonte.
fn attack_sentence(esito: &lisi_services::attack_snapshot::AttackImportOutcome) -> String {
    format!(
        "Fotografia ATT&CK {} importata: {} tecniche, {} tattiche, {} mitigazioni e rilevazioni. \
         {} oggetti che nominano attori lasciati fuori: il prodotto non attribuisce attacchi a \
         gruppi o persone.",
        esito.attack_version, esito.techniques, esito.tactics, esito.guidance, esito.actors_ignored
    )
}

/// Scarica dalla fonte fissata nel programma e importa (SNAP-NET-01,
/// ADR-0186): una persona lo chiede, e la verifica è quella di sempre.
fn attack_download(_window: &AppWindow, screen: &SharedReferences) -> String {
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    let mut screen = screen.borrow_mut();
    match lisi_services::snapshot_download::SnapshotDownloadService::new(screen.database_mut())
        .download_attack(&attore, crate::account::now())
    {
        Ok(esito) => attack_sentence(&esito),
        Err(errore) => errore.operator_message(),
    }
}

/// Il termine scritto nei due campi, se valido.
fn termine(window: &AppWindow) -> Result<AssociatedTerm, String> {
    AssociatedTerm::new(
        window.get_references_attack_term().trim(),
        window.get_references_attack_category().trim(),
    )
    .map_err(|errore| errore.to_string())
}

/// Le associazioni in piedi del termine scritto.
fn attack_lookup(window: &AppWindow, screen: &SharedReferences) -> String {
    let termine = match termine(window) {
        Ok(termine) => termine,
        Err(frase) => return frase,
    };
    let mut screen = screen.borrow_mut();
    match AttackMappingService::new(screen.database_mut()).for_term(&termine) {
        Ok(associazioni) => {
            let quante = associazioni.len();
            window.set_references_attack_associations(model(
                associazioni
                    .iter()
                    .map(|associazione| ReferenceAssociationRow {
                        key: i32::try_from(associazione.id().get()).unwrap_or_default(),
                        sentence: testo(associazione.as_sentence()),
                        motive: testo(associazione.reason()),
                        who: testo(associazione.declared_by().as_str()),
                        when: testo(associazione.declared_at().to_readable_local()),
                    })
                    .collect(),
            ));
            if quante == 0 {
                String::from("Nessuna associazione in piedi per questo termine.")
            } else {
                String::new()
            }
        }
        Err(errore) => errore.operator_message(),
    }
}

/// Dichiara un'associazione sulla fotografia ATT&CK più recente.
fn attack_declare(window: &AppWindow, screen: &SharedReferences) -> String {
    let (termine, attore) = match (termine(window), chi()) {
        (Ok(termine), Ok(attore)) => (termine, attore),
        (Err(frase), _) | (_, Err(frase)) => return frase,
    };
    let Ok(tecnica) = AttackTechniqueId::try_new(window.get_references_attack_technique().trim())
    else {
        return String::from("La tecnica non ha la forma di un identificativo ATT&CK, come T1566.");
    };
    let mut screen = screen.borrow_mut();
    let mut servizio = AttackMappingService::new(screen.database_mut());
    let Some(fotografia) = servizio
        .snapshots()
        .unwrap_or_default()
        .into_iter()
        .max_by_key(|fotografia| fotografia.imported_at)
    else {
        return String::from("Nessuna fotografia ATT&CK importata: prima si importa.");
    };
    match servizio.declare(
        fotografia.id,
        NewAttackAssociation {
            term: termine,
            technique: tecnica,
            reason: window.get_references_attack_motive().trim().to_owned(),
            declared_by: attore,
            declared_at: crate::account::now(),
        },
    ) {
        Ok(_) => {
            window.set_references_attack_motive(SharedString::default());
            String::from("Associazione dichiarata, con il suo motivo.")
        }
        Err(errore) => errore.operator_message(),
    }
}

/// Ritira l'associazione indicata, con il motivo scritto.
fn attack_withdraw(window: &AppWindow, screen: &SharedReferences, chiave: i32) -> String {
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    let mut screen = screen.borrow_mut();
    match AttackMappingService::new(screen.database_mut()).withdraw(
        lisi_core::AttackAssociationId::new(i64::from(chiave)),
        AttackAssociationWithdrawal {
            reason: window
                .get_references_attack_withdraw_motive()
                .trim()
                .to_owned(),
            withdrawn_by: attore,
            withdrawn_at: crate::account::now(),
        },
    ) {
        Ok(()) => {
            window.set_references_attack_withdraw_motive(SharedString::default());
            String::from("Associazione ritirata: resta nel registro, con il motivo del ritiro.")
        }
        Err(errore) => errore.operator_message(),
    }
}

/// Gli anni scritti, separati da virgole o spazi.
fn anni(scritti: &str) -> Result<Vec<i32>, String> {
    scritti
        .split(|carattere: char| carattere == ',' || carattere.is_whitespace())
        .filter(|parte| !parte.is_empty())
        .map(|parte| {
            parte
                .parse::<i32>()
                .map_err(|_| format!("«{parte}» non è un anno."))
        })
        .collect()
}

/// Importa una fotografia CVE.
fn cve_import(window: &AppWindow, screen: &SharedReferences) -> String {
    let anni = match anni(&window.get_references_cve_years()) {
        Ok(anni) => anni,
        Err(frase) => return frase,
    };
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    let cartella = window.get_references_cve_folder().to_string();
    let mut screen = screen.borrow_mut();
    match CveSnapshotService::new(screen.database_mut()).import(
        Path::new(cartella.trim()),
        &anni,
        CVE_ATTRIBUTION,
        &attore,
        crate::account::now(),
    ) {
        Ok(esito) => cve_sentence(&esito),
        Err(errore) => errore.operator_message(),
    }
}

/// L'esito di una fotografia CVE importata, da cartella o dalla fonte.
fn cve_sentence(esito: &lisi_services::cve_snapshot::CveImportOutcome) -> String {
    format!(
        "Fotografia CVE importata: {} voci, {} omesse con il loro motivo.",
        esito.records,
        esito.omitted.len()
    )
}

/// Scarica gli anni fissati nel programma da NVD e importa (SNAP-NET-01).
fn cve_download(_window: &AppWindow, screen: &SharedReferences) -> String {
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    let mut screen = screen.borrow_mut();
    match lisi_services::snapshot_download::SnapshotDownloadService::new(screen.database_mut())
        .download_cve(&attore, crate::account::now())
    {
        Ok(esito) => cve_sentence(&esito),
        Err(errore) => errore.operator_message(),
    }
}

/// La scheda della tecnica scritta nel campo, dalla fotografia ATT&CK più
/// recente: il nome, le mitigazioni e le rilevazioni (ATTACK-03, ADR-0185).
/// La frase la compone il servizio.
fn attack_show(window: &AppWindow, screen: &SharedReferences) -> String {
    let Ok(tecnica) = AttackTechniqueId::try_new(window.get_references_attack_technique().trim())
    else {
        return String::from("La tecnica non ha la forma di un identificativo ATT&CK, come T1566.");
    };
    match lisi_services::attack_guidance::technique_card(screen.borrow().database(), &tecnica) {
        Ok(scheda) => scheda,
        Err(errore) => errore.operator_message(),
    }
}

/// La risposta per un identificativo, contro la fotografia CVE più recente.
fn cve_resolve(window: &AppWindow, screen: &SharedReferences) -> String {
    let Ok(identificativo) = CveId::try_new(window.get_references_cve_id().trim()) else {
        return String::from("L'identificativo non ha la forma CVE-anno-numero.");
    };
    let mut screen = screen.borrow_mut();
    let servizio = CveSnapshotService::new(screen.database_mut());
    let Some(fotografia) = servizio
        .snapshots()
        .unwrap_or_default()
        .into_iter()
        .max_by_key(|fotografia| fotografia.imported_at)
    else {
        return String::from("Nessuna fotografia CVE importata.");
    };
    let esito = match servizio.resolve(fotografia.id, &identificativo) {
        Ok(esito) => esito,
        Err(errore) => return errore.operator_message(),
    };
    let mut frase = format!(
        "Fotografia del {}, importata da {}. {}",
        fotografia.imported_at.to_readable_local(),
        fotografia.imported_by.as_str(),
        esito.as_sentence(&identificativo)
    );
    // IL PUNTEGGIO, SOLTANTO QUI E SOLTANTO PER UNA CVE TROVATA (ADR-0184,
    // decisione 3): la frase la compone il dominio, e dice che cosa grada.
    if matches!(esito, lisi_core::model::cve::CveResolution::Found(_)) {
        match lisi_services::cve_scores::sentence(screen.database(), fotografia.id, &identificativo)
        {
            Ok(riga) => {
                frase.push(' ');
                frase.push_str(&riga);
            }
            Err(errore) => {
                frase.push(' ');
                frase.push_str(&errore.operator_message());
            }
        }
    }
    frase
}

/// Importa una fotografia del catalogo KEV.
fn kev_import(window: &AppWindow, screen: &SharedReferences) -> String {
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    let cartella = window.get_references_kev_folder().to_string();
    let mut screen = screen.borrow_mut();
    match KevSnapshotService::new(screen.database_mut()).import(
        Path::new(cartella.trim()),
        &attore,
        crate::account::now(),
    ) {
        Ok(esito) => kev_sentence(&esito),
        Err(errore) => errore.operator_message(),
    }
}

/// L'esito di un catalogo KEV importato, da cartella o dalla fonte.
fn kev_sentence(esito: &lisi_services::kev_snapshot::KevImportOutcome) -> String {
    format!(
        "Catalogo KEV {} importato: {} voci, {} omesse con il loro motivo.",
        esito.catalog.version(),
        esito.entries,
        esito.omitted.len()
    )
}

/// Scarica il catalogo KEV di CISA e importa (SNAP-NET-01).
fn kev_download(_window: &AppWindow, screen: &SharedReferences) -> String {
    let attore = match chi() {
        Ok(attore) => attore,
        Err(frase) => return frase,
    };
    let mut screen = screen.borrow_mut();
    match lisi_services::snapshot_download::SnapshotDownloadService::new(screen.database_mut())
        .download_kev(&attore, crate::account::now())
    {
        Ok(esito) => kev_sentence(&esito),
        Err(errore) => errore.operator_message(),
    }
}

/// La presenza di un identificativo nel catalogo KEV più recente.
fn kev_resolve(window: &AppWindow, screen: &SharedReferences) -> String {
    let Ok(identificativo) = CveId::try_new(window.get_references_kev_id().trim()) else {
        return String::from("L'identificativo non ha la forma CVE-anno-numero.");
    };
    let mut screen = screen.borrow_mut();
    let servizio = KevSnapshotService::new(screen.database_mut());
    let Some(fotografia) = servizio
        .snapshots()
        .unwrap_or_default()
        .into_iter()
        .max_by_key(|fotografia| fotografia.imported_at)
    else {
        return String::from("Nessun catalogo KEV importato.");
    };
    match servizio.resolve(fotografia.id, &identificativo) {
        Ok(esito) => format!(
            "Catalogo del {}, importato da {}. {}",
            fotografia.catalog.released_at(),
            fotografia.imported_by.as_str(),
            esito.as_sentence(&identificativo)
        ),
        Err(errore) => errore.operator_message(),
    }
}

/// Collega i comandi della schermata.
pub fn wire(window: &AppWindow, screen: &SharedReferences) {
    /// Collega un comando che restituisce la frase da mostrare, e rilegge le
    /// fotografie dopo.
    macro_rules! collega {
        ($registra:ident, $funzione:ident, $area:expr) => {{
            let handle = window.as_weak();
            let screen = Rc::clone(screen);
            window.$registra(move || {
                if crate::lock::refuse_while_locked(stringify!($registra)) {
                    return;
                }
                let Some(window) = handle.upgrade() else {
                    return;
                };
                let frase = $funzione(&window, &screen);
                say(&window, $area, frase);
                refresh(&window, &screen);
            });
        }};
    }

    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_references_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &screen);
                screen.borrow_mut().taxii_previewed = None;
                window.set_references_taxii_ready(false);
                window.set_references_taxii_summary(SharedString::default());
                refresh_taxii(&window, &screen);
            }
        });
    }
    wire_taxii(window, screen);
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_references_stix_preview(move || {
            if crate::lock::refuse_while_locked("references_stix_preview") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                stix_preview(&window, &screen);
            }
        });
    }
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_references_stix_export(move || {
            if crate::lock::refuse_while_locked("references_stix_export") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                stix_export(&window, &screen);
            }
        });
    }
    collega!(on_references_attack_import, attack_import, AREA_ATTACK);
    collega!(on_references_attack_download, attack_download, AREA_ATTACK);
    collega!(on_references_cve_download, cve_download, AREA_CVE);
    collega!(on_references_kev_download, kev_download, AREA_KEV);
    collega!(on_references_attack_lookup, attack_lookup, AREA_ATTACK);
    collega!(on_references_attack_declare, attack_declare, AREA_ATTACK);
    collega!(on_references_attack_show, attack_show, AREA_ATTACK);
    collega!(on_references_cve_import, cve_import, AREA_CVE);
    collega!(on_references_cve_resolve, cve_resolve, AREA_CVE);
    collega!(on_references_kev_import, kev_import, AREA_KEV);
    collega!(on_references_kev_resolve, kev_resolve, AREA_KEV);
    {
        let handle = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_references_attack_withdraw(move |chiave| {
            if crate::lock::refuse_while_locked("references_attack_withdraw") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let frase = attack_withdraw(&window, &screen, chiave);
            say(&window, AREA_ATTACK, frase);
            refresh(&window, &screen);
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, SessionId, Timestamp};
    use lisi_services::ServiceError;
    use lisi_services::history::HistoryService;
    use lisi_services::taxii::{StoredTaxiiSubmission, TaxiiDestination};

    use super::{
        ReferencesScreen, SHOWN_SUBMISSIONS, TaxiiFields, anni, prepare_taxii, save_taxii,
        send_prepared, submissions_text, taxii, taxii_note,
    };

    const THIS_MODULE: &str = include_str!("references.rs");

    /// Una schermata su un archivio privato, con la parola d'ordine in una
    /// cartella del test.
    fn schermata(cartella: &tempfile::TempDir) -> ReferencesScreen {
        let Ok(database) = lisi_services::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        ReferencesScreen {
            history: HistoryService::new(database),
            sessions: Vec::new(),
            previewed: None,
            taxii_password: Some(cartella.path().join("taxii.protetto")),
            taxii_previewed: None,
        }
    }

    fn cartella() -> tempfile::TempDir {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella di prova deve potersi creare");
        };
        cartella
    }

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("amministratore.prova") else {
            panic!("nome di prova valido");
        };
        attore
    }

    fn campi<'a>(root: &'a str, collection: &'a str, password: &'a str) -> TaxiiFields<'a> {
        TaxiiFields {
            root,
            collection,
            username: "ufficio",
            password,
        }
    }

    const ADESSO: Timestamp = Timestamp::from_millis(1_800_000_000_000);

    #[test]
    fn la_nota_dice_che_senza_destinazione_non_esce_niente() {
        let completa = TaxiiDestination {
            api_root: String::from("https://taxii.example/api"),
            collection_id: String::from("osservabili"),
            username: Some(String::from("ufficio")),
        };
        let senza_nome = TaxiiDestination {
            username: None,
            ..completa.clone()
        };
        assert!(taxii_note(None, true, true).starts_with("Senza destinazione"));
        assert!(taxii_note(Some(&senza_nome), true, true).contains("non manda niente"));
        assert!(taxii_note(Some(&completa), false, true).contains("non manda niente"));
        assert!(!taxii_note(Some(&completa), true, true).contains("non manda niente"));
        for nota in [
            taxii_note(None, false, true),
            taxii_note(Some(&completa), true, false),
        ] {
            assert!(nota.contains("questo utente di Windows"), "{nota}");
        }
        // L'operatore sa perché i campi sono spenti.
        assert!(taxii_note(None, false, false).contains("modalità amministratore"));
        assert!(!taxii_note(None, false, true).contains("modalità amministratore"));
    }

    #[test]
    fn l_amministratore_salva_la_destinazione_e_l_operatore_no() {
        let cartella = cartella();
        let mut schermata = schermata(&cartella);
        assert_eq!(
            save_taxii(
                &mut schermata,
                &campi(
                    " https://taxii.example/api/ ",
                    "osservabili",
                    "parola di prova"
                ),
                OperatingMode::Administrator,
                &attore(),
                ADESSO,
            ),
            Ok("Destinazione e parola d'ordine salvate.")
        );
        let Ok(servizio) = taxii(&mut schermata) else {
            panic!("la cartella dei dati c'è");
        };
        assert!(servizio.has_password());
        assert_eq!(
            servizio
                .destination()
                .ok()
                .flatten()
                .map(|d| d.collection_id),
            Some(String::from("osservabili"))
        );

        // Una radice in chiaro si rifiuta e lascia quella di prima.
        assert!(
            save_taxii(
                &mut schermata,
                &campi("http://taxii.example/api", "altra", ""),
                OperatingMode::Administrator,
                &attore(),
                ADESSO,
            )
            .is_err()
        );
        // L'operatore non scrive: il rifiuto viene dal servizio.
        assert_eq!(
            save_taxii(
                &mut schermata,
                &campi("https://altro.example/api", "altra", ""),
                OperatingMode::Operator,
                &attore(),
                ADESSO,
            ),
            Err(ServiceError::ActionReservedToAdministrator {
                action: lisi_core::RestrictedAction::ChooseTaxiiDestination,
            }
            .operator_message())
        );
        let Ok(servizio) = taxii(&mut schermata) else {
            panic!("la cartella dei dati c'è");
        };
        assert_eq!(
            servizio.destination().ok().flatten().map(|d| d.api_root),
            Some(String::from("https://taxii.example/api/"))
        );
    }

    #[test]
    fn svuotare_la_destinazione_toglie_la_parola_d_ordine() {
        let cartella = cartella();
        let mut schermata = schermata(&cartella);
        let scrivi = |schermata: &mut ReferencesScreen, campi: &TaxiiFields<'_>| {
            save_taxii(
                schermata,
                campi,
                OperatingMode::Administrator,
                &attore(),
                ADESSO,
            )
        };
        assert!(
            scrivi(
                &mut schermata,
                &campi(
                    "https://taxii.example/api",
                    "osservabili",
                    "parola di prova"
                )
            )
            .is_ok()
        );
        // Lasciata vuota, la parola di prima resta.
        assert_eq!(
            scrivi(
                &mut schermata,
                &campi("https://taxii.example/api", "osservabili", "")
            ),
            Ok("Destinazione salvata.")
        );
        assert!(taxii(&mut schermata).is_ok_and(|servizio| servizio.has_password()));

        assert!(scrivi(&mut schermata, &campi(" ", "", "")).is_ok());
        let Ok(servizio) = taxii(&mut schermata) else {
            panic!("la cartella dei dati c'è");
        };
        assert!(!servizio.has_password());
        assert_eq!(servizio.destination().ok(), Some(None));
    }

    #[test]
    fn si_manda_soltanto_cio_che_si_e_preparato() {
        let cartella = cartella();
        let mut schermata = schermata(&cartella);
        let (uno, due) = (SessionId::new(1), SessionId::new(2));

        // Senza anteprima non si manda.
        assert!(send_prepared(&mut schermata, Some(uno), ADESSO).starts_with("Prima si prepara"));

        // Senza destinazione l'anteprima lo dice, e non si può confermare.
        let (frase, pronto) = prepare_taxii(&mut schermata, Some(uno));
        assert_eq!(
            frase,
            ServiceError::TaxiiDestinationMissing.operator_message()
        );
        assert!(!pronto);
        assert_eq!(schermata.taxii_previewed, None);
        assert_eq!(
            prepare_taxii(&mut schermata, None),
            (String::from("Nessun monitoraggio scelto."), false)
        );

        // Un altro monitoraggio scelto dopo l'anteprima si rifiuta, e la
        // conferma non vale più.
        schermata.taxii_previewed = Some(uno);
        assert!(
            send_prepared(&mut schermata, Some(due), ADESSO).contains("non è quello preparato")
        );
        assert_eq!(schermata.taxii_previewed, None);
        assert!(send_prepared(&mut schermata, Some(uno), ADESSO).starts_with("Prima si prepara"));

        let Ok(servizio) = taxii(&mut schermata) else {
            panic!("la cartella dei dati c'è");
        };
        assert_eq!(servizio.submissions().ok().map(|r| r.len()), Some(0));
    }

    #[test]
    fn il_registro_si_legge_invio_per_invio() {
        let riga = |outcome: &str, conti: Option<(u64, u64, u64)>, detail: Option<&str>| {
            StoredTaxiiSubmission {
                id: 1,
                requested_by: String::from("operatore di prova"),
                requested_at: Timestamp::from_millis(0),
                url: String::from("https://taxii.example/api/collections/c/objects/"),
                session_id: 1,
                objects: 3,
                body_sha256: "0".repeat(64),
                http_status: Some(if outcome == "consegnato" { 202 } else { 401 }),
                outcome: outcome.to_owned(),
                outcome_detail: detail.map(str::to_owned),
                status_id: None,
                success_count: conti.map(|c| c.0),
                failure_count: conti.map(|c| c.1),
                pending_count: conti.map(|c| c.2),
            }
        };
        assert_eq!(submissions_text(&[]), "Nessun invio a TAXII finora.");
        let testo = submissions_text(&[
            riga("consegnato", Some((2, 1, 0)), None),
            riga(
                "non_consegnato",
                None,
                Some("la destinazione non riconosce il nome"),
            ),
        ]);
        let righe: Vec<&str> = testo.lines().collect();
        assert_eq!(righe.len(), 3);
        assert!(righe[1].ends_with(
            "operatore di prova: 3 oggetti, preso (2 accettati, 1 rifiutati, 0 in attesa)"
        ));
        assert!(
            righe[2].ends_with(": 3 oggetti, non preso (la destinazione non riconosce il nome)")
        );

        let molte: Vec<StoredTaxiiSubmission> = (0..15)
            .map(|_| riga("non_consegnato", None, None))
            .collect();
        assert_eq!(
            submissions_text(&molte).lines().count(),
            1 + SHOWN_SUBMISSIONS
        );
    }

    /// Gli anni si leggono separati da virgole o spazi; un anno non valido si
    /// dice.
    #[test]
    fn gli_anni_si_leggono_o_si_rifiutano() {
        assert_eq!(anni("2024, 2025 2026"), Ok(vec![2024, 2025, 2026]));
        assert!(anni("2024, venti").is_err());
    }

    /// **La schermata non calcola nulla**: nessun punteggio — la rete la vieta
    /// già la guardia di `no_ai_guard` —, e le frasi delle risposte le compone il
    /// dominio.
    #[test]
    fn la_schermata_non_calcola_e_non_scarica() {
        let Some((codice, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("blocco di prove riconoscibile");
        };
        // L'UNICA ECCEZIONE È LA FRASE DEL PUNTEGGIO, composta dal dominio e
        // mostrata soltanto nella scheda della CVE (CVSS-01, ADR-0184): la
        // schermata la riceve e non calcola niente.
        let codice = codice
            .replace("lisi_services::cve_scores::sentence(", "")
            .replace("IL PUNTEGGIO, SOLTANTO QUI", "");
        for vietato in ["cvss", "score", "punteggio"] {
            assert!(
                !codice.to_lowercase().contains(&vietato.to_lowercase()),
                "«{vietato}» nella schermata dei riferimenti"
            );
        }
        for frase in ["esito.as_sentence(", "associazione.as_sentence()"] {
            assert!(
                codice.contains(frase),
                "la frase la compone il dominio: {frase}"
            );
        }
    }
}

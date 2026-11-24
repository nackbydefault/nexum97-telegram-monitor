//! Collegamento fra la schermata **Live condiviso** e i servizi della squadra
//! (TEAM-LIVE-01, ADR-0093).
//!
//! # Che cosa mostra
//!
//! Che cosa è questa postazione — Hub, client, oppure Standalone —, lo stato
//! dell'ultimo collegamento, fin dove è arrivata, e le righe del live: che cosa
//! l'Hub ha acquisito, da quale fonte, con quale livello.
//!
//! **Non mostra i messaggi.** Il live condiviso dice che cosa accade, non che
//! cosa è scritto: il contenuto monitorato resta sull'Hub, e il flusso porta
//! fatti dell'attività (ADR-0093, decisione 1).
//!
//! # Che cosa non offre
//!
//! Nessun comando sul lavoro altrui: prendere in carico, assegnare e rivedere
//! sono di TEAM-REVIEW-01, TEAM-WQ-01 e TEAM-ASSIGN-01, e richiedono
//! un'identità di **operatore** autenticata che ancora non esiste. Un pulsante
//! che ci fosse adesso attribuirebbe un atto a un segnaposto.
//!
//! # Perché la sessione la chiede una persona
//!
//! Il collegamento all'Hub non gira in sottofondo: l'operatore chiede
//! «Aggiorna dall'Hub» e la sessione è **breve** (`with_screen_limits`), così
//! che la finestra non resti ferma. Ciò che resta indietro lo recupera la
//! richiesta successiva: il cursore è conservato, e nulla si perde.

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::model::hub_access::HubRole;
use lisi_core::model::hub_client::HubAddress;
use lisi_core::model::hub_person::{Passphrase, PersonId, PersonState};
use lisi_core::model::hub_presence::PresenceSnapshot;
use lisi_core::role::OperatingMode;
use lisi_services::Database;
use lisi_services::acquisition_authority::StationAuthorityService;
use lisi_services::device_identity::DeviceIdentityService;
use lisi_services::hub_backup::HubBackupService;
use lisi_services::hub_catchup::HubCatchUpService;
use lisi_services::hub_client::EnrollmentForm;
use lisi_services::hub_client::{
    HubClientService, HubConnectionStore, ReviewSessionOutcome, SessionOutcome,
};
use lisi_services::hub_client::{HubReviewSession, SharedCoverageAnswer};
use lisi_services::hub_live::HubLiveFeed;
use lisi_services::hub_server::{HubServerService, HubServerStore, RunningHub};
use lisi_services::station::persisted_mode_or_restricted;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, TeamLiveRow, TeamPresenceRow};

/// Indice della pagina Live condiviso nell'interfaccia.
///
/// Usato solo dalla prova che lo lega al file `.slint`: la navigazione avviene
/// nella voce di menu, non da Rust.
#[cfg(test)]
const TEAM_LIVE_PAGE: i32 = 27;

/// Quante righe del live si mostrano.
///
/// La proiezione ne conserva cinquecento (ADR-0093, decisione 3); a schermo ne
/// bastano molte meno, e chiederle tutte a ogni aggiornamento sarebbe lavoro
/// buttato.
const RIGHE_A_SCHERMO: usize = 100;

/// Vero quando questa postazione ha un indirizzo di ascolto configurato, cioè
/// quando fa da Hub.
///
/// Serve al ciclo di acquisizione, che pubblica il live **solo** sull'Hub.
#[must_use]
pub fn questa_postazione_e_un_hub() -> bool {
    crate::account::data_root().is_some_and(|root| HubServerStore::in_directory(&root).exists())
}

/// Lo stato della schermata, condiviso fra i gestori dei comandi.
pub struct TeamLive {
    feed: HubLiveFeed,
    client: HubClientService,
    server: HubServerService,
    authority: StationAuthorityService,
    /// Le reti dell'ufficio della postazione (HUB-SITES-01, ADR-0198).
    networks: lisi_services::office_networks::OfficeNetworksStore,
    /// L'archivio dove la dichiarazione delle reti resta registrata.
    networks_archive: std::path::PathBuf,
    /// L'Hub acceso, finché una persona non lo spegne.
    running: RefCell<Option<RunningHub>>,
    /// L'esito dell'ultima azione, per l'operatore.
    message: RefCell<String>,
    /// Chi è collegato all'Hub, l'ultima volta che si è chiesto.
    ///
    /// Non si conserva da nessuna parte: vive quanto la schermata, come vive
    /// quanto la porta aperta sull'Hub (ADR-0096, decisione 1).
    presence: RefCell<Vec<TeamPresenceRow>>,
    /// Che cosa dice la presenza nel suo insieme, o perché non si sa.
    presence_summary: RefCell<String>,
    /// La copertura dell'ufficio, come l'Hub l'ha calcolata (HUB-COVERAGE-01,
    /// ADR-0199). Come la presenza, non si conserva da nessuna parte.
    coverage: RefCell<String>,
    /// La copia di sicurezza dell'ufficio (TEAM-BACKUP-01, ADR-0101).
    backups: HubBackupService,
    /// L'esito dell'ultima copia.
    backup_message: RefCell<String>,
    /// Se l'ultima copia non è riuscita.
    backup_failed: RefCell<bool>,
    /// Il foglietto dell'arruolamento, finché chi amministra non lo toglie
    /// (ADR-0132, decisione 5). Vive solo qui: non si scrive da nessuna parte.
    sheet: RefCell<String>,
    /// Le persone dell'ufficio, sull'archivio di questa postazione: servono solo
    /// quando la postazione fa da Hub (FINAL-REVIEW-01, FR-047).
    people: lisi_services::hub_people::HubPeopleService,
    /// L'esito dell'ultima azione sulle persone.
    people_message: RefCell<String>,
}

/// Lo stato condiviso.
pub type SharedTeamLive = Rc<TeamLive>;

/// Costruisce la schermata, se gli archivi e le configurazioni sono apribili.
#[must_use]
pub fn create_service(
    feed_database: Option<Database>,
    client_database: Option<Database>,
    backup_database: Option<Database>,
    people_database: Option<Database>,
) -> Option<SharedTeamLive> {
    let root = crate::account::data_root()?;
    let archivio = root.join(lisi_services::sources::DATABASE_FILE);

    let identita = DeviceIdentityService::default_location().ok()?;
    let configurazione = HubConnectionStore::default_location().ok()?;
    let client = HubClientService::new(
        HubCatchUpService::new(client_database?),
        identita,
        configurazione,
    )
    .with_default_office_networks()
    .with_screen_limits();

    Some(Rc::new(TeamLive {
        feed: HubLiveFeed::new(feed_database?),
        client,
        server: con_il_nome(HubServerService::new(root.clone(), archivio.clone())),
        networks: lisi_services::office_networks::OfficeNetworksStore::in_directory(&root),
        networks_archive: archivio,
        authority: StationAuthorityService::in_directory(&root),
        running: RefCell::new(None),
        message: RefCell::new(String::new()),
        presence: RefCell::new(Vec::new()),
        presence_summary: RefCell::new(String::new()),
        coverage: RefCell::new(String::new()),
        backups: HubBackupService::new(backup_database?, &root),
        backup_message: RefCell::new(String::new()),
        backup_failed: RefCell::new(false),
        sheet: RefCell::new(String::new()),
        people: lisi_services::hub_people::HubPeopleService::new(people_database?),
        people_message: RefCell::new(String::new()),
    }))
}

impl TeamLive {
    /// Che cosa è questa postazione, in una riga.
    fn role_label(&self) -> String {
        if self.running.borrow().is_some() {
            return String::from("Hub — la porta è aperta e serve le postazioni dell'ufficio");
        }
        match self.server.address() {
            Ok(Some(indirizzo)) => {
                format!("Hub — configurato su {indirizzo}, in ascolto solo quando attivato")
            }
            Ok(None) | Err(_) => {
                if self.authority.role().may_acquire() {
                    String::from(
                        "Da sola — questa postazione acquisisce da sé e non segue alcun Hub",
                    )
                } else {
                    String::from("Collegata — questa postazione segue l'Hub configurato")
                }
            }
        }
    }

    /// Fin dove la postazione è arrivata sulla storia dell'Hub.
    fn position_label(&self) -> String {
        match self.client.catch_up().cursor() {
            Ok(Some(cursore)) => format!(
                "Ricevuto fino all'evento numero {} della storia {}",
                cursore.last_applied,
                cursore.stream.to_hex()
            ),
            Ok(None) => String::from("Nessun evento ricevuto finora da questo Hub"),
            Err(error) => error.operator_message(),
        }
    }

    /// Le righe del live, dalla più recente.
    fn rows(&self) -> Vec<TeamLiveRow> {
        match self.feed.latest(RIGHE_A_SCHERMO) {
            Ok(eventi) => eventi
                .iter()
                .map(|evento| TeamLiveRow {
                    when: SharedString::from(evento.recorded_at.to_readable_local()),
                    kind: SharedString::from(etichetta_del_tipo(evento.kind)),
                    subject: SharedString::from(evento.subject.as_str()),
                    detail: SharedString::from(
                        evento.detail.as_ref().map_or("", |detail| detail.as_str()),
                    ),
                    sequence: crate::lingua::schermo(format!("n. {}", evento.sequence)),
                })
                .collect(),
            Err(error) => {
                tracing::warn!(kind = error.kind(), "live condiviso non leggibile");
                Vec::new()
            }
        }
    }

    /// Chiede all'Hub ciò che manca, in una sessione breve.
    fn refresh_from_hub(&self) -> String {
        self.refresh_presence();
        let esito = self
            .client
            .run_session_with(crate::account::now(), |evento| self.feed.apply(evento));
        match esito {
            Ok(rapporto) => match rapporto.outcome {
                SessionOutcome::CaughtUp { latest } => format!(
                    "Allineato con l'Hub: {} eventi applicati, ultimo numero {latest}.",
                    rapporto.applied
                ),
                SessionOutcome::Truncated { reason } => String::from(reason.operator_message()),
                SessionOutcome::Stopped { stop } => String::from(stop.operator_message()),
                SessionOutcome::Unreachable => String::from(
                    "L'Hub non risponde. Riprovare più tardi; se non risponde nemmeno allora, \
                     chiedere a chi amministra se l'Hub è acceso.",
                ),
                SessionOutcome::NotTheExpectedHub => String::from(
                    "All'indirizzo dell'Hub risponde una chiave diversa da quella attesa. Il \
                     collegamento si è fermato e la configurazione non è stata modificata: \
                     serve una persona che verifichi presso chi amministra.",
                ),
                SessionOutcome::Refused { reason }
                | SessionOutcome::UnexpectedAnswer { reason } => String::from(reason),
            },
            Err(error) => error.operator_message(),
        }
    }

    /// Rilegge chi è collegato all'Hub.
    ///
    /// Una sessione breve, come tutte quelle di questa schermata: la presenza
    /// è vera adesso, e tenere una connessione aperta per guardarla sarebbe
    /// tenere aperta una connessione per guardare delle persone.
    ///
    /// Un Hub che non offre la capacità **lo fa dire alla schermata**, invece
    /// di lasciarle mostrare «nessuno collegato» (ADR-0096, decisione 6).
    fn refresh_presence(&self) {
        let mut sessione = match self.client.open_review_session(crate::account::now()) {
            Ok(ReviewSessionOutcome::Ready(sessione)) => *sessione,
            Ok(altro) => {
                self.presence.borrow_mut().clear();
                self.coverage.borrow_mut().clear();
                *self.presence_summary.borrow_mut() = altro
                    .refusal_message()
                    .unwrap_or_else(|| String::from("La sessione con l'Hub non si è aperta."));
                return;
            }
            Err(errore) => {
                self.presence.borrow_mut().clear();
                self.coverage.borrow_mut().clear();
                *self.presence_summary.borrow_mut() = errore.operator_message();
                return;
            }
        };
        let esito = sessione.presence(RIGHE_DELLA_PRESENZA);
        *self.coverage.borrow_mut() = copertura_dell_ufficio(&mut sessione);
        sessione.close();

        match esito {
            Ok(Some(fotografia)) => {
                *self.presence.borrow_mut() = fotografia
                    .stations
                    .iter()
                    .map(|riga| TeamPresenceRow {
                        station: crate::lingua::schermo(format!("postazione.{}", riga.device)),
                        since: crate::lingua::schermo(format!(
                            "Collegata dalle {}",
                            riga.connected_since.to_readable_local()
                        )),
                        last_seen: crate::lingua::schermo(format!(
                            "Vista dall'Hub alle {}",
                            riga.last_seen.to_readable_local()
                        )),
                    })
                    .collect();
                *self.presence_summary.borrow_mut() = sommario_della_presenza(&fotografia);
            }
            Ok(None) => {
                self.presence.borrow_mut().clear();
                *self.presence_summary.borrow_mut() = String::from(
                    "Questo Hub non dice chi è collegato: l'elenco non è vuoto, non si sa.",
                );
            }
            Err(errore) => {
                self.presence.borrow_mut().clear();
                *self.presence_summary.borrow_mut() = errore.operator_message();
            }
        }
    }

    /// Scrive la copia dell'ufficio.
    ///
    /// La cartella la sceglie una persona da una finestra di sistema: una
    /// cartella scelta così **esiste per costruzione**, e non c'è un testo da
    /// convalidare che possa contenere qualcosa di inatteso (DEC-113).
    ///
    /// La copia nasce nella cartella dati di questa postazione e **parte solo
    /// dopo essere stata verificata** (ADR-0101, decisione 2).
    fn backup_to(&self, destinazione: &std::path::Path) -> (String, bool) {
        let Some(radice) = crate::account::data_root() else {
            return (
                String::from("La cartella dati di questa postazione non è raggiungibile."),
                true,
            );
        };

        let Ok(attore) = crate::operator::audit_actor() else {
            return (
                String::from("Identità dell'operatore non utilizzabile: segnalarlo."),
                true,
            );
        };
        match self
            .backups
            .write_to(destinazione, &radice, &attore, crate::account::now())
        {
            Ok(copia) => {
                let fallita = !copia.staging_removed;
                (copia.operator_message(), fallita)
            }
            Err(errore) => {
                tracing::warn!(kind = errore.kind(), "copia dell'ufficio non riuscita");
                (errore.operator_message(), true)
            }
        }
    }

    /// Scrive l'indirizzo su cui questa postazione ascolterà.
    fn save_listen_address(&self, testo: &str) -> String {
        let indirizzo = match HubAddress::parse(testo) {
            Ok(indirizzo) => indirizzo,
            Err(errore) => {
                return format!(
                    "L'indirizzo non è utilizzabile: {errore}. Serve un indirizzo di rete in cifre, con la sua \
                     porta, per esempio 192.168.1.10:8443."
                );
            }
        };
        match self.server.configure(
            &indirizzo,
            &crate::operator::current(),
            crate::account::now(),
        ) {
            Ok(()) => format!(
                "Indirizzo salvato: {indirizzo}. La porta non è ancora aperta: si apre con \
                 «Attiva modalità Hub»."
            ),
            Err(error) => error.operator_message(),
        }
    }

    /// Apre la porta dell'Hub.
    fn activate(&self) -> String {
        if self.running.borrow().is_some() {
            return String::from("La modalità Hub è già attiva.");
        }
        match self
            .server
            .activate(&crate::operator::current(), crate::account::now())
        {
            Ok(acceso) => {
                let indirizzo = acceso.local_addr();
                let impronta = acceso.fingerprint().prefix().to_readable();
                *self.running.borrow_mut() = Some(acceso);
                format!(
                    "Modalità Hub attiva su {indirizzo}. Impronta da consegnare con il codice di \
                     arruolamento: {impronta}"
                )
            }
            Err(error) => error.operator_message(),
        }
    }

    /// Dichiara le reti dell'ufficio (HUB-SITES-01, ADR-0198).
    ///
    /// Un'azione riservata: il servizio la rifiuta in modalità operatore, e la
    /// scrive nel registro delle operazioni.
    fn declare_networks(&self, testo: &str) -> String {
        let Ok(archivio) = lisi_services::Database::open(&self.networks_archive) else {
            return String::from(
                "L'archivio non si apre: le reti dell'ufficio non sono state dichiarate.",
            );
        };
        match self.networks.declare(
            &archivio,
            testo,
            persisted_mode_or_restricted(),
            &crate::operator::current(),
            crate::account::now(),
        ) {
            Ok(reti) if reti.declared().is_empty() => String::from(
                "Nessuna rete dichiarata: valgono soltanto le reti che Internet non instrada.",
            ),
            Ok(reti) => format!("Reti dell'ufficio dichiarate: {}.", reti.to_text()),
            Err(error) => error.operator_message(),
        }
    }

    /// Che cosa vale, detto all'operatore: le reti sempre ammesse, quelle
    /// dichiarate e, fra queste, quelle che Internet instrada.
    fn networks_note(&self) -> String {
        let reti = match self.networks.load() {
            Ok(reti) => reti,
            Err(error) => return error.operator_message(),
        };
        let pubbliche = reti.declared_routed_on_internet();
        if pubbliche.is_empty() {
            return String::from(
                "Valgono sempre gli indirizzi privati, quelli dei collegamenti fra le sedi e \
                 questo computer. Internet non li instrada.",
            );
        }
        let elenco = pubbliche
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Valgono sempre gli indirizzi privati, quelli dei collegamenti fra le sedi e questo \
             computer. Internet instrada invece {elenco}: dichiararle vuol dire che l'ufficio \
             le usa al proprio interno."
        )
    }

    /// Accetta o non accetta più comandi a distanza (HUB-REMOTE-01, ADR-0200):
    /// la nona azione riservata, che resta nel registro delle operazioni.
    fn choose_remote(&self, accetta: bool) -> String {
        let mut archivio = match lisi_services::Database::open(&self.networks_archive) {
            Ok(archivio) => archivio,
            Err(_) => {
                return String::from(
                    "L'archivio non si apre: la scelta sui comandi a distanza non è cambiata.",
                );
            }
        };
        let Ok(chi) = crate::operator::audit_actor() else {
            return String::from("Identità dell'operatore non utilizzabile: segnalarlo.");
        };
        match lisi_services::remote_commands::choose(
            &mut archivio,
            accetta,
            persisted_mode_or_restricted(),
            &chi,
            crate::account::now(),
        ) {
            Ok(frase) => frase,
            Err(error) => error.operator_message(),
        }
    }

    /// Se l'Hub accetta comandi a distanza, che cosa vale e gli ultimi
    /// ricevuti. Vuoto su una postazione che non è un Hub.
    fn remote_state(&self) -> (bool, String, String) {
        if !questa_postazione_e_un_hub() {
            return (false, String::new(), String::new());
        }
        let archivio = match lisi_services::Database::open(&self.networks_archive) {
            Ok(archivio) => archivio,
            Err(_) => {
                return (
                    false,
                    String::from("L'archivio non si apre: i comandi a distanza non si leggono."),
                    String::new(),
                );
            }
        };
        let accettati = lisi_services::remote_commands::accepted(&archivio).unwrap_or(false);
        let nota = match lisi_services::remote_commands::status_sentence(&archivio) {
            Ok(frase) => crate::lingua::schermo(frase).to_string(),
            Err(error) => error.operator_message(),
        };
        let registro = match lisi_services::remote_commands::recent(&archivio) {
            Ok(righe) if righe.is_empty() => {
                crate::lingua::schermo("Nessun comando a distanza ricevuto.").to_string()
            }
            Ok(righe) => righe
                .iter()
                .map(lisi_services::remote_commands::as_sentence)
                .collect::<Vec<_>>()
                .join("\n"),
            Err(error) => error.operator_message(),
        };
        (accettati, nota, registro)
    }

    /// Chiude la porta dell'Hub.
    fn deactivate(&self) -> String {
        let acceso = self.running.borrow_mut().take();
        let Some(acceso) = acceso else {
            return String::from("La modalità Hub non è attiva.");
        };
        let da_fuori = acceso.refused_outside();
        acceso.stop();
        if let Err(error) = self.server.record_deactivation(
            &crate::operator::current(),
            crate::account::now(),
            da_fuori,
        ) {
            return error.operator_message();
        }
        String::from("Modalità Hub disattivata: la porta è chiusa.")
    }

    /// Vero se questa postazione fa da Hub, acceso o soltanto configurato.
    fn fa_da_hub(&self) -> bool {
        self.running.borrow().is_some() || matches!(self.server.address(), Ok(Some(_)))
    }

    /// Emette un codice e mostra il foglietto (ADR-0132, decisione 5).
    ///
    /// **Solo l'amministratore**, e il controllo sta qui, non solo nel pulsante
    /// nascosto: emettere un'autorizzazione cambia l'ufficio.
    fn issue_sheet(&self) -> String {
        if !in_modalita_amministratore() {
            return String::from(SOLO_AMMINISTRATORE);
        }
        match self
            .server
            .issue_enrollment_sheet(&crate::operator::current(), crate::account::now())
        {
            Ok(foglietto) => {
                *self.sheet.borrow_mut() = foglietto.text_for_the_administrator();
                let porta = if self.running.borrow().is_some() {
                    "La porta dell'Hub è aperta."
                } else {
                    "La porta dell'Hub è chiusa: aprirla con «Attiva modalità Hub» prima che il \
                     codice scada."
                };
                format!(
                    "Codice emesso. Ricopiare a mano il foglietto, o dettarlo di persona: non \
                     verrà mostrato una seconda volta. {porta}"
                )
            }
            Err(errore) => errore.operator_message(),
        }
    }

    /// Toglie il foglietto dallo schermo. Non si rivede più.
    fn hide_sheet(&self) -> String {
        self.sheet.borrow_mut().clear();
        String::from("Foglietto tolto dallo schermo. Il codice vale ancora fino alla scadenza.")
    }

    /// Collega questa postazione all'Hub del foglietto (ADR-0132).
    ///
    /// **Solo l'amministratore**: da questo momento la postazione smette di
    /// acquisire da sola, ed è una decisione che cambia l'ufficio.
    ///
    /// Restituisce la frase per l'operatore e se, da ora, la postazione segue
    /// l'Hub: chi chiama deve allora togliere l'autorità di acquisire alla
    /// sessione dell'account (FINAL-REVIEW-01, FR-003).
    fn connect(&self, indirizzo: &str, impronta: &str, codice: &str, nome: &str) -> (String, bool) {
        if !in_modalita_amministratore() {
            return (String::from(SOLO_AMMINISTRATORE), false);
        }
        if self.fa_da_hub() {
            return (
                String::from(
                    "Questa postazione fa da Hub: non può seguirne un altro. Un ufficio ha un \
                     solo Hub.",
                ),
                false,
            );
        }
        let modulo = match EnrollmentForm::parse(indirizzo, impronta, codice, nome) {
            Ok(modulo) => modulo,
            Err(frase) => return (frase, false),
        };
        match self
            .client
            .enroll(modulo, &crate::operator::current(), crate::account::now())
        {
            Ok(esito) => (esito.operator_message(), esito.is_connected()),
            Err(errore) => (errore.operator_message(), false),
        }
    }
}

impl TeamLive {
    /// Le persone dell'ufficio, per la schermata.
    fn people_rows(&self) -> Vec<crate::HubPersonRow> {
        if !self.fa_da_hub() {
            return Vec::new();
        }
        match self.people.people() {
            Ok(persone) => persone
                .iter()
                .map(|persona| crate::HubPersonRow {
                    id: SharedString::from(persona.id.as_str()),
                    name: SharedString::from(persona.label.as_str()),
                    role: crate::lingua::schermo(persona.role.label()),
                    state: SharedString::from(match persona.state {
                        PersonState::Active => "attiva",
                        PersonState::Suspended => "sospesa",
                    }),
                    active: persona.state == PersonState::Active,
                })
                .collect(),
            Err(errore) => {
                *self.people_message.borrow_mut() = errore.operator_message();
                Vec::new()
            }
        }
    }

    /// Il controllo comune ai comandi sulle persone: modalità amministratore,
    /// e postazione che fa da Hub. Sta qui, dove il comando gira, e non solo
    /// nel pulsante nascosto (ADR-0132, decisione 5).
    fn chi_amministra(&self) -> Result<lisi_core::model::identity::OperatorId, String> {
        if !in_modalita_amministratore() {
            return Err(String::from(SOLO_AMMINISTRATORE));
        }
        if !self.fa_da_hub() {
            return Err(String::from(
                "Le persone dell'ufficio si creano sulla postazione che fa da Hub.",
            ));
        }
        Ok(crate::operator::current())
    }

    /// Crea una persona dell'ufficio (FINAL-REVIEW-01, FR-047).
    fn create_person(&self, id: &str, nome: &str, ruolo: i32, frase: &str) -> String {
        let amministratore = match self.chi_amministra() {
            Ok(chi) => chi,
            Err(frase) => return frase,
        };
        let Ok(id) = PersonId::parse(id.trim()) else {
            return String::from(
                "L'identificativo non è utilizzabile: da tre a trentadue caratteri fra lettere, \
                 cifre, trattino e trattino basso, senza spazi né punti.",
            );
        };
        let Ok(nome) = lisi_core::text::DisplayName::try_new(nome.trim()) else {
            return String::from("Il nome non è utilizzabile.");
        };
        let Ok(frase) = Passphrase::try_new(frase) else {
            return String::from("La frase deve avere almeno dodici caratteri.");
        };
        let ruolo = if ruolo == 1 {
            HubRole::Administrator
        } else {
            HubRole::Operator
        };
        match self.people.create_on_the_hub(
            &amministratore,
            &id,
            &nome,
            ruolo,
            &frase,
            crate::account::now(),
        ) {
            Ok(persona) => format!(
                "{} può entrare con l'identificativo «{}» e la frase consegnata di persona.",
                persona.label.as_str(),
                persona.id.as_str()
            ),
            Err(errore) => errore.operator_message(),
        }
    }

    /// Sospende una persona attiva, o riattiva una sospesa.
    fn toggle_person(&self, id: &str) -> String {
        let amministratore = match self.chi_amministra() {
            Ok(chi) => chi,
            Err(frase) => return frase,
        };
        let Ok(id) = PersonId::parse(id) else {
            return String::from("Persona non riconosciuta.");
        };
        let attuale = self
            .people
            .people()
            .ok()
            .and_then(|persone| persone.into_iter().find(|persona| persona.id == id))
            .map(|persona| persona.state);
        let Some(attuale) = attuale else {
            return String::from("Persona non trovata.");
        };
        let nuovo = match attuale {
            PersonState::Active => PersonState::Suspended,
            PersonState::Suspended => PersonState::Active,
        };
        match self
            .people
            .set_state_on_the_hub(&amministratore, &id, nuovo, crate::account::now())
        {
            Ok(()) => match nuovo {
                PersonState::Active => String::from("La persona può entrare di nuovo."),
                PersonState::Suspended => {
                    String::from("La persona è sospesa: non entra più, e i suoi atti restano suoi.")
                }
            },
            Err(errore) => errore.operator_message(),
        }
    }

    /// Rimette la frase di una persona, con quella scritta nel campo.
    fn reset_person(&self, id: &str, frase: &str) -> String {
        let amministratore = match self.chi_amministra() {
            Ok(chi) => chi,
            Err(frase) => return frase,
        };
        let Ok(id) = PersonId::parse(id) else {
            return String::from("Persona non riconosciuta.");
        };
        if frase.is_empty() {
            return String::from(
                "Scrivere la nuova frase nel campo «Frase di accesso», poi premere di nuovo.",
            );
        }
        let Ok(frase) = Passphrase::try_new(frase) else {
            return String::from("La frase deve avere almeno dodici caratteri.");
        };
        match self.people.reset_passphrase_on_the_hub(
            &amministratore,
            &id,
            &frase,
            crate::account::now(),
        ) {
            Ok(()) => String::from("Frase rimessa. Consegnarla di persona."),
            Err(errore) => errore.operator_message(),
        }
    }
}

/// Che cosa dice un comando riservato quando la postazione è in modalità
/// operatore.
const SOLO_AMMINISTRATORE: &str = "Questo comando è riservato alla modalità amministratore. \
     Chiedere a chi amministra la postazione.";

/// Vero se la postazione è in modalità amministratore.
fn in_modalita_amministratore() -> bool {
    persisted_mode_or_restricted() == OperatingMode::Administrator
}

/// Il nome con cui questa postazione, se fa da Hub, si presenta alle altre.
///
/// Il nome del computer, perché è ciò che le persone di un ufficio
/// riconoscono, e perché **resta lo stesso** fra un avvio e l'altro: la
/// postazione arruolata lo conserva, e un nome che cambiasse le farebbe
/// credere di essere davanti a un altro Hub (ADR-0047 decisione 8).
fn con_il_nome(servizio: HubServerService) -> HubServerService {
    let nome = std::env::var("COMPUTERNAME")
        .ok()
        .and_then(|computer| lisi_core::text::DisplayName::try_new(computer.trim()).ok());
    match nome {
        Some(nome) => servizio.named(nome),
        None => servizio,
    }
}

/// Il nome proposto per questa postazione nel modulo di collegamento.
fn nome_proposto() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// Righe della presenza che questa schermata chiede.
///
/// Coincide con il tetto del protocollo: chiederne meno taglierebbe un elenco
/// che in un ufficio vero ci sta tutto.
const RIGHE_DELLA_PRESENZA: usize = 64;

/// Quanti monitoraggi dell'ufficio, dai più recenti, mostrano la copertura.
const MONITORAGGI_DELLA_COPERTURA: usize = 3;

/// La copertura dei monitoraggi più recenti dell'ufficio, come l'Hub l'ha
/// calcolata (HUB-COVERAGE-01, ADR-0199, decisione 5).
///
/// Si chiede nella stessa sessione della presenza, e si dice con le frasi della
/// schermata Monitoraggio: una sola voce, sull'Hub e su chi lo segue.
fn copertura_dell_ufficio(sessione: &mut HubReviewSession) -> String {
    let non_la_manda = || {
        crate::lingua::schermo(
            "Questo Hub non dice che cosa stava guardando l'ufficio: lo si legge sull'Hub.",
        )
        .to_string()
    };
    if !sessione.offre_la_copertura() {
        return non_la_manda();
    }
    let monitoraggi = match sessione.shared_sessions(MONITORAGGI_DELLA_COPERTURA) {
        Ok(Some(monitoraggi)) => monitoraggi,
        Ok(None) => return non_la_manda(),
        Err(errore) => return crate::lingua::schermo(errore.operator_message()).to_string(),
    };
    if monitoraggi.is_empty() {
        return crate::lingua::schermo(
            "L'ufficio non ha ancora monitoraggi: non c'è nulla da mostrare.",
        )
        .to_string();
    }
    let mut righe = Vec::new();
    for monitoraggio in monitoraggi.iter().take(MONITORAGGI_DELLA_COPERTURA) {
        if !righe.is_empty() {
            righe.push(String::new());
        }
        righe.push(format!("«{}»", monitoraggio.label));
        match sessione.shared_coverage(monitoraggio.id) {
            Ok(Some(SharedCoverageAnswer::Taken(copertura))) => {
                righe.push(
                    crate::lingua::schermo(format!(
                        "Calcolata dall'Hub alle {}: un minuto dopo può essere diversa.",
                        copertura.taken_at.to_readable_local()
                    ))
                    .to_string(),
                );
                righe.push(crate::coverage::overall_in_words(&copertura.overall));
                if !copertura.overall.intervals().is_empty() {
                    righe.push(crate::coverage::in_words(&copertura.overall));
                }
                for (nome, fonte) in &copertura.sources {
                    // Il nome della fonte è un dato: non si traduce.
                    let mut riga = nome.clone();
                    riga.push_str(": ");
                    riga.push_str(&lisi_services::coverage::totals_in_words(fonte));
                    righe.push(riga);
                }
            }
            Ok(Some(SharedCoverageAnswer::Refused(ragione))) => {
                righe.push(crate::lingua::schermo(ragione).to_string());
            }
            Ok(None) => return non_la_manda(),
            Err(errore) => {
                righe.push(crate::lingua::schermo(errore.operator_message()).to_string())
            }
        }
    }
    righe.join("\n")
}

/// Che cosa dice la presenza nel suo insieme.
fn sommario_della_presenza(fotografia: &PresenceSnapshot) -> String {
    if fotografia.is_empty() {
        return String::from(
            "Nessuna postazione collegata all'Hub in questo momento. Anche questa è una \
             fotografia: dice adesso, non oggi.",
        );
    }
    let oltre = fotografia.beyond();
    let resto = if oltre == 0 {
        String::new()
    } else {
        format!(" Altre {oltre} non sono mostrate.")
    };
    format!(
        "{} collegate. Fotografia dell'Hub delle {}.{resto}",
        fotografia.total,
        fotografia.composed_at.to_readable_local()
    )
}

/// L'etichetta con cui un tipo di evento compare nel live.
fn etichetta_del_tipo(kind: lisi_core::model::hub_event::HubEventKind) -> &'static str {
    use lisi_core::model::hub_event::HubEventKind as Tipo;

    match kind {
        Tipo::ReviewRecorded => "Revisione registrata",
        Tipo::MonitoringStarted => "Monitoraggio avviato",
        Tipo::MonitoringStopped => "Monitoraggio concluso",
        Tipo::ContentAcquired => "Contenuti acquisiti",
        Tipo::AlertRaised => "Avviso",
        Tipo::DeviceEnrolled => "Postazione ammessa",
        Tipo::DeviceRevoked => "Postazione ritirata",
        Tipo::DeviceRoleChanged => "Ruolo cambiato",
        Tipo::WorkAssigned => "Lavoro assegnato",
    }
}

/// Riporta nell'interfaccia lo stato della squadra e le righe del live.
pub fn refresh(window: &AppWindow, service: &SharedTeamLive) {
    window.set_team_live_role(crate::lingua::schermo(service.role_label()));
    window.set_team_live_position(crate::lingua::schermo(service.position_label()));
    window.set_team_live_rows(ModelRc::from(Rc::new(VecModel::from(service.rows()))));
    window.set_team_live_message(SharedString::from(service.message.borrow().clone()));
    window.set_team_live_presence(ModelRc::from(Rc::new(VecModel::from(
        service.presence.borrow().clone(),
    ))));
    window.set_team_live_presence_summary(SharedString::from(
        service.presence_summary.borrow().clone(),
    ));
    window.set_team_live_coverage(SharedString::from(service.coverage.borrow().clone()));
    window
        .set_team_live_backup_message(SharedString::from(service.backup_message.borrow().clone()));
    window.set_team_live_backup_failed(*service.backup_failed.borrow());
    window.set_team_live_hub_running(service.running.borrow().is_some());
    let indirizzo = match service.server.address() {
        Ok(Some(indirizzo)) => indirizzo.to_string(),
        Ok(None) | Err(_) => String::new(),
    };
    window.set_team_live_hub_address(SharedString::from(indirizzo));
    // I COMANDI A DISTANZA (HUB-REMOTE-01, ADR-0200): se l'Hub li accetta, e
    // gli ultimi ricevuti.
    let (accettati, nota, registro) = service.remote_state();
    window.set_team_live_remote_accepted(accettati);
    window.set_team_live_remote_note(SharedString::from(nota));
    window.set_team_live_remote_log(SharedString::from(registro));
    // LE RETI DELL'UFFICIO (HUB-SITES-01, ADR-0198): quelle dichiarate, che
    // cosa vale, e quante connessioni da fuori l'Hub acceso ha chiuso.
    let dichiarate = service
        .networks
        .load()
        .map(|reti| reti.to_text())
        .unwrap_or_default();
    window.set_team_live_networks(SharedString::from(dichiarate));
    window.set_team_live_networks_note(crate::lingua::schermo(service.networks_note()));
    let rifiutate = service
        .running
        .borrow()
        .as_ref()
        .map_or(0, RunningHub::refused_outside);
    window.set_team_live_refused(if rifiutate == 0 {
        SharedString::new()
    } else {
        crate::lingua::schermo(format!(
            "Connessioni da fuori delle reti dell'ufficio chiuse prima della negoziazione: {rifiutate}."
        ))
    });
    window.set_team_live_sheet(SharedString::from(service.sheet.borrow().clone()));
    window.set_team_live_people(ModelRc::from(Rc::new(VecModel::from(
        service.people_rows(),
    ))));
    window
        .set_team_live_people_message(SharedString::from(service.people_message.borrow().clone()));
    // CHI PUO' FARE CHE COSA, deciso qui e non nella schermata: un Hub emette
    // codici, una postazione da sola si collega, una che segue gia' non fa
    // nessuna delle due (ADR-0132, decisione 5).
    let segue = !service.authority.role().may_acquire();
    window.set_team_live_can_issue(service.fa_da_hub() && !segue);
    window.set_team_live_can_connect(!service.fa_da_hub() && !segue);
    if window.get_team_live_station_name().is_empty() {
        window.set_team_live_station_name(SharedString::from(nome_proposto()));
    }
}

/// Collega i comandi della schermata ai servizi.
pub fn wire(window: &AppWindow, service: &SharedTeamLive, session: &crate::account::SharedSession) {
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_shown(move || {
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_refresh(move || {
            if crate::lock::refuse_while_locked("team_live_refresh") {
                return;
            }
            let esito = service.refresh_from_hub();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_backup(move || {
            if crate::lock::refuse_while_locked("team_live_backup") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            // Finestra chiusa senza scegliere: non e' un errore, e non si
            // annuncia nulla. Un messaggio dopo un annullamento fa credere che
            // sia successo qualcosa.
            let service = Rc::clone(&service);
            crate::dialogs::ask(
                &window,
                rfd::AsyncFileDialog::new()
                    .set_title("Scegliere la cartella dove portare la copia dell'ufficio"),
                crate::dialogs::Pick::Folder,
                "team_live_backup",
                move |window, destinazione| {
                    let (messaggio, fallita) = service.backup_to(&destinazione);
                    *service.backup_message.borrow_mut() = messaggio;
                    *service.backup_failed.borrow_mut() = fallita;
                    refresh(window, &service);
                },
            );
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_save_address(move |testo| {
            if crate::lock::refuse_while_locked("team_live_save_address") {
                return;
            }
            let esito = service.save_listen_address(testo.as_str());
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_choose_remote(move |accetta| {
            if crate::lock::refuse_while_locked("team_live_choose_remote") {
                return;
            }
            let esito = service.choose_remote(accetta);
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_declare_networks(move |testo| {
            if crate::lock::refuse_while_locked("team_live_declare_networks") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let esito = service.declare_networks(testo.as_str());
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_activate(move || {
            if crate::lock::refuse_while_locked("team_live_activate") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let esito = service.activate();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_deactivate(move || {
            if crate::lock::refuse_while_locked("team_live_deactivate") {
                return;
            }
            // Un prerequisito della fascia di prontezza puo' essere cambiato (F-08).
            crate::preflight::mark_stale();
            let esito = service.deactivate();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_issue_code(move || {
            if crate::lock::refuse_while_locked("team_live_issue_code") {
                return;
            }
            let esito = service.issue_sheet();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_hide_sheet(move || {
            if crate::lock::refuse_while_locked("team_live_hide_sheet") {
                return;
            }
            let esito = service.hide_sheet();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        let session = Rc::clone(session);
        window.on_team_live_connect(move |indirizzo, impronta, codice, nome| {
            if crate::lock::refuse_while_locked("team_live_connect") {
                return;
            }
            let (mut esito, segue_l_hub) = service.connect(
                indirizzo.as_str(),
                impronta.as_str(),
                codice.as_str(),
                nome.as_str(),
            );
            // UNA SOLA AUTORITÀ NELL'UFFICIO (FINAL-REVIEW-01, FR-003). Fino al
            // 2026-10-03 la postazione appena arruolata teneva aperto il suo
            // client TDLib fino al riavvio, mentre la frase diceva «non
            // acquisisce più da sola». Ora lo chiude adesso, e lo dice.
            if segue_l_hub && session.borrow_mut().relinquish_authority() {
                esito.push_str(
                    " L'account Telegram aperto su questa postazione è stato chiuso: i \
                     monitoraggi in corso qui non acquisiscono più, e si arrestano dalla \
                     schermata Monitoraggio.",
                );
            }
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                // Il codice digitato non resta nel campo, comunque sia andata:
                // e' un'autorizzazione, e uno schermo lasciato acceso la
                // mostrerebbe a chi passa.
                window.set_team_live_typed_code(SharedString::new());
                refresh(&window, &service);
            }
        });
    }
    // LE PERSONE DELL'UFFICIO (FINAL-REVIEW-01, FR-047). La frase non resta
    // nel campo dopo l'uso, comunque sia andata.
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_person_create(move || {
            if crate::lock::refuse_while_locked("team_live_person_create") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let esito = service.create_person(
                window.get_team_live_person_id().as_str(),
                window.get_team_live_person_name().as_str(),
                window.get_team_live_person_role(),
                window.get_team_live_person_passphrase().as_str(),
            );
            window.set_team_live_person_passphrase(SharedString::new());
            *service.people_message.borrow_mut() = esito;
            refresh(&window, &service);
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_person_toggle(move |id| {
            if crate::lock::refuse_while_locked("team_live_person_toggle") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            *service.people_message.borrow_mut() = service.toggle_person(id.as_str());
            refresh(&window, &service);
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_live_person_reset(move |id| {
            if crate::lock::refuse_while_locked("team_live_person_reset") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            let esito = service.reset_person(
                id.as_str(),
                window.get_team_live_person_passphrase().as_str(),
            );
            window.set_team_live_person_passphrase(SharedString::new());
            *service.people_message.borrow_mut() = esito;
            refresh(&window, &service);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{TEAM_LIVE_PAGE, etichetta_del_tipo};

    /// Interfaccia, letta a tempo di compilazione.
    const UI: &str = include_str!("../ui/app-window.slint");

    #[test]
    fn the_team_live_page_index_matches_the_interface() {
        assert!(
            UI.contains(&format!("current-page == {TEAM_LIVE_PAGE}: Rectangle")),
            "la pagina Live condiviso con indice {TEAM_LIVE_PAGE} non e' nell'interfaccia"
        );
        assert!(
            UI.contains(&format!("root.open-page({TEAM_LIVE_PAGE});")),
            "la voce di menu Live condiviso non naviga all'indice {TEAM_LIVE_PAGE}"
        );
    }

    /// **La schermata non offre comandi sul lavoro altrui** (ADR-0093,
    /// decisione 5).
    ///
    /// Prendere in carico, assegnare e rivedere richiedono un'identità di
    /// operatore autenticata che non esiste ancora: un pulsante che ci fosse
    /// adesso attribuirebbe un atto a un segnaposto.
    #[test]
    fn the_shared_live_offers_no_command_on_other_peoples_work() {
        let pagina = crate::page_guard::corpo_della_pagina(
            u32::try_from(TEAM_LIVE_PAGE).unwrap_or_default(),
        );
        for vietato in ["Prendi in carico", "Assegna", "Revoca", "Rivedi"] {
            assert!(
                !pagina.contains(vietato),
                "la schermata del live condiviso offre «{vietato}», che richiede un'identità di \
                 operatore autenticata (ADR-0093, decisione 5)"
            );
        }
    }

    /// **La riga della presenza porta tre cose, e nessuna in più**
    /// (TEAM-PRESENCE-01, ADR-0096, decisione 2).
    ///
    /// Aggiungere qui la schermata aperta, il contenuto in lettura o un tempo
    /// di inattività trasformerebbe «chi c'è» in «che cosa sta facendo un
    /// collega», che è guardare il collega invece del lavoro. La guardia legge
    /// **l'interfaccia**, perché è lì che una riga in più si aggiungerebbe per
    /// comodità.
    #[test]
    fn a_presence_row_carries_three_things_and_no_more() {
        let Some((_, struttura)) = UI.split_once("export struct TeamPresenceRow {") else {
            panic!("la riga della presenza deve esistere nell'interfaccia");
        };
        let Some((struttura, _)) = struttura.split_once('}') else {
            panic!("la riga della presenza deve finire");
        };
        let campi: Vec<&str> = struttura
            .lines()
            .map(str::trim)
            .filter(|riga| riga.ends_with(','))
            .collect();
        assert_eq!(
            campi,
            vec!["station: string,", "since: string,", "last-seen: string,"],
            "la presenza dice chi c'è, non che cosa fa"
        );
    }

    /// **La presenza non si conserva** (ADR-0096, decisione 1).
    ///
    /// Questa schermata la tiene in memoria e la riscrive a ogni lettura. Se
    /// qualcuno la scrivesse in una tabella, l'ufficio si troverebbe con un
    /// foglio presenze che nessuno ha deciso di tenere: la guardia legge il
    /// **modulo**, perché è qui che la scrittura si aggiungerebbe.
    #[test]
    fn presence_is_never_written_down() {
        const QUESTO_MODULO: &str = include_str!("team_live.rs");
        let Some((_, dopo)) = QUESTO_MODULO.split_once("fn refresh_presence(&self)") else {
            panic!("la lettura della presenza deve esistere");
        };
        // Il corpo finisce alla chiusura del metodo: legare la fine a un
        // commento che viene dopo lega la guardia a cio' che le sta accanto, e
        // la prima funzione aggiunta li' la farebbe guardare altro.
        let Some((corpo, _)) = dopo.split_once("\n    }\n") else {
            panic!("la lettura della presenza deve finire");
        };
        for vietato in ["insert_", "record_", "database", "Database", "audit"] {
            assert!(
                !corpo.contains(vietato),
                "la presenza non si scrive, e qui compare «{vietato}»"
            );
        }
    }

    /// **La schermata dell'Hub dice sempre che cosa la copia non salva.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// L'avvertenza non è un messaggio di esito: appare **prima** che qualcuno
    /// prema il pulsante, e resta anche dopo. Se finisse dentro l'esito — dove
    /// sembrerebbe più ordinata — la leggerebbe solo chi una copia l'ha già
    /// fatta, e la leggerebbe come una nota a margine di un successo.
    ///
    /// Chi la legge dopo un guasto la legge troppo tardi: è il giorno in cui
    /// l'ufficio scopre che la copia non rimette l'identità dell'Hub
    /// (TEAM-BACKUP-01, ADR-0101, decisione 3).
    #[test]
    fn the_hub_page_always_says_what_the_backup_leaves_out() {
        let pagina = crate::page_guard::corpo_della_pagina(
            u32::try_from(TEAM_LIVE_PAGE).unwrap_or_default(),
        );

        assert!(
            pagina.contains("root.team-live-backup()"),
            "nessun comando scrive la copia dell'ufficio: la capacità esisterebbe senza che \
             nessuno possa usarla"
        );
        for detto in [
            "Non contiene le chiavi dell'Hub",
            "rimette l'identità dell'Hub",
            "non ripristina da solo",
        ] {
            assert!(
                pagina.contains(detto),
                "la schermata non dice «{detto}»: un ufficio lo scoprirebbe il giorno del guasto"
            );
        }
    }

    /// **La schermata dell'Hub non promette un ripristino che non esiste.**
    ///
    /// Sovrascrivere l'archivio in uso con uno più vecchio cancellerebbe il
    /// lavoro in un secondo, e su un Hub il danno si moltiplica per quante
    /// persone stanno lavorando (ADR-0101, decisione 5).
    #[test]
    fn the_hub_page_offers_no_restore_button() {
        let pagina = crate::page_guard::corpo_della_pagina(
            u32::try_from(TEAM_LIVE_PAGE).unwrap_or_default(),
        );
        for proibito in ["Ripristina", "restore-hub", "team-live-restore"] {
            assert!(
                !pagina.contains(proibito),
                "la schermata dell'Hub offre «{proibito}»: il prodotto non ripristina, e un \
                 comando che sovrascrivesse l'archivio in uso cancellerebbe il lavoro di tutti"
            );
        }
    }

    /// La firma del collegamento all'Hub (dal 2026-10-04 restituisce anche se
    /// la postazione segue l'Hub, FR-003).
    const FIRMA_CONNECT: &str = "fn connect(&self";

    /// **Le persone dell'ufficio si creano dall'Hub, in modalità
    /// amministratore** (FINAL-REVIEW-01, FR-047). Senza questo percorso
    /// nessuna persona esisteva, e «Entra» non riusciva mai.
    #[test]
    fn office_people_are_created_on_the_hub_by_the_administrator() {
        for callback in [
            "callback team-live-person-create();",
            "callback team-live-person-toggle(string);",
            "callback team-live-person-reset(string);",
        ] {
            assert!(UI.contains(callback), "manca «{callback}»");
        }
        let collegamenti = corpo_di("pub fn wire(");
        for (gestore, chiamata) in [
            ("on_team_live_person_create", "service.create_person("),
            ("on_team_live_person_toggle", "service.toggle_person("),
            ("on_team_live_person_reset", "service.reset_person("),
        ] {
            assert!(
                collegamenti.contains(gestore) && collegamenti.contains(chiamata),
                "«{gestore}» deve chiamare «{chiamata}»"
            );
        }
        let controllo = corpo_di("fn chi_amministra(&self)");
        assert!(controllo.contains("in_modalita_amministratore()"));
        assert!(controllo.contains("self.fa_da_hub()"));
        for firma in [
            "fn create_person(&self",
            "fn toggle_person(&self",
            "fn reset_person(&self",
        ] {
            assert!(
                corpo_di(firma).contains("self.chi_amministra()"),
                "«{firma}» deve controllare chi amministra dove il comando gira"
            );
        }
        assert!(corpo_di("fn create_person(&self").contains(".create_on_the_hub("));
    }

    /// Il corpo di un metodo o di una funzione di questo modulo, fino alla
    /// sua chiusura.
    fn corpo_di(firma: &str) -> &'static str {
        const QUESTO_MODULO: &str = include_str!("team_live.rs");
        // Una funzione libera finisce a colonna zero, un metodo a quattro.
        let chiusura = if firma.starts_with("pub fn") {
            "\n}\n"
        } else {
            "\n    }\n"
        };
        let Some((_, dopo)) = QUESTO_MODULO.split_once(firma) else {
            panic!("«{firma}» deve esistere in questo modulo");
        };
        let Some((corpo, _)) = dopo.split_once(chiusura) else {
            panic!("«{firma}» deve finire");
        };
        assert!(corpo.len() > 40, "«{firma}»: la guardia non ha letto nulla");
        corpo
    }

    /// **D-19: l'arruolamento si raggiunge dalla schermata** (ADR-0132).
    ///
    /// Fino al 2026-10-02 il servizio esisteva e lo chiamavano solo le prove.
    /// La guardia legge la pagina e i collegamenti: un pulsante che non chiama
    /// niente, o una chiamata che nessun pulsante fa, la fanno diventare rossa.
    #[test]
    fn enrollment_is_reachable_from_the_shared_live_page() {
        let pagina = crate::page_guard::corpo_della_pagina(
            u32::try_from(TEAM_LIVE_PAGE).unwrap_or_default(),
        );
        for atteso in [
            "Emetti codice di arruolamento",
            "root.team-live-issue-code()",
            "Togli il foglietto dallo schermo",
            "Collega questa postazione a un Hub",
            "Collega a questo Hub",
            "root.team-live-connect(",
        ] {
            assert!(
                pagina.contains(atteso),
                "la pagina Live condiviso non contiene «{atteso}»: l'arruolamento non si \
                 raggiunge (D-19)"
            );
        }

        let collegamenti = corpo_di("pub fn wire(");
        for (callback, metodo) in [
            ("on_team_live_issue_code", "service.issue_sheet()"),
            ("on_team_live_hide_sheet", "service.hide_sheet()"),
            ("on_team_live_connect", "service.connect("),
        ] {
            let Some((_, dopo)) = collegamenti.split_once(callback) else {
                panic!("«{callback}» non è collegata: il pulsante non farebbe niente");
            };
            let blocco = dopo.split("window.on_").next().unwrap_or_default();
            assert!(
                blocco.contains(metodo),
                "«{callback}» non chiama «{metodo}»"
            );
        }
        assert!(
            corpo_di("fn issue_sheet(&self)").contains(".issue_enrollment_sheet("),
            "il comando dell'Hub non chiama il servizio che emette il codice"
        );
        assert!(
            corpo_di(FIRMA_CONNECT).contains(".enroll("),
            "il comando della postazione non chiama il servizio che arruola"
        );
    }

    /// **Solo l'amministratore emette un codice e collega una postazione**, e
    /// il controllo sta **nel codice che esegue**, non solo nel pulsante
    /// nascosto (ADR-0132, decisione 5).
    #[test]
    fn enrollment_commands_check_the_administrator_mode_where_they_run() {
        for firma in ["fn issue_sheet(&self)", FIRMA_CONNECT] {
            let corpo = corpo_di(firma);
            let Some(controllo) = corpo.find("in_modalita_amministratore()") else {
                panic!("«{firma}» non controlla la modalità amministratore");
            };
            let Some(servizio) = corpo
                .find(".issue_enrollment_sheet(")
                .or_else(|| corpo.find(".enroll("))
            else {
                panic!("«{firma}» non chiama alcun servizio");
            };
            assert!(
                controllo < servizio,
                "«{firma}» chiama il servizio prima di controllare la modalità"
            );
        }
        let pagina = crate::page_guard::corpo_della_pagina(
            u32::try_from(TEAM_LIVE_PAGE).unwrap_or_default(),
        );
        assert!(pagina.contains("root.team-live-can-issue && root.administrator-mode"));
        assert!(pagina.contains("if root.administrator-mode: Rectangle"));
    }

    /// **Il foglietto non si copia da nessuna parte** (ADR-0132, decisione 5):
    /// non negli appunti di Windows, non nel registro, non nell'audit. E il
    /// codice digitato non resta nel campo.
    #[test]
    fn the_enrollment_sheet_is_never_copied_or_logged() {
        const QUESTO_MODULO: &str = include_str!("team_live.rs");
        let produzione = QUESTO_MODULO
            .split_once("#[cfg(test)]")
            .map_or(QUESTO_MODULO, |(prima, _)| prima);
        for vietato in ["clipboard", "Clipboard", "arboard"] {
            assert!(
                !produzione.contains(vietato),
                "il modulo nomina «{vietato}»: il foglietto finirebbe negli appunti"
            );
        }
        let emissione = corpo_di("fn issue_sheet(&self)");
        for vietato in ["tracing::", "audit", "record_"] {
            assert!(
                !emissione.contains(vietato),
                "l'emissione del foglietto nomina «{vietato}»: il codice finirebbe in un registro"
            );
        }
        let collegamenti = corpo_di("pub fn wire(");
        let Some((_, dopo)) = collegamenti.split_once("on_team_live_connect") else {
            panic!("il collegamento deve esistere");
        };
        assert!(
            dopo.contains("set_team_live_typed_code(SharedString::new())"),
            "il codice digitato resterebbe nel campo dopo il tentativo"
        );
    }

    #[test]
    fn every_event_kind_has_a_label_for_the_operator() {
        for kind in lisi_core::model::hub_event::HubEventKind::ALL {
            let etichetta = etichetta_del_tipo(kind);
            assert!(
                !etichetta.is_empty(),
                "il tipo {kind:?} non ha un'etichetta leggibile"
            );
        }
    }
}

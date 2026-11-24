//! Collegamento fra la schermata **Revisione condivisa** e l'Hub
//! (TEAM-REVIEW-01, ADR-0094).
//!
//! # Che cosa mostra, e in quale ordine
//!
//! L'**elenco** di ciò che l'Hub ha segnalato: identificativo, fonte, livello,
//! istante, stato e versione. Nessun testo. Il contenuto si apre **uno per
//! volta**, e aprirlo è un atto che l'Hub registra (ADR-0094, decisione 1).
//!
//! # Il contenuto non si conserva
//!
//! Ciò che si è aperto vive in memoria per la durata della schermata: non c'è
//! alcuna tabella dei contenuti sulla postazione, e chiudendo il programma non
//! resta nulla. Una copia locale sarebbe l'archivio dell'Hub costruito un pezzo
//! alla volta.
//!
//! # Una sessione per gesto
//!
//! Ogni azione — l'elenco, l'apertura, la decisione — apre una sessione, fa il
//! suo scambio e la chiude. Costa un handshake in più e **non lascia una
//! connessione aperta** su una schermata che qualcuno può dimenticare aperta:
//! finché non esiste un ciclo di sottofondo deciso, è la scelta prudente.
//!
//! # L'identificativo del comando è deterministico
//!
//! `rev-<contenuto>-<versione>-<stato>`: la **stessa** decisione ripetuta ha lo
//! stesso identificativo, e l'Hub risponde «ripetuta» invece di eseguirla due
//! volte (ADR-0089). Una decisione **diversa** ha un identificativo diverso, e
//! l'Hub la valuta.

use std::cell::RefCell;
use std::rc::Rc;

use crate::accesso::SharedAccesso;
use lisi_core::ContentId;
use lisi_core::NoteId;
use lisi_core::model::explanation::{Explained, ExplanationOutcome};
use lisi_core::model::hub_notes::SharedNote;
use lisi_core::model::hub_person::{Passphrase, PersonId};
use lisi_core::model::hub_review::{ReviewContent, ReviewQueueCursor};
use lisi_core::model::reference::{ArchiveRef, ArchiveRefKind};
use lisi_core::model::remote_command::RemoteAction;
use lisi_core::model::review::ReviewState;
use lisi_core::text::Note;
use lisi_services::Database;
use lisi_services::device_identity::DeviceIdentityService;
use lisi_services::hub_catchup::HubCatchUpService;
use lisi_services::hub_client::{
    HubClientService, HubConnectionStore, HubReviewSession, KnownPerson, ReviewSessionOutcome,
    SharedSession, SharedWorkQueue,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, ReviewQueueRow, SharedNoteRow, TeamPersonRow};

/// Quante righe della coda si mostrano.
///
/// È il tetto della fotografia che l'Hub compone (ADR-0095, decisione 4):
/// chi arriva in fondo a cento righe ha deciso qualcosa, e la coda si è
/// accorciata.
const RIGHE_A_SCHERMO: usize = 100;

/// Quanti monitoraggi dell'ufficio si offrono ai comandi a distanza.
const MONITORAGGI_COMANDABILI: usize = 10;

/// Indice della pagina Revisione condivisa nell'interfaccia.
///
/// Usato solo dalla prova che lo lega al file `.slint`.
#[cfg(test)]
const TEAM_REVIEW_PAGE: i32 = 28;

/// Una riga da mostrare, comunque l'elenco sia arrivato.
///
/// La coda dell'ufficio la compone l'Hub (TEAM-WQ-01, ADR-0095) e porta il
/// **perché sta qui**; quando l'Hub non offre quella capacità resta l'elenco di
/// ciò che è stato segnalato, in ordine di identificativo, e il «perché» non
/// c'è — non si inventa.
#[derive(Debug, Clone)]
struct RigaDaRivedere {
    content_id: ContentId,
    source: String,
    level: u8,
    raised_at: lisi_core::Timestamp,
    state: Option<ReviewState>,
    why: String,
    assigned_to: Option<PersonId>,
}

/// Lo stato della schermata.
pub struct TeamReview {
    client: HubClientService,
    /// La coda letta dall'Hub, per l'ultima volta che si è chiesta.
    queue: RefCell<Vec<RigaDaRivedere>>,
    /// Che cosa dice la coda nel suo insieme.
    summary: RefCell<String>,
    /// Il contenuto aperto, **in memoria e basta**.
    opened: RefCell<Option<ReviewContent>>,
    /// L'esito dell'ultima azione, per l'operatore.
    message: RefCell<String>,
    /// L'accesso di chi è entrato, **condiviso con le altre schermate**.
    ///
    /// L'accesso vale per la connessione (ADR-0097, decisione 6): tenerla
    /// aperta è il modo in cui dura, e chiuderla è il modo in cui si esce.
    /// Una sola, perché una sola persona per volta siede alla postazione.
    accesso: SharedAccesso,
    /// I colleghi, quando chi è dentro li ha chiesti.
    people: RefCell<Vec<KnownPerson>>,
    /// Che cosa l'ufficio ha scritto sul contenuto aperto.
    notes: RefCell<Vec<SharedNote>>,
    /// Perché le note non ci sono, quando non ci sono.
    notes_message: RefCell<String>,
    /// I monitoraggi dell'ufficio, per i comandi a distanza (HUB-REMOTE-01).
    monitoraggi: RefCell<Vec<SharedSession>>,
    /// L'archivio della postazione, dove chi comanda scrive il comando dato
    /// (ADR-0200, decisione 6).
    registro: Database,
}

/// Lo stato condiviso fra i gestori dei comandi.
pub type SharedTeamReview = Rc<TeamReview>;

/// Costruisce la schermata, se l'archivio e le configurazioni sono apribili.
#[must_use]
pub fn create_service(
    client_database: Option<Database>,
    audit_database: Option<Database>,
    accesso: &SharedAccesso,
) -> Option<SharedTeamReview> {
    let identita = DeviceIdentityService::default_location().ok()?;
    let configurazione = HubConnectionStore::default_location().ok()?;
    let client = HubClientService::new(
        HubCatchUpService::new(client_database?),
        identita,
        configurazione,
    )
    .with_default_office_networks()
    .with_screen_limits();

    Some(Rc::new(TeamReview {
        client,
        queue: RefCell::new(Vec::new()),
        summary: RefCell::new(String::new()),
        opened: RefCell::new(None),
        message: RefCell::new(String::new()),
        accesso: Rc::clone(accesso),
        people: RefCell::new(Vec::new()),
        notes: RefCell::new(Vec::new()),
        notes_message: RefCell::new(String::new()),
        monitoraggi: RefCell::new(Vec::new()),
        registro: audit_database?,
    }))
}

impl TeamReview {
    /// Apre una sessione, o restituisce la frase che dice perché no.
    fn sessione(&self) -> Result<HubReviewSession, String> {
        match self.client.open_review_session(crate::account::now()) {
            Ok(ReviewSessionOutcome::Ready(sessione)) => Ok(*sessione),
            Ok(altro) => Err(altro
                .refusal_message()
                .unwrap_or_else(|| String::from("Il collegamento all'Hub non si è aperto."))),
            Err(errore) => Err(errore.operator_message()),
        }
    }

    /// Fa una cosa sull'Hub, dentro la sessione giusta.
    ///
    /// Se una persona è entrata, si usa **la sua** sessione: il suo accesso
    /// vive lì, e una sessione nuova sarebbe una sessione in cui non è
    /// entrato nessuno. Altrimenti se ne apre una breve e la si chiude.
    fn con_sessione<T>(
        &self,
        azione: impl FnOnce(&mut HubReviewSession) -> T,
    ) -> Result<T, String> {
        // Se c'e' un accesso aperto, l'atto passa di li': la sessione non si
        // presta, e per questo l'azione ci entra una volta sola.
        if self.accesso.c_e_qualcuno() {
            let Some(esito) = self.accesso.con_sessione(azione) else {
                return Err(String::from("L'accesso si è chiuso: entrare di nuovo."));
            };
            return Ok(esito);
        }
        let mut breve = self.sessione()?;
        let esito = azione(&mut breve);
        breve.close();
        Ok(esito)
    }

    /// Fa entrare una persona, e **tiene aperta** la sua sessione.
    fn sign_in(&self, identificativo: &str, frase: &str) -> String {
        let (Ok(chi), Ok(frase)) = (PersonId::parse(identificativo), Passphrase::try_new(frase))
        else {
            // Non si dice quale dei due era malformato: il rifiuto di un
            // accesso non distingue (ADR-0097, decisione 5).
            return String::from(
                "Identificativo o frase non riconosciuti. La frase ha almeno dodici caratteri.",
            );
        };

        self.accesso.esci();
        self.people.borrow_mut().clear();
        let mut sessione = match self.sessione() {
            Ok(sessione) => sessione,
            Err(frase) => return frase,
        };
        match sessione.sign_in(&chi, &frase) {
            Ok(Some(risposta)) if risposta.entered => {
                *self.people.borrow_mut() = sessione.people().ok().flatten().unwrap_or_default();
                self.accesso.entra(chi, sessione);
                let _ = self.reload();
                risposta.detail
            }
            Ok(Some(risposta)) => {
                sessione.close();
                risposta.detail
            }
            Ok(None) => {
                sessione.close();
                String::from(
                    "Questo Hub non conosce le persone dell'ufficio: non c'è dove entrare.",
                )
            }
            Err(errore) => {
                sessione.close();
                errore.operator_message()
            }
        }
    }

    /// Fa uscire chi è entrato.
    fn sign_out(&self) -> String {
        if !self.accesso.c_e_qualcuno() {
            return String::from("Non è entrato nessuno.");
        }
        self.accesso.esci();
        self.people.borrow_mut().clear();
        let _ = self.reload();
        String::from("Uscita eseguita: sulla postazione non resta nulla dell'accesso.")
    }

    /// Scrive a chi è un contenuto, o lo rimette a nessuno.
    fn assegna(&self, content_id: i64, a_chi: Option<PersonId>) -> String {
        if content_id <= 0 {
            return String::from("Nessun elemento selezionato.");
        }
        if !self.accesso.c_e_qualcuno() {
            return String::from(
                "Per assegnare il lavoro occorre prima entrare come persona su questo Hub.",
            );
        }
        let contenuto = ContentId::new(content_id);
        let versione = self
            .queue
            .borrow()
            .iter()
            .find(|riga| riga.content_id == contenuto)
            .map_or(0, |_| 0);
        let identificativo = identificativo_dell_assegnazione(contenuto, versione, a_chi.as_ref());

        let esito = self.con_sessione(|sessione| {
            sessione.assign(&identificativo, contenuto, versione, a_chi.as_ref())
        });
        match esito {
            Ok(Ok(Some(risposta))) => {
                let _ = self.reload();
                risposta.detail
            }
            Ok(Ok(None)) => String::from(
                "Questo Hub non sa assegnare il lavoro: l'elenco resta, ma senza a chi.",
            ),
            Ok(Err(errore)) => errore.operator_message(),
            Err(frase) => frase,
        }
    }

    /// Rilegge le note dell'ufficio sul contenuto aperto.
    ///
    /// Comprende **anche quelle ritirate**: chi le aveva lette deve poter
    /// capire che cosa è successo a ciò che aveva letto (ADR-0099,
    /// decisione 2).
    fn reload_notes(&self) {
        let Some(contenuto) = self
            .opened
            .borrow()
            .as_ref()
            .map(|aperto| aperto.content_id)
        else {
            self.notes.borrow_mut().clear();
            self.notes_message.borrow_mut().clear();
            return;
        };
        let Ok(dove) = ArchiveRef::to(ArchiveRefKind::Content, contenuto.get()) else {
            return;
        };

        let esito = self.con_sessione(|sessione| sessione.shared_notes(dove, RIGHE_A_SCHERMO));
        match esito {
            Ok(Ok(Some(note))) => {
                let quante = note.len();
                *self.notes.borrow_mut() = note;
                *self.notes_message.borrow_mut() = if quante == 0 {
                    String::from("Nessuno ha ancora annotato questo contenuto.")
                } else {
                    String::new()
                };
            }
            Ok(Ok(None)) => {
                self.notes.borrow_mut().clear();
                *self.notes_message.borrow_mut() = String::from(
                    "Questo Hub non tiene il blocco condiviso: le note restano su ciascuna \
                     postazione.",
                );
            }
            Ok(Err(errore)) => {
                self.notes.borrow_mut().clear();
                *self.notes_message.borrow_mut() = errore.operator_message();
            }
            Err(frase) => {
                self.notes.borrow_mut().clear();
                *self.notes_message.borrow_mut() = frase;
            }
        }
    }

    /// Annota il contenuto aperto.
    fn write_note(&self, testo: &str) -> String {
        let Some(contenuto) = self
            .opened
            .borrow()
            .as_ref()
            .map(|aperto| aperto.content_id)
        else {
            return String::from("Aprire prima un contenuto: si annota ciò che si è letto.");
        };
        if !self.accesso.c_e_qualcuno() {
            return String::from(
                "Per scrivere una nota dell'ufficio occorre prima entrare come persona.",
            );
        }
        let (Ok(dove), Ok(parole)) = (
            ArchiveRef::to(ArchiveRefKind::Content, contenuto.get()),
            Note::try_new(testo.trim()),
        ) else {
            return String::from("Una nota senza parole non è una nota.");
        };

        let esito = self.con_sessione(|sessione| sessione.write_shared_note(dove, &parole));
        let frase = match esito {
            Ok(Ok(Some(risposta))) => risposta.detail,
            Ok(Ok(None)) => String::from("Questo Hub non tiene il blocco condiviso."),
            Ok(Err(errore)) => errore.operator_message(),
            Err(frase) => frase,
        };
        self.reload_notes();
        frase
    }

    /// Ritira una nota. **Non la cancella.**
    fn withdraw_note(&self, note_id: i64) -> String {
        if note_id <= 0 {
            return String::from("Nessuna nota selezionata.");
        }
        let esito =
            self.con_sessione(|sessione| sessione.withdraw_shared_note(NoteId::new(note_id)));
        let frase = match esito {
            Ok(Ok(Some(risposta))) => risposta.detail,
            Ok(Ok(None)) => String::from("Questo Hub non tiene il blocco condiviso."),
            Ok(Err(errore)) => errore.operator_message(),
            Err(frase) => frase,
        };
        self.reload_notes();
        frase
    }

    /// Rilegge la coda da rivedere.
    ///
    /// **Prima si chiede la coda dell'ufficio**, che l'Hub compone nell'ordine
    /// deciso e con il «perché sta qui» (ADR-0095). Se questo Hub non offre
    /// quella capacità, resta l'elenco di ciò che è stato segnalato, in ordine
    /// di identificativo — e la schermata **lo dice**, invece di far credere
    /// che l'ordine sia quello dell'ufficio.
    fn reload(&self) -> String {
        let mut sessione = match self.sessione() {
            Ok(sessione) => sessione,
            Err(frase) => return frase,
        };
        let coda = sessione.work_queue(RIGHE_A_SCHERMO);
        let esito = match coda {
            Ok(Some(condivisa)) => {
                let righe: Vec<RigaDaRivedere> = condivisa
                    .items
                    .iter()
                    .map(|riga| RigaDaRivedere {
                        content_id: riga.content_id,
                        source: riga.source_name.clone(),
                        level: riga.level,
                        raised_at: riga.raised_at,
                        state: riga.state,
                        why: riga.why_here.clone(),
                        assigned_to: riga.assigned_to.clone(),
                    })
                    .collect();
                let quante = righe.len();
                *self.queue.borrow_mut() = righe;
                *self.summary.borrow_mut() = sommario(&condivisa);
                if quante == 0 {
                    String::from("La coda dell'ufficio è vuota: non resta nulla da rivedere.")
                } else {
                    format!("Coda dell'ufficio: {quante} righe mostrate.")
                }
            }
            Ok(None) => match sessione.queue(ReviewQueueCursor::start()) {
                Ok(elementi) => {
                    let righe: Vec<RigaDaRivedere> = elementi
                        .iter()
                        .map(|elemento| RigaDaRivedere {
                            content_id: elemento.content_id,
                            source: String::from(elemento.source.as_str()),
                            level: elemento.level,
                            raised_at: elemento.raised_at,
                            state: elemento.state,
                            why: String::new(),
                            assigned_to: None,
                        })
                        .collect();
                    let quante = righe.len();
                    *self.queue.borrow_mut() = righe;
                    *self.summary.borrow_mut() = String::from(
                        "Questo Hub non compone la coda dell'ufficio: l'elenco è in ordine di \
                         identificativo, non nell'ordine in cui il lavoro andrebbe guardato.",
                    );
                    format!("{quante} elementi segnalati.")
                }
                Err(errore) => errore.operator_message(),
            },
            Err(errore) => errore.operator_message(),
        };
        // I MONITORAGGI DELL'UFFICIO, per i comandi a distanza: un Hub che non
        // li elenca lascia l'elenco vuoto, e il comando non parte.
        *self.monitoraggi.borrow_mut() = sessione
            .shared_sessions(MONITORAGGI_COMANDABILI)
            .ok()
            .flatten()
            .unwrap_or_default();
        sessione.close();
        esito
    }

    /// Manda un comando a distanza su un monitoraggio dell'Hub (HUB-REMOTE-01,
    /// ADR-0200): una persona entrata, un monitoraggio, un atto, un motivo.
    /// Il comando e la risposta dell'Hub restano nell'audit di questa
    /// postazione.
    fn comanda(&self, indice: i32, atto: &str, motivo: &str) -> String {
        if !self.accesso.c_e_qualcuno() {
            return String::from(
                "Per comandare a distanza occorre prima entrare come persona su questo Hub.",
            );
        }
        let Some(monitoraggio) = usize::try_from(indice)
            .ok()
            .and_then(|indice| self.monitoraggi.borrow().get(indice).cloned())
        else {
            return String::from("Scegliere prima il monitoraggio dell'ufficio.");
        };
        let Ok(atto) = RemoteAction::parse(atto) else {
            return String::from("Questo comando non è fra quelli previsti.");
        };
        let Ok(chi) = crate::operator::audit_actor() else {
            return String::from("Identità dell'operatore non utilizzabile: segnalarlo.");
        };
        let adesso = crate::account::now();
        let identificativo = format!(
            "cmd-{}-{}-{}",
            monitoraggio.id.get(),
            atto.as_str(),
            adesso.as_millis()
        );
        let esito = self.con_sessione(|sessione| {
            sessione.remote_command(&identificativo, monitoraggio.id, atto, motivo)
        });
        let (frase, risposta) = match esito {
            Ok(Ok(Some(risposta))) => {
                let frase = match risposta.verdict.as_str() {
                    "applicata" => format!("L'Hub ha eseguito il comando: {}.", risposta.detail),
                    "ripetuta" => format!(
                        "L'Hub aveva già ricevuto questo comando: {}.",
                        risposta.detail
                    ),
                    _ => format!("L'Hub ha rifiutato il comando: {}.", risposta.detail),
                };
                (frase, format!("{}: {}", risposta.verdict, risposta.detail))
            }
            Ok(Ok(None)) => (
                String::from("Questo Hub non riceve comandi a distanza."),
                String::from("nessuna: l'Hub non riceve comandi a distanza"),
            ),
            Ok(Err(errore)) => (
                errore.operator_message(),
                String::from("nessuna: il collegamento non è riuscito"),
            ),
            Err(frase) => (frase, String::from("nessuna: l'accesso si è chiuso")),
        };
        // CHI COMANDA LO SCRIVE (ADR-0200, decisione 6), anche quando l'Hub
        // non ha risposto.
        if lisi_services::remote_commands::record_sent(
            &self.registro,
            &chi,
            monitoraggio.id,
            atto,
            motivo,
            &risposta,
            adesso,
        )
        .is_err()
        {
            return format!(
                "{frase} Il comando non si è potuto scrivere nel registro di questa postazione."
            );
        }
        frase
    }

    /// Apre **un** contenuto.
    fn open(&self, content_id: i64) -> String {
        if content_id <= 0 {
            return String::from("Nessun elemento selezionato.");
        }
        let esito = match self.con_sessione(|sessione| sessione.content(ContentId::new(content_id)))
        {
            Ok(esito) => esito,
            Err(frase) => return frase,
        };

        match esito {
            Ok(Some(contenuto)) => {
                let fonte = String::from(contenuto.source.as_str());
                *self.opened.borrow_mut() = Some(contenuto);
                self.reload_notes();
                format!("Contenuto aperto: {fonte}. La lettura è stata registrata sull'Hub.")
            }
            Ok(None) => {
                *self.opened.borrow_mut() = None;
                String::from(
                    "L'Hub non ha questo contenuto fra quelli segnalati: forse è stato \
                     ripulito, o l'elenco è vecchio. Aggiornare l'elenco.",
                )
            }
            Err(errore) => {
                *self.opened.borrow_mut() = None;
                errore.operator_message()
            }
        }
    }

    /// Manda una decisione sull'elemento aperto.
    fn decide(&self, stato: &str, nota: &str) -> String {
        let Some(contenuto) = self.opened.borrow().clone() else {
            return String::from("Aprire prima un contenuto: si decide su ciò che si è letto.");
        };
        let Ok(stato) = <ReviewState as core::str::FromStr>::from_str(stato) else {
            return String::from("Questa decisione non è fra quelle previste.");
        };

        let nota = nota.trim();
        let nota = if nota.is_empty() { None } else { Some(nota) };
        let identificativo =
            identificativo_del_comando(contenuto.content_id, contenuto.version, stato);

        let mut sessione = match self.sessione() {
            Ok(sessione) => sessione,
            Err(frase) => return frase,
        };
        let esito = sessione.submit(
            &identificativo,
            contenuto.content_id,
            contenuto.version,
            stato,
            nota,
        );
        sessione.close();

        match esito {
            Ok(risposta) => {
                // Dopo una decisione l'elenco è vecchio: si rilegge, così che
                // chi guarda veda subito lo stato nuovo invece di doverlo
                // chiedere.
                let _ = self.reload();
                *self.opened.borrow_mut() = None;
                risposta.detail
            }
            Err(errore) => errore.operator_message(),
        }
    }
}

/// L'identificativo deterministico di un cambio di assegnazione.
///
/// Lo stesso cambio ripetuto ha lo stesso identificativo: l'Hub risponde
/// «ripetuta» invece di registrarlo due volte (ADR-0089).
fn identificativo_dell_assegnazione(
    content_id: ContentId,
    version: u64,
    to: Option<&PersonId>,
) -> String {
    format!(
        "asg-{}-{version}-{}",
        content_id.get(),
        to.map_or("nessuno", PersonId::as_str)
    )
}

/// L'identificativo deterministico di una decisione.
///
/// La stessa decisione ripetuta ha lo stesso identificativo: l'Hub risponde
/// «ripetuta» invece di registrarla due volte (ADR-0089).
fn identificativo_del_comando(content_id: ContentId, version: u64, state: ReviewState) -> String {
    format!(
        "rev-{}-{}-{}",
        content_id.get(),
        version,
        state.as_str().replace('_', "-")
    )
}

/// «Perché vedo questo?» su una voce della coda dell'ufficio (PR-02).
///
/// # Si spiega soltanto ciò che l'Hub ha mostrato
///
/// La risposta si compone **dalla riga che l'Hub ha consegnato** in
/// quest'ultima lettura, e da nient'altro: né dall'archivio locale, che ha
/// identificativi che non sono quelli dell'Hub, né da una nuova domanda
/// all'Hub. Un identificativo che non è fra quelle righe non si spiega, e la
/// risposta dice soltanto che non è disponibile. Un canale di spiegazione che
/// aggira l'autorizzazione sarebbe un canale di esfiltrazione (ADR-0119,
/// decisione 5).
fn spiegazione_della_riga(coda: &[RigaDaRivedere], content_id: i32) -> ExplanationOutcome {
    let Some(riga) = coda
        .iter()
        .find(|riga| riga.content_id.get() == i64::from(content_id))
    else {
        return ExplanationOutcome::NotAvailable;
    };

    let perche = if riga.why.trim().is_empty() {
        "Questo Hub non compone la coda dell'ufficio: l'elenco è in ordine di identificativo."
    } else {
        riga.why.trim()
    };
    let fatti = format!(
        "Livello {}, {}, segnalato il {}. {perche}",
        riga.level,
        etichetta_dello_stato(riga.state),
        riga.raised_at.to_readable_local()
    );

    lisi_services::why::explain_from_hub(Explained::WorkQueueItem, &fatti).map_or(
        ExplanationOutcome::NotAvailable,
        ExplanationOutcome::Composed,
    )
}

/// Mostra la risposta su una voce della coda, oppure che non è disponibile.
fn spiega(window: &AppWindow, service: &SharedTeamReview, content_id: i32) {
    match spiegazione_della_riga(&service.queue.borrow(), content_id) {
        ExplanationOutcome::Composed(risposta) => {
            crate::explain::show(window, &risposta, &crate::explain::Door::Nowhere);
        }
        ExplanationOutcome::NotAvailable => crate::explain::show_unavailable(
            window,
            Explained::WorkQueueItem,
            ExplanationOutcome::NOT_AVAILABLE,
        ),
    }
}

/// Che cosa dice la coda nel suo insieme.
///
/// I conteggi sono di **tutta** la coda, non delle righe mostrate: servono a
/// sapere quanto lavoro resta senza doverlo scorrere.
fn sommario(coda: &SharedWorkQueue) -> String {
    let oltre = coda.beyond();
    let resto = if oltre == 0 {
        String::new()
    } else {
        format!(" Altre {oltre} righe non sono mostrate.")
    };
    format!(
        "{} in attesa, {} in esame, {} in tutto. Fotografia dell'Hub delle {}.{resto}",
        coda.untouched,
        coda.in_review,
        coda.total,
        coda.composed_at.to_readable_local()
    )
}

/// L'etichetta con cui uno stato compare nell'elenco.
fn etichetta_dello_stato(state: Option<ReviewState>) -> &'static str {
    match state {
        None => "da rivedere",
        Some(ReviewState::New) => "nuovo",
        Some(ReviewState::InReview) => "in esame",
        Some(ReviewState::Relevant) => "rilevante",
        Some(ReviewState::NotRelevant) => "non rilevante",
        Some(ReviewState::Duplicate) => "duplicato",
        Some(ReviewState::Archived) => "archiviato",
        Some(ReviewState::Reported) => "trasmesso",
    }
}

/// Riporta nell'interfaccia la coda e il contenuto aperto.
pub fn refresh(window: &AppWindow, service: &SharedTeamReview) {
    let righe: Vec<ReviewQueueRow> = service
        .queue
        .borrow()
        .iter()
        .map(|elemento| ReviewQueueRow {
            content_id: i32::try_from(elemento.content_id.get()).unwrap_or(i32::MAX),
            source: SharedString::from(elemento.source.as_str()),
            level: crate::lingua::schermo(format!("Livello {}", elemento.level)),
            raised: SharedString::from(elemento.raised_at.to_readable_local()),
            state: SharedString::from(etichetta_dello_stato(elemento.state)),
            // La versione la porta il contenuto quando si apre: nell'elenco non
            // serve, e una copia vecchia si leggerebbe come attuale.
            version: 0,
            why: SharedString::from(elemento.why.as_str()),
            assigned: SharedString::from(
                elemento
                    .assigned_to
                    .as_ref()
                    .map_or_else(String::new, |persona| String::from(persona.as_str())),
            ),
        })
        .collect();
    window.set_review_queue_rows(ModelRc::from(Rc::new(VecModel::from(righe))));

    let aperto = service.opened.borrow();
    match aperto.as_ref() {
        Some(contenuto) => {
            window.set_review_open_source(crate::lingua::schermo(format!(
                "{} — {}",
                contenuto.source.as_str(),
                contenuto.source_name.as_str()
            )));
            window.set_review_open_published(SharedString::from(
                contenuto.published_at.to_readable_local(),
            ));
            window.set_review_open_body(SharedString::from(contenuto.body.as_str()));
            window.set_review_open_level(crate::lingua::schermo(format!(
                "Livello {} · versione {}",
                contenuto.level, contenuto.version
            )));
            window
                .set_review_open_id(i32::try_from(contenuto.content_id.get()).unwrap_or(i32::MAX));
            window.set_review_has_open(true);
        }
        None => {
            window.set_review_open_source(SharedString::new());
            window.set_review_open_published(SharedString::new());
            window.set_review_open_body(SharedString::new());
            window.set_review_open_level(SharedString::new());
            window.set_review_open_id(0);
            window.set_review_has_open(false);
        }
    }
    window.set_review_message(SharedString::from(service.message.borrow().clone()));
    // I COMANDI A DISTANZA (HUB-REMOTE-01): i monitoraggi dell'ufficio, per nome.
    let monitoraggi: Vec<SharedString> = service
        .monitoraggi
        .borrow()
        .iter()
        .map(|monitoraggio| SharedString::from(monitoraggio.label.as_str()))
        .collect();
    window.set_review_monitorings(ModelRc::from(Rc::new(VecModel::from(monitoraggi))));
    window.set_review_queue_summary(SharedString::from(service.summary.borrow().clone()));
    window.set_review_person(SharedString::from(
        service
            .accesso
            .person()
            .map_or_else(String::new, |persona| String::from(persona.as_str())),
    ));
    let colleghi: Vec<TeamPersonRow> = service
        .people
        .borrow()
        .iter()
        .map(|collega| TeamPersonRow {
            person: SharedString::from(collega.id.as_str()),
            label: SharedString::from(collega.label.as_str()),
            role: crate::lingua::schermo(collega.role.label()),
            active: collega.active,
        })
        .collect();
    window.set_review_people(ModelRc::from(Rc::new(VecModel::from(colleghi))));

    let chi_sono = service.accesso.person();
    let note: Vec<SharedNoteRow> = service
        .notes
        .borrow()
        .iter()
        .map(|nota| SharedNoteRow {
            id: i32::try_from(nota.id.get()).unwrap_or(i32::MAX),
            body: SharedString::from(nota.body.as_str()),
            author: crate::lingua::schermo(format!("persona.{}", nota.author)),
            written: SharedString::from(nota.written_at.to_readable_local()),
            withdrawn: SharedString::from(
                nota.withdrawn
                    .as_ref()
                    .map_or_else(String::new, |(chi, quando)| {
                        format!(" · ritirata da {chi} il {}", quando.to_readable_local())
                    }),
            ),
            mine: chi_sono.as_ref() == Some(&nota.author),
        })
        .collect();
    window.set_review_notes(ModelRc::from(Rc::new(VecModel::from(note))));
    window.set_review_notes_message(SharedString::from(service.notes_message.borrow().clone()));
}

/// Collega i comandi della schermata al servizio.
pub fn wire(window: &AppWindow, service: &SharedTeamReview) {
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_remote_command(move |indice, atto, motivo| {
            if crate::lock::refuse_while_locked("review_remote_command") {
                return;
            }
            let esito = service.comanda(indice, atto.as_str(), motivo.as_str());
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_team_explain(move |content_id| {
            if crate::lock::refuse_while_locked("team_explain") {
                return;
            }
            if let Some(window) = handle.upgrade() {
                spiega(&window, &service, content_id);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_sign_in(move |chi, frase| {
            if crate::lock::refuse_while_locked("review_sign_in") {
                return;
            }
            let esito = service.sign_in(chi.as_str(), frase.as_str());
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_write_note(move |testo| {
            if crate::lock::refuse_while_locked("review_write_note") {
                return;
            }
            let esito = service.write_note(testo.as_str());
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_withdraw_note(move |note_id| {
            if crate::lock::refuse_while_locked("review_withdraw_note") {
                return;
            }
            let esito = service.withdraw_note(i64::from(note_id));
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_sign_out(move || {
            if crate::lock::refuse_while_locked("review_sign_out") {
                return;
            }
            let esito = service.sign_out();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_take(move |content_id| {
            if crate::lock::refuse_while_locked("review_take") {
                return;
            }
            let chi = service.accesso.person();
            let esito = service.assegna(i64::from(content_id), chi);
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_release(move |content_id| {
            if crate::lock::refuse_while_locked("review_release") {
                return;
            }
            let esito = service.assegna(i64::from(content_id), None);
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_assign(move |content_id, persona| {
            if crate::lock::refuse_while_locked("review_assign") {
                return;
            }
            let esito = match PersonId::parse(persona.as_str()) {
                Ok(persona) => service.assegna(i64::from(content_id), Some(persona)),
                Err(_) => String::from("L'identificativo della persona non è utilizzabile."),
            };
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_shown(move || {
            let esito = service.reload();
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_open(move |content_id| {
            if crate::lock::refuse_while_locked("review_open") {
                return;
            }
            let esito = service.open(i64::from(content_id));
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
    {
        let handle = window.as_weak();
        let service = Rc::clone(service);
        window.on_review_decide(move |stato, nota| {
            if crate::lock::refuse_while_locked("review_decide") {
                return;
            }
            let esito = service.decide(stato.as_str(), nota.as_str());
            *service.message.borrow_mut() = esito;
            if let Some(window) = handle.upgrade() {
                refresh(&window, &service);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::ContentId;
    use lisi_core::model::hub_command::{COMMAND_ID_MAX_LEN, COMMAND_ID_MIN_LEN, CommandId};
    use lisi_core::model::review::ReviewState;

    use super::{TEAM_REVIEW_PAGE, etichetta_dello_stato, identificativo_del_comando};

    /// Interfaccia, letta a tempo di compilazione.
    const UI: &str = include_str!("../ui/app-window.slint");

    #[test]
    fn the_review_page_index_matches_the_interface() {
        assert!(
            UI.contains(&format!("current-page == {TEAM_REVIEW_PAGE}: Rectangle")),
            "la pagina Revisione condivisa con indice {TEAM_REVIEW_PAGE} non e' nell'interfaccia"
        );
        assert!(
            UI.contains(&format!("root.open-page({TEAM_REVIEW_PAGE});")),
            "la voce di menu Revisione condivisa non naviga all'indice {TEAM_REVIEW_PAGE}"
        );
    }

    /// **La stessa decisione ha lo stesso identificativo, una diversa no.**
    ///
    /// È ciò che rende una ripetizione una ripetizione, e non una seconda
    /// decisione (ADR-0089).
    #[test]
    fn the_command_id_is_the_same_for_the_same_decision() {
        let contenuto = ContentId::new(42);
        let primo = identificativo_del_comando(contenuto, 0, ReviewState::Relevant);
        let stesso = identificativo_del_comando(contenuto, 0, ReviewState::Relevant);
        let diverso = identificativo_del_comando(contenuto, 0, ReviewState::NotRelevant);
        let dopo = identificativo_del_comando(contenuto, 1, ReviewState::Relevant);

        assert_eq!(primo, stesso);
        assert_ne!(primo, diverso);
        assert_ne!(primo, dopo);
    }

    /// L'identificativo deve essere accettato dal dominio: se non lo fosse, la
    /// decisione verrebbe rifiutata come malformata.
    #[test]
    fn every_command_id_is_accepted_by_the_domain() {
        for stato in [
            ReviewState::New,
            ReviewState::InReview,
            ReviewState::Relevant,
            ReviewState::NotRelevant,
            ReviewState::Duplicate,
            ReviewState::Archived,
            ReviewState::Reported,
        ] {
            let identificativo = identificativo_del_comando(ContentId::new(1), 0, stato);
            assert!(
                identificativo.len() >= COMMAND_ID_MIN_LEN
                    && identificativo.len() <= COMMAND_ID_MAX_LEN,
                "«{identificativo}» non rispetta la lunghezza ammessa"
            );
            assert!(
                CommandId::parse(&identificativo).is_ok(),
                "«{identificativo}» non e' un identificativo di comando valido"
            );
        }
    }

    #[test]
    fn every_state_has_a_label_for_the_operator() {
        assert_eq!(etichetta_dello_stato(None), "da rivedere");
        for stato in [
            ReviewState::Relevant,
            ReviewState::NotRelevant,
            ReviewState::Duplicate,
            ReviewState::Archived,
            ReviewState::Reported,
        ] {
            assert!(!etichetta_dello_stato(Some(stato)).is_empty());
        }
    }

    /// Una riga come l'Hub l'avrebbe consegnata.
    fn riga(id: i64, perche: &str) -> super::RigaDaRivedere {
        super::RigaDaRivedere {
            content_id: ContentId::new(id),
            source: String::from("Canale dell'ufficio"),
            level: 3,
            raised_at: lisi_core::Timestamp::from_millis(1_700_000_000_000),
            state: None,
            why: String::from(perche),
            assigned_to: None,
        }
    }

    /// **Ciò che l'Hub non ha mostrato non si spiega** (PR-02, controllo
    /// negativo 2).
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che il comando «Perché vedo questo?» diventi un modo di sapere qualcosa
    /// di un elemento che l'Hub non ha consegnato a questa postazione: un
    /// identificativo scritto a mano, o rimasto da un elenco vecchio,
    /// aprirebbe una risposta su ciò che l'autorizzazione non concede.
    #[test]
    fn cio_che_l_hub_non_ha_mostrato_non_si_spiega() {
        use lisi_core::model::explanation::ExplanationOutcome;

        let coda = vec![riga(1, "Mai esaminato; livello più alto della coda.")];
        assert_eq!(
            super::spiegazione_della_riga(&coda, 2),
            ExplanationOutcome::NotAvailable
        );
        assert_eq!(
            super::spiegazione_della_riga(&[], 1),
            ExplanationOutcome::NotAvailable
        );

        let ExplanationOutcome::Composed(risposta) = super::spiegazione_della_riga(&coda, 1) else {
            panic!("una riga mostrata dall'Hub si spiega");
        };
        // I fatti sono quelli della riga, e la versione è dichiarata come
        // quella dell'Hub.
        assert!(
            risposta.facts().contains("Mai esaminato"),
            "{}",
            risposta.facts()
        );
        assert!(
            risposta.rule().contains("versione dell'Hub"),
            "{}",
            risposta.rule()
        );
    }

    /// **Stessa riga, stessa risposta**, e senza il «perché» dell'Hub la
    /// risposta dice che l'ordine non è quello dell'ufficio.
    #[test]
    fn la_risposta_sulla_coda_e_deterministica_e_non_inventa_il_perche() {
        let coda = vec![riga(4, "")];
        assert_eq!(
            super::spiegazione_della_riga(&coda, 4),
            super::spiegazione_della_riga(&coda, 4)
        );
        let lisi_core::model::explanation::ExplanationOutcome::Composed(risposta) =
            super::spiegazione_della_riga(&coda, 4)
        else {
            panic!("una riga mostrata dall'Hub si spiega");
        };
        assert!(risposta.facts().contains("ordine di identificativo"));
    }
}

//! Collegamento fra la schermata Account e i servizi Telegram.
//!
//! È l'unico punto in cui l'interfaccia parla con i servizi degli account. Non
//! contiene logica di dominio: traduce i comandi dell'operatore in chiamate a
//! [`lisi_services::AccountService`] e [`lisi_services::AccountRuntime`], e lo
//! stato dei servizi in proprietà dell'interfaccia.
//!
//! Tre cose che questo modulo **non** fa, deliberatamente:
//!
//! - non accede a SQLite, ai file protetti, alle chiavi o a TDLib: passa solo
//!   dai servizi;
//! - non costruisce i tipi riservati delle credenziali (API id/hash): il testo
//!   digitato entra in un servizio che lo valida e lo protegge, e il segreto non
//!   torna al livello grafico;
//! - non decide quali comandi siano abilitati: quell'elenco arriva dal runtime,
//!   dove è coperto da test.
//!
//! `AccountRuntime` è la **fonte unica** dello stato di autenticazione
//! dell'account selezionato: lo stesso runtime autorizzato è quello che la
//! schermata Fonti usa per elencare le chat accessibili. Vedere
//! `docs/adr/ADR-0010-APPLICATION-SERVICES.md` e ADR-0019.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Instant;

use lisi_core::model::monitoring_account::MAX_ACTIVE_ACCOUNTS;
use lisi_core::model::{MaskedPhoneNumber, PersistedAuthStatus, TelegramAccount};
use lisi_core::text::{Actor, DisplayName};
use lisi_core::{TelegramAccountId, Timestamp};
use lisi_services::acquisition_authority::{AcquisitionAuthority, StationAuthorityService};
use lisi_services::secrets::{LoginCode, PhoneNumber, TwoFactorPassword};
use lisi_services::{
    AccountRuntime, AccountService, AuthCommand, AuthStage, Database, RuntimeMode, ServiceError,
};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::{AppWindow, TelegramAccountEntry};

/// Cartella dati dell'applicazione, dove vive l'archivio.
///
/// È la stessa che `lisi_services::sources::open_application_database` compone:
/// duplicarla qui sarebbe un secondo percorso che un giorno divergerebbe, ma il
/// servizio non la espone e ricavarla è l'unico modo per azzerare l'archivio
/// prima che qualcuno lo apra.
#[must_use]
pub fn data_root() -> Option<PathBuf> {
    // Quella del modo del processo: in Esercitazione, l'archivio separato
    // (PR-13, ADR-0129).
    lisi_services::data_directory::mode_directory()
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
pub fn now() -> Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit, costruito dal nome fisso.
fn actor() -> Result<Actor, ServiceError> {
    crate::operator::audit_actor()
}

/// Sessione dell'operatore sulla schermata Account.
///
/// Possiede il servizio degli account (profili, account, persistenza), la
/// modalità scelta e il runtime dell'account selezionato. L'interfaccia è a
/// thread singolo, quindi `Rc<RefCell<…>>` è sufficiente e non serve alcuna
/// sincronizzazione.
pub struct AccountSession {
    accounts: AccountService,
    /// Cartella base dei file protetti (configurazione dell'applicazione,
    /// chiavi degli account).
    base_dir: PathBuf,
    /// Se questa installazione ha le credenziali dell'applicazione
    /// (APP-CREDENTIALS-01, ADR-0204). Si legge alla creazione della sessione:
    /// il ciclo della schermata gira cinque volte al secondo, e decifrare a
    /// ogni giro non direbbe niente di nuovo.
    telegram_configured: bool,
    /// Modalità del connettore. **Mock è la predefinita.**
    mode: RuntimeMode,
    selected_account: Option<TelegramAccountId>,
    /// Stato **volatile** dell'accesso degli account aperti, al più
    /// [`MAX_ACTIVE_ACCOUNTS`] (ADR-0173): quello selezionato più quelli tenuti
    /// attivi. Per l'account selezionato è la fonte unica.
    runtimes: Vec<AccountRuntime>,
    /// Gli account che l'operatore ha scelto di tenere attivi anche quando ne
    /// seleziona un altro.
    kept_active: Vec<TelegramAccountId>,
    /// Messaggio d'errore quando l'apertura del runtime non riesce (per esempio
    /// modalità reale senza la feature): non c'è un runtime da cui leggerlo.
    runtime_error: Option<String>,
    /// Perché l'ultimo passo dell'accesso è stato rifiutato prima di arrivare al
    /// connettore (F-11): un numero non valido, un codice vuoto. Il ciclo
    /// periodico rilegge la schermata cinque volte al secondo, e un messaggio
    /// scritto solo sulla finestra spariva al giro dopo. Resta qui finché un
    /// passo non riesce o l'accesso non ricomincia. È una frase fissa dei tipi
    /// segreti: non contiene mai il valore scritto.
    refusal: Option<String>,
    /// La prova che questa postazione può acquisire da Telegram
    /// (TEAM-AUTHORITY-01, ADR-0092).
    ///
    /// Si ottiene **una volta**, alla creazione della sessione: una postazione
    /// che segue un Hub non la ottiene affatto, e allora nessun runtime si apre
    /// — né reale né simulato, perché l'acquisizione la esegue l'Hub.
    authority: Option<AcquisitionAuthority>,
    /// Perché l'autorità è stata rifiutata, per l'operatore.
    authority_refusal: Option<&'static str>,
    /// Modello Slint degli account, tenuto in vita per l'intera sessione.
    ///
    /// Sostituire l'intero modello (una nuova `VecModel`) a ogni pompaggio
    /// periodico (ogni 200 ms, vedere [`Self::pump`] e il timer di `main.rs`)
    /// distrugge e ricrea ogni riga della lista nell'interfaccia: un clic o
    /// una pressione di tasto in corso su una riga va perso. È **una** delle
    /// due cause accertate della mancata selezione di profili e account
    /// salvati (incidente M3B del 2026-07-29) — l'altra è nel file Slint
    /// (`FocusScope.focus-on-click`), corretta insieme a questa. Gli
    /// aggiornamenti passano da [`sync_model`], riga per riga.
    accounts_model: Rc<VecModel<TelegramAccountEntry>>,
}

/// Che cosa dire quando non si sa chi sta operando (PR-01, ADR-0117).
///
/// Fino a PR-01 le schermate scrivevano «Attore dell'audit non valido», in
/// quattro varianti. Dice lo stesso fatto in parole comuni, e dice che cosa
/// ne segue: senza un autore l'operazione non si registra, e quindi non si
/// esegue. Una frase sola, perché la stessa cosa si chiami sempre allo stesso
/// modo.
pub(crate) const NON_SI_SA_CHI_OPERA: &str =
    "Non si sa chi sta operando, quindi l'operazione non si può registrare. Non è stata eseguita.";

/// Che cosa dice la schermata Account in Esercitazione (PR-13, ADR-0129).
pub(crate) const EXERCISE_REFUSAL: &str = "In esercitazione il programma non si collega a \
     Telegram. I contenuti sono sintetici e stanno in un archivio separato.";

/// Sessione condivisa fra i gestori dei comandi.
pub type SharedSession = Rc<RefCell<AccountSession>>;

/// Crea la sessione degli account sull'archivio indicato.
///
/// L'archivio arriva da fuori, come per gli altri servizi: l'applicazione gli
/// passa quello di esercizio e i test uno in memoria. La cartella base dei file
/// protetti è quella dei dati dell'applicazione; se non è determinabile si
/// ripiega su una cartella temporanea, così che la schermata resti utilizzabile
/// in modalità dimostrativa.
#[must_use]
pub fn create_service(database: Database) -> SharedSession {
    let base_dir = lisi_services::telegram_runtime::account_data_root()
        .unwrap_or_else(|_| std::env::temp_dir());

    create_service_at(database, base_dir)
}

/// Come [`create_service`], ma con la cartella dei file protetti indicata dal
/// chiamante.
///
/// Esiste perché i test **non devono scrivere nella cartella dati reale**.
/// Fino al 2026-08-04 la usavano: `create_service` ricava la radice da
/// `account_data_root()`, e un test che salvava le credenziali di un profilo
/// fittizio scriveva un file protetto accanto a quelli dell'operatore. Due test
/// paralleli sullo stesso profilo si contendevano lo stesso file, e la suite
/// lasciava residui su una postazione di esercizio. Segnalato il 2026-07-29,
/// corretto qui.
///
/// Non è un accorgimento per i soli test: separare *dove* si scrive da *chi*
/// costruisce la sessione è la ragione per cui il percorso può essere
/// verificato invece che assunto.
#[must_use]
pub fn create_service_at(database: Database, base_dir: PathBuf) -> SharedSession {
    // L'autorità di acquisire si chiede alla configurazione conservata ACCANTO
    // agli altri file protetti della postazione: la stessa cartella base, così
    // che una prova non legga mai quella di esercizio.
    let stazione = StationAuthorityService::in_directory(&base_dir);
    // In Esercitazione il testimone operativo non esiste, e l'autorità non si
    // chiede nemmeno (PR-13, ADR-0129).
    let esito = match lisi_services::run_mode::operational() {
        Ok(operativo) => stazione.acquisition_authority(&operativo).map(Some),
        Err(_) => Ok(None),
    };
    let (authority, authority_refusal) = match esito {
        Ok(Some(esito)) => {
            let rifiuto = esito.refusal_message();
            (esito.into_granted(), rifiuto)
        }
        Ok(None) => (None, Some(EXERCISE_REFUSAL)),
        // Non si ripiega sul concedere: se non si sa che cosa sia questa
        // postazione, non si acquisisce.
        Err(_) => (
            None,
            Some(
                "Non è stato possibile stabilire se questa postazione segue un Hub: \
                 l'acquisizione da Telegram resta chiusa finché la configurazione non è \
                 leggibile.",
            ),
        ),
    };

    let telegram_configured = lisi_services::app_credentials::is_configured(&base_dir);
    Rc::new(RefCell::new(AccountSession {
        accounts: AccountService::new(database),
        base_dir,
        telegram_configured,
        mode: RuntimeMode::Mock,
        selected_account: None,
        runtimes: Vec::new(),
        kept_active: Vec::new(),
        runtime_error: None,
        refusal: None,
        authority,
        authority_refusal,
        accounts_model: Rc::new(VecModel::from(Vec::new())),
    }))
}

/// Aggiorna un modello Slint sul posto, riga per riga, invece di sostituirlo.
///
/// Sostituire l'intero modello distrugge e ricrea ogni riga della lista
/// nell'interfaccia, interrompendo un clic o una pressione di tasto in corso
/// su una riga: è **una** delle due cause accertate della mancata selezione
/// di profili e account salvati (incidente M3B del 2026-07-29), perché
/// `refresh()` viene richiamata anche dal pompaggio periodico ogni 200 ms, non
/// solo dalle azioni esplicite dell'operatore. Qui si aggiornano solo le righe
/// realmente cambiate, e si tocca il conteggio (che ricrea tutto) solo quando
/// serve davvero, cioè quando una riga è stata aggiunta o rimossa.
///
/// La proprietà "nessun reset completo quando cambia solo il contenuto" è
/// garantita per costruzione qui (guardia sul conteggio prima del ciclo), ma
/// **non è osservabile da un test unitario**: l'API pubblica di `slint`
/// (`Model`, `ModelNotify`, `ModelPeer`, …) non espone un modo per distinguere
/// dall'esterno una notifica di reset da una di riga cambiata. I test su
/// questa funzione verificano quindi solo la correttezza del contenuto
/// risultante, non quale notifica sia stata emessa.
fn sync_model<T: Clone + PartialEq + 'static>(model: &VecModel<T>, fresh: Vec<T>) {
    if model.row_count() != fresh.len() {
        model.set_vec(fresh);
        return;
    }
    for (index, new_row) in fresh.into_iter().enumerate() {
        if model.row_data(index).as_ref() != Some(&new_row) {
            model.set_row_data(index, new_row);
        }
    }
}

/// La frase di un gesto che chiede Telegram, in Esercitazione; `None` fuori.
///
/// Una frase sola per ogni gesto (CAPABILITY-AUDIT-02, CA02-06): «Cerca nel
/// passato» e «Cerca cosa manca» rispondevano «L'account non è collegato»
/// mentre la testata diceva «Account non necessario», e la Ricerca puntuale
/// diceva già questa.
#[must_use]
pub fn exercise_refusal(gesto: &str) -> Option<String> {
    lisi_services::run_mode::is_exercise().then(|| {
        format!(
            "{gesto} non si prova in Esercitazione: l'esercitazione non si collega a \
             Telegram e non ha contenuti acquisiti davvero. Qui si provano il monitoraggio, \
             la revisione, i raccoglitori e il Report."
        )
    })
}

impl AccountSession {
    /// Se l'account selezionato è autorizzato e operativo.
    ///
    /// È ciò che la schermata Fonti interroga per sapere se può elencare le chat.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.selected_runtime()
            .is_some_and(|runtime| runtime.view().stage == AuthStage::Authenticated)
    }

    /// Il runtime dell'account selezionato, se aperto.
    fn selected_runtime(&self) -> Option<&AccountRuntime> {
        let scelto = self.selected_account?;
        self.runtimes
            .iter()
            .find(|runtime| runtime.account_id() == scelto)
    }

    /// L'autorità di acquisire, se questa postazione l'ha ottenuta.
    ///
    /// Serve a costruire una richiesta di recupero per intervallo (PR-07): su
    /// una postazione che segue un Hub non c'è, e la richiesta non esiste.
    #[must_use]
    pub const fn authority(&self) -> Option<&AcquisitionAuthority> {
        self.authority.as_ref()
    }

    /// La frase di un gesto che chiede l'autorità di acquisire e non la trova
    /// (OPERATOR-UX-REMEDIATION-01, OS-03 e OS-04).
    ///
    /// # Perché due frasi, e non una
    ///
    /// Le postazioni senza autorità sono di due specie: l'Esercitazione, che
    /// non si collega per progetto (ADR-0129), e la postazione che segue un
    /// Hub, che lascia l'acquisizione all'Hub (ADR-0092). Una frase sola
    /// sull'Hub, detta in Esercitazione, parlava di una cosa che l'operatore
    /// non aveva e non gli diceva che cosa poteva provare invece.
    #[must_use]
    pub fn refused(&self, gesto: &str) -> String {
        if let Some(frase) = exercise_refusal(gesto) {
            return frase;
        }
        let perche = self.authority_refusal.unwrap_or(
            "Questa postazione non ha l'autorità di acquisire da Telegram: chiedere a chi \
             amministra la postazione.",
        );
        format!("{gesto} non parte. {perche}")
    }

    /// La postazione è stata ammessa in un Hub: da ora l'acquisizione la fa
    /// l'Hub, e questa sessione rinuncia all'autorità (FINAL-REVIEW-01,
    /// FR-003; ADR-0092).
    ///
    /// Il runtime si abbandona come quando si rimuove un account, cioè
    /// chiudendo il client TDLib; l'autorità non torna fino al riavvio, che la
    /// richiede di nuovo alla configurazione — e la configurazione ora dice che
    /// la postazione segue un Hub.
    ///
    /// Restituisce vero se un account era aperto e si è chiuso.
    pub fn relinquish_authority(&mut self) -> bool {
        // TUTTI gli account aperti, non soltanto quello selezionato: chi
        // acquisisce ora è l'Hub.
        let era_aperto = !self.runtimes.is_empty();
        self.runtimes.clear();
        self.kept_active.clear();
        self.authority = None;
        // La frase è quella che la postazione leggerà anche dopo il riavvio:
        // una sola, dal dominio.
        let frase =
            lisi_core::model::hub_client::StationRole::of_station(true).acquisition_message();
        self.authority_refusal = Some(frase);
        self.runtime_error = Some(String::from(frase));
        era_aperto
    }

    /// Runtime dell'account **selezionato**, per gli **altri servizi**.
    ///
    /// La schermata Fonti lo passa ai servizi delle fonti, che ne ricavano le
    /// chat accessibili senza che l'interfaccia tocchi il connettore.
    ///
    /// # Mai un altro account (ADR-0173, decisione 4)
    ///
    /// È sempre e soltanto quello che l'operatore ha scelto: se quell'account
    /// è limitato, scollegato o bloccato, la richiesta fallisce e l'operatore
    /// lo legge; non passa da sé a un altro account aperto. Una guardia sul
    /// sorgente lo sorveglia (`nessun_codice_ruota_gli_account`).
    pub fn runtime_mut(&mut self) -> Option<&mut AccountRuntime> {
        selected_in(&mut self.runtimes, self.selected_account)
    }

    /// I runtime di **tutti** gli account aperti, per il ciclo
    /// d'acquisizione soltanto (ADR-0173, decisione 3).
    ///
    /// Il ciclo ne ritira gli eventi e li attribuisce ai monitoraggi del loro
    /// account; non li usa per interrogare Telegram. Lo chiama soltanto il
    /// pompaggio di `main.rs`, e la guardia contro la rotazione lo verifica.
    pub fn runtimes_for_acquisition(&mut self) -> Vec<&mut AccountRuntime> {
        self.runtimes.iter_mut().collect()
    }

    /// L'account selezionato con cui legare un monitoraggio che nasce adesso
    /// (ADR-0173, decisione 3), se ce n'è uno aperto.
    ///
    /// Senza account aperto il monitoraggio nasce senza account: riceverà
    /// soltanto quando ne sarà aperto uno solo.
    #[must_use]
    pub fn binding_for_new_monitoring(&self) -> Option<lisi_services::monitoring::AccountBinding> {
        let runtime = self.selected_runtime()?;
        let account = self.accounts.account(runtime.account_id()).ok()?;
        Some(lisi_services::monitoring::AccountBinding::of(&account))
    }

    /// Tiene attivo l'account selezionato anche quando se ne seleziona un
    /// altro (ADR-0173, decisione 2): al più [`MAX_ACTIVE_ACCOUNTS`] insieme.
    ///
    /// È un gesto dell'operatore, dalla schermata Account: nessun codice lo
    /// compie da sé.
    ///
    /// # Errori
    ///
    /// Restituisce la frase per l'operatore se nessun account selezionato è
    /// aperto.
    pub fn keep_selected_active(&mut self) -> Result<&'static str, String> {
        let Some(scelto) = self.selected_account else {
            return Err(String::from("Selezionare prima un account."));
        };
        if self.selected_runtime().is_none() {
            return Err(String::from(
                "L'account selezionato non è aperto, e non si può tenere attivo.",
            ));
        }
        if !self.kept_active.contains(&scelto) {
            self.kept_active.push(scelto);
        }
        Ok("L'account resta attivo anche selezionandone un altro.")
    }

    /// Smette di tenere attivo un account: se non è quello selezionato, il
    /// suo collegamento si chiude.
    pub fn release_active(&mut self, account_id: TelegramAccountId) {
        self.kept_active.retain(|tenuto| *tenuto != account_id);
        if self.selected_account != Some(account_id) {
            self.runtimes
                .retain(|runtime| runtime.account_id() != account_id);
        }
    }

    /// Gli account collegati davvero a Telegram, con la sessione reale salvata:
    /// quelli che un passaggio di mano riprende (SERVICE-01, ADR-0203).
    #[must_use]
    pub fn linked_live_accounts(&self) -> Vec<i64> {
        if !lisi_services::TELEGRAM_RUNTIME_AVAILABLE {
            return Vec::new();
        }
        self.runtimes
            .iter()
            .filter(|runtime| runtime.is_ready())
            .filter_map(|runtime| self.accounts.account(runtime.account_id()).ok())
            .filter(|account| {
                lisi_services::AccountPaths::new(&self.base_dir, &account.uuid).has_saved_session()
            })
            .map(|account| account.id.get())
            .collect()
    }

    /// Riprende gli account che la persona aveva collegati (SERVICE-01,
    /// ADR-0203): ciascuno in modalità reale, con l'accesso avviato dalla
    /// sessione salvata e tenuto attivo. Restituisce quanti ne ha ripresi.
    ///
    /// Non è un accesso nuovo: un account senza la sessione reale salvata non
    /// si riprende, e chiedere numero o codice resta un gesto della persona.
    pub fn resume_linked(&mut self, ids: &[i64]) -> usize {
        if !lisi_services::TELEGRAM_RUNTIME_AVAILABLE {
            return 0;
        }
        let mut ripresi = Vec::new();
        for &id in ids.iter().take(MAX_ACTIVE_ACCOUNTS) {
            let Ok(account) = self.accounts.account(TelegramAccountId::new(id)) else {
                continue;
            };
            if account.auth_status != PersistedAuthStatus::Authorized
                || !lisi_services::AccountPaths::new(&self.base_dir, &account.uuid)
                    .has_saved_session()
            {
                continue;
            }
            self.selected_account = Some(account.id);
            self.mode = RuntimeMode::Live;
            self.rebuild_runtime();
            if let Err(frase) = self.start_login() {
                tracing::warn!(motivo = %frase, "account non ripreso nel passaggio di mano");
                continue;
            }
            if !self.kept_active.contains(&account.id) {
                self.kept_active.push(account.id);
            }
            ripresi.push(account.id);
        }
        if let Some(primo) = ripresi.first() {
            self.selected_account = Some(*primo);
        }
        ripresi.len()
    }

    /// Chiude i client di tutti gli account aperti, senza uscire dagli
    /// account: il passaggio di mano li riapre nell'altro processo (ADR-0203).
    pub fn close_all(&mut self) {
        for runtime in &mut self.runtimes {
            if let Err(errore) = runtime.close() {
                tracing::warn!(kind = errore.kind(), "client dell'account non chiuso");
            }
        }
        self.runtimes.clear();
        self.kept_active.clear();
    }

    /// Gli account con un collegamento aperto: il selezionato e quelli tenuti
    /// attivi.
    #[must_use]
    pub fn linked_accounts(&self) -> Vec<TelegramAccountId> {
        self.runtimes
            .iter()
            .map(AccountRuntime::account_id)
            .collect()
    }

    /// Lo stato del collegamento di un account aperto, detto per la sua riga:
    /// `None` se l'account non ha un collegamento aperto.
    ///
    /// Un account tenuto collegato può cadere mentre si lavora su un altro: la
    /// riga non deve continuare a dire «Collegato» (MULTI-ACCOUNT-02 parte 3).
    #[must_use]
    pub fn link_state(&self, account: TelegramAccountId) -> Option<LinkState> {
        let runtime = self
            .runtimes
            .iter()
            .find(|runtime| runtime.account_id() == account)?;
        Some(LinkState::of(
            runtime.is_ready(),
            runtime.view().failure.is_some(),
        ))
    }

    /// Se l'account resta collegato anche quando se ne seleziona un altro.
    #[must_use]
    pub fn is_kept_active(&self, account: TelegramAccountId) -> bool {
        self.kept_active.contains(&account)
    }

    /// Smette di tenere collegato l'account **selezionato**: resta aperto finché
    /// è selezionato, e si chiude quando se ne sceglie un altro.
    pub fn release_selected(&mut self) -> &'static str {
        if let Some(scelto) = self.selected_account {
            self.release_active(scelto);
        }
        "L'account resta collegato finché è selezionato, e si scollega quando se ne sceglie un altro."
    }

    /// Consuma gli eventi in attesa dai runtime di tutti gli account aperti.
    ///
    /// Richiamata periodicamente da `main.rs` finché la finestra resta aperta:
    /// senza, la modalità reale non apprenderebbe mai gli aggiornamenti di
    /// TDLib (parametri richiesti, numero richiesto, codice richiesto, esito)
    /// e resterebbe bloccata nello stato in cui l'avvio l'ha lasciata. Il
    /// mock risponde subito dalla propria coda: chiamarla anche in modalità
    /// dimostrativa, o senza alcun account selezionato, è innocuo.
    pub fn pump(&mut self) {
        let now = now();
        for runtime in &mut self.runtimes {
            if let Err(error) = runtime.pump(&self.accounts, now) {
                tracing::warn!(kind = error.kind(), "pompaggio degli eventi non riuscito");
            }
        }
    }

    /// Chiude i runtime degli account che non sono né selezionati né tenuti
    /// attivi: cambiare account senza averlo tenuto attivo lo chiude, come
    /// prima di MULTI-ACCOUNT-02.
    fn close_unkept(&mut self) {
        let scelto = self.selected_account;
        let tenuti = &self.kept_active;
        self.runtimes.retain(|runtime| {
            Some(runtime.account_id()) == scelto || tenuti.contains(&runtime.account_id())
        });
    }

    /// (Ri)costruisce il runtime per l'account e la modalità correnti.
    ///
    /// Ogni cambio di account o di modalità riparte da un runtime pulito: gli
    /// stati non si mescolano fra account diversi. Gli account tenuti attivi
    /// restano come sono.
    fn rebuild_runtime(&mut self) {
        if let Some(scelto) = self.selected_account {
            self.runtimes
                .retain(|runtime| runtime.account_id() != scelto);
        }
        self.close_unkept();
        self.runtime_error = None;
        // Un accesso che riparte non porta con sé il rifiuto di prima.
        self.refusal = None;

        let Some(account_id) = self.selected_account else {
            return;
        };
        // IL TETTO (ADR-0173, decisione 2): un account in più non si apre, e
        // nessuno degli attivi si chiude da sé per fargli posto.
        if self.runtimes.len() >= MAX_ACTIVE_ACCOUNTS {
            self.runtime_error = Some(
                ServiceError::ActiveAccountLimit {
                    limit: MAX_ACTIVE_ACCOUNTS,
                }
                .operator_message(),
            );
            return;
        }
        let account = match self.accounts.account(account_id) {
            Ok(account) => account,
            Err(error) => {
                self.runtime_error = Some(error.operator_message());
                return;
            }
        };

        // L'ACQUISIZIONE LA FA L'HUB (TEAM-AUTHORITY-01, ADR-0092): senza la
        // prova non si apre alcun runtime, e l'operatore legge dove il lavoro
        // viene fatto invece di un guasto.
        let Some(authority) = self.authority.as_ref() else {
            self.runtime_error = self.authority_refusal.map(String::from).or_else(|| {
                Some(String::from(
                    "L'acquisizione da Telegram non spetta a questa postazione.",
                ))
            });
            return;
        };

        match AccountRuntime::open(
            &self.accounts,
            &account,
            self.mode,
            &self.base_dir,
            authority,
        ) {
            Ok(runtime) => self.runtimes.push(runtime),
            Err(error) => {
                tracing::warn!(kind = error.kind(), "apertura del runtime non riuscita");
                self.runtime_error = Some(error.operator_message());
            }
        }
    }

    // ------------------------------------------------------- gestione account

    fn create_account(&mut self, label: &str) -> Result<&'static str, String> {
        let display = DisplayName::try_new(label)
            .map_err(ServiceError::from)
            .map_err(op_error)?;
        let actor = actor().map_err(op_error)?;
        // Ogni nuovo account usa il profilo dell'applicazione: le credenziali
        // sono quelle della distribuzione (ADR-0204), e nessuno le sceglie.
        let profile_id = self
            .accounts
            .application_profile(&actor, now())
            .map_err(op_error)?;
        let account = self
            .accounts
            .add_account(&display, profile_id, &actor, now())
            .map_err(op_error)?;
        self.selected_account = Some(account.id);
        self.rebuild_runtime();
        Ok("Account creato e selezionato. Scegliere la modalità e avviare l'accesso.")
    }

    fn select_account(&mut self, raw_id: i64) {
        let scelto = TelegramAccountId::new(raw_id);
        // UN ACCOUNT TENUTO ATTIVO SI RITROVA COM'ERA (ADR-0173): selezionarlo
        // non ne ricomincia l'accesso, e i suoi monitoraggi continuano.
        let gia_aperto = self.selected_account != Some(scelto)
            && self.kept_active.contains(&scelto)
            && self
                .runtimes
                .iter()
                .any(|runtime| runtime.account_id() == scelto);
        self.selected_account = Some(scelto);
        if gia_aperto {
            self.close_unkept();
            self.runtime_error = None;
            self.refusal = None;
            return;
        }
        self.rebuild_runtime();
    }

    /// All'avvio, se la postazione ha **un solo** account, lo sceglie (F-23).
    ///
    /// Dopo ogni riavvio l'account non era più selezionato, e il turno
    /// ricominciava cercandolo. Sceglierlo non accede a nulla: prepara il
    /// connettore dell'account, nella modalità predefinita, e l'accesso resta un
    /// gesto della persona. Con due account o più non si sceglie: quale sia
    /// quello del turno lo sa chi lavora.
    pub fn preselect_single_account(&mut self) {
        if self.selected_account.is_some() {
            return;
        }
        let Ok(accounts) = self.accounts.accounts() else {
            return;
        };
        if let [unico] = accounts.as_slice() {
            self.selected_account = Some(unico.id);
            // LA MODALITÀ SEGUE L'ACCOUNT, NON IL RIAVVIO (E2E01-02, ADR-0146).
            // Un account già autorizzato con Telegram reale si riapre in
            // modalità reale: dopo un riavvio la schermata diceva
            // «Dimostrativa» su una postazione che lavora davvero. Aprire il
            // connettore reale **non contatta Telegram** — il client nasce solo
            // con «Avvia accesso» — e l'accesso resta un gesto della persona.
            // Serve la sessione reale salvata, non soltanto «Autorizzato»: lo
            // scrive anche l'accesso dimostrativo.
            if lisi_services::TELEGRAM_RUNTIME_AVAILABLE
                && unico.auth_status == PersistedAuthStatus::Authorized
                && lisi_services::AccountPaths::new(&self.base_dir, &unico.uuid).has_saved_session()
            {
                self.mode = RuntimeMode::Live;
            }
            self.rebuild_runtime();
        }
    }

    // ------------------------------------------------------------- modalità

    fn set_mode(&mut self, mode: RuntimeMode) {
        self.mode = mode;
        // Cambiare modalità ricostruisce il connettore dell'account selezionato.
        self.rebuild_runtime();
    }

    // ----------------------------------------------------------------- accesso

    /// Registra nel nuovo audit che cosa e' stato archiviato dall'azzeramento.
    ///
    /// Non fallisce rumorosamente: se la scrittura non riesce, l'avvio prosegue
    /// e la riga viene persa. E' il compromesso meno dannoso — fermare l'avvio
    /// lascerebbe l'operatore senza strumento — ma va detto che in quel caso la
    /// catena di continuita' si interrompe.
    pub fn record_continuity(&self, record: &str) {
        let Ok(actor) = actor() else {
            tracing::error!("attore dell'audit non valido: continuita' non registrata");
            return;
        };
        if let Err(error) = self.accounts.record_reset_continuity(record, &actor, now()) {
            tracing::error!(
                kind = error.kind(),
                "riga di continuità dell'azzeramento non registrata"
            );
        }
    }

    /// Chiede l'azzeramento dello storico al prossimo avvio.
    fn request_history_reset(&mut self) -> String {
        let Ok(actor) = actor() else {
            return String::from(NON_SI_SA_CHI_OPERA);
        };
        let _ = actor;
        let Some(root) = data_root() else {
            return String::from("Cartella dati non determinabile: azzeramento non richiesto.");
        };
        match lisi_services::reset::request_archive_reset(&self.accounts, &root, now()) {
            Ok(archive) => format!(
                "Azzeramento richiesto. Il registro delle operazioni è stato salvato in {} ({} voci). \
                 L'archivio verrà azzerato alla prossima apertura del programma, \
                 prima che qualunque servizio lo apra.",
                archive.path.display(),
                archive.entries
            ),
            Err(error) => error.operator_message(),
        }
    }

    /// Rimuove l'account selezionato: riga, chiave e sessione TDLib.
    ///
    /// Il runtime viene abbandonato **prima**, perché tiene aperto il client
    /// TDLib sui file che si stanno per rimuovere: cancellarli sotto un client
    /// vivo lascerebbe l'applicazione a scrivere su un archivio che non esiste
    /// più.
    fn remove_selected_account(&mut self) -> String {
        let Some(account_id) = self.selected_account else {
            return String::from("Selezionare prima un account da rimuovere.");
        };
        self.runtimes
            .retain(|runtime| runtime.account_id() != account_id);
        self.kept_active.retain(|tenuto| *tenuto != account_id);
        self.runtime_error = None;

        let Ok(actor) = actor() else {
            return String::from(NON_SI_SA_CHI_OPERA);
        };
        match lisi_services::reset::remove_account(
            &self.accounts,
            &self.base_dir,
            account_id,
            &actor,
            now(),
        ) {
            Ok(outcome) => {
                self.selected_account = None;
                outcome.operator_message()
            }
            Err(error) => error.operator_message(),
        }
    }

    /// Azzera tutti gli account e tutti i profili, con i loro file.
    fn reset_accounts_and_profiles(&mut self) -> String {
        self.runtimes.clear();
        self.kept_active.clear();
        self.runtime_error = None;

        let Ok(actor) = actor() else {
            return String::from(NON_SI_SA_CHI_OPERA);
        };
        match lisi_services::reset::reset_accounts_and_profiles(
            &self.accounts,
            &self.base_dir,
            &actor,
            now(),
        ) {
            Ok(outcome) => {
                self.selected_account = None;
                outcome.operator_message()
            }
            Err(error) => error.operator_message(),
        }
    }

    fn start_login(&mut self) -> Result<(), String> {
        let now = now();
        let accounts = &self.accounts;
        let Some(runtime) = selected_in(&mut self.runtimes, self.selected_account) else {
            return Err(String::from("Selezionare prima un account."));
        };
        runtime.start(accounts, now).map_err(op_error)
    }

    fn submit_phone(&mut self, text: &str) -> Result<(), String> {
        let phone = PhoneNumber::try_new(text)
            .map_err(ServiceError::from)
            .map_err(op_error)?;
        let now = now();
        let accounts = &self.accounts;
        let Some(runtime) = selected_in(&mut self.runtimes, self.selected_account) else {
            return Err(String::from("Selezionare prima un account."));
        };
        runtime
            .submit_phone_number(phone, accounts, now)
            .map_err(op_error)
    }

    fn submit_code(&mut self, text: &str) -> Result<(), String> {
        let code = LoginCode::try_new(text)
            .map_err(ServiceError::from)
            .map_err(op_error)?;
        let now = now();
        let accounts = &self.accounts;
        let Some(runtime) = selected_in(&mut self.runtimes, self.selected_account) else {
            return Err(String::from("Selezionare prima un account."));
        };
        runtime.submit_code(code, accounts, now).map_err(op_error)
    }

    fn submit_password(&mut self, text: &str) -> Result<(), String> {
        let password = TwoFactorPassword::try_new(text)
            .map_err(ServiceError::from)
            .map_err(op_error)?;
        let now = now();
        let accounts = &self.accounts;
        let Some(runtime) = selected_in(&mut self.runtimes, self.selected_account) else {
            return Err(String::from("Selezionare prima un account."));
        };
        runtime
            .submit_password(password, accounts, now)
            .map_err(op_error)
    }

    /// Ricomincia l'accesso dell'account selezionato da un runtime pulito.
    ///
    /// Non è un logout remoto né una cancellazione locale: ricrea soltanto il
    /// connettore in memoria, scartando un tentativo a metà.
    fn reset_login(&mut self) {
        self.rebuild_runtime();
    }
}

/// Registra la classe tecnica di un errore e ne restituisce il messaggio per
/// l'operatore, già privo di qualunque valore riservato.
fn op_error(error: ServiceError) -> String {
    tracing::warn!(kind = error.kind(), "operazione sull'account non riuscita");
    error.operator_message()
}

/// Il runtime dell'account scelto fra quelli aperti; mai un altro.
///
/// È una funzione e non un metodo perché chi la chiama tiene in prestito, nello
/// stesso momento, il servizio degli account.
fn selected_in(
    runtimes: &mut [AccountRuntime],
    scelto: Option<TelegramAccountId>,
) -> Option<&mut AccountRuntime> {
    let scelto = scelto?;
    runtimes
        .iter_mut()
        .find(|runtime| runtime.account_id() == scelto)
}

/// Etichetta leggibile dello stato conservato di un account.
const fn status_label(status: PersistedAuthStatus) -> &'static str {
    match status {
        PersistedAuthStatus::Fresh => "Nuovo",
        PersistedAuthStatus::Authorizing => "Accesso in corso",
        PersistedAuthStatus::Authorized => "Autorizzato",
        PersistedAuthStatus::LoggedOut => "Disconnesso",
        PersistedAuthStatus::Failed => "Non riuscito",
    }
}

/// Etichetta dell'account attivo: il numero redatto della sessione corrente
/// se c'è, altrimenti quello mascherato già conservato per l'account.
///
/// Le due fonti descrivono la stessa cosa ma non sono sempre entrambe
/// disponibili: `in_memory` esiste solo se l'operatore ha inviato il numero in
/// **questa** esecuzione, mentre `stored` sopravvive ai riavvii. Riprendendo
/// una sessione già autorizzata dal binlog TDLib la prima è vuota, e senza
/// questo ripiego il pannello dichiarava «Nessun numero configurato» per un
/// account autorizzato e attivo. Nessuna delle due rivela più delle ultime due
/// cifre.
fn active_account_label(
    in_memory: Option<&str>,
    stored: Option<&MaskedPhoneNumber>,
) -> SharedString {
    // UNA FORMA SOLA (INSTALLED-APP-E2E-01, E2E01-20): la forma tenuta in
    // memoria e quella conservata mascherano diversamente, e la stessa
    // schermata mostrava lo stesso numero in due modi. Vince la conservata, che
    // è quella dell'elenco degli account; la memoria serve solo finché nulla è
    // conservato.
    if let Some(masked) = stored {
        return SharedString::from(masked.as_str());
    }
    in_memory.map_or_else(SharedString::default, SharedString::from)
}

/// Se in questa esecuzione Telegram è **collegato davvero** (E2E01-02).
///
/// Due condizioni, e servono entrambe: il connettore è quello reale, e
/// l'accesso è autenticato. Il connettore dimostrativo si autentica con un
/// codice qualunque e non riceve nulla; un account autorizzato ieri non è un
/// account collegato oggi. È l'unica definizione di «collegato» che diagnostica,
/// cruscotto e fascia di prontezza leggono: due definizioni divergerebbero.
#[must_use]
pub fn telegram_live_connected(window: &AppWindow) -> bool {
    window.get_auth_authenticated() && window.get_account_mode_live()
}

/// Titolo e spiegazione di un accesso **non ancora avviato** su un account già
/// scelto (E2E01-02).
///
/// Il connettore appena aperto è nella fase iniziale, il cui titolo generico è
/// «Nessun account configurato»: dopo un riavvio, accanto a un account
/// «Autorizzato», era una frase falsa. Qui si dice che cosa è vero: c'è un
/// account, l'accesso non è stato ripreso, e che cosa succede premendo.
const fn not_started_texts(demo: bool, authorized: bool) -> (&'static str, &'static str) {
    match (demo, authorized) {
        (true, _) => (
            "Modalità dimostrativa: accesso non avviato",
            "Premere «Avvia accesso». Nessun messaggio parte verso Telegram e nessun \
             monitoraggio riceve messaggi in questa modalità.",
        ),
        (false, true) => (
            "Telegram non collegato: accesso da riprendere",
            "Il programma è stato aperto di nuovo e la connessione a Telegram non riparte da sola. \
             Premere «Avvia accesso»: se la sessione salvata è ancora valida non serve un \
             codice nuovo. I monitoraggi non si riprendono da soli.",
        ),
        (false, false) => (
            "Accesso non avviato",
            "Premere «Avvia accesso» e seguire i passaggi: numero, codice ed eventuale \
             password arrivano da Telegram.",
        ),
    }
}

/// UUID dell'account attivo, quando ce n'è uno.
///
/// È l'identità **stabile** dell'account, quella con cui il blocco indicizza le
/// parole di sblocco: l'identificatore di riga cambierebbe se l'account venisse
/// tolto e rimesso, e la parola resterebbe legata a un account che non esiste
/// più mentre il nuovo risulterebbe non protetto.
#[must_use]
pub fn active_account_uuid(session: &SharedSession) -> Option<String> {
    let session = session.borrow();
    let id = session.selected_account?;
    match session.accounts.account(id) {
        Ok(account) => Some(account.uuid.as_str().to_owned()),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "account attivo non leggibile");
            None
        }
    }
}

/// Lo stato del collegamento di un account aperto (MULTI-ACCOUNT-02 parte 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Collegato e pronto: i suoi monitoraggi ricevono.
    Ready,
    /// Aperto, ma l'accesso non è ancora pronto.
    Connecting,
    /// Aperto, e l'ultima operazione è fallita.
    Failed,
}

impl LinkState {
    /// Lo stato da due fatti del collegamento: se è pronto, e se l'ultima
    /// operazione è fallita. Pronto vince: un errore passato non spegne un
    /// account che riceve.
    #[must_use]
    pub const fn of(ready: bool, failed: bool) -> Self {
        if ready {
            Self::Ready
        } else if failed {
            Self::Failed
        } else {
            Self::Connecting
        }
    }

    /// La parola sulla riga dell'account.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ready => "Collegato",
            Self::Connecting => "In collegamento",
            Self::Failed => "Collegamento in errore",
        }
    }
}

/// Quanti account sono collegati insieme, sul tetto di
/// [`lisi_core::model::monitoring_account::MAX_ACTIVE_ACCOUNTS`]
/// (MULTI-ACCOUNT-02 parte 3).
///
/// Con uno o nessuno non dice niente: è la situazione di sempre.
fn linked_line(collegati: usize) -> String {
    if collegati < 2 {
        return String::new();
    }
    format!(
        "Account collegati insieme: {collegati} su {}. Ogni monitoraggio riceve soltanto dal suo \
         account.",
        lisi_core::model::monitoring_account::MAX_ACTIVE_ACCOUNTS
    )
}

/// La frase per i monitoraggi in corso senza account, quando non ricevono
/// perché gli account collegati sono più d'uno (ADR-0173).
///
/// Senza, l'operatore vedrebbe un monitoraggio in corso che tace e penserebbe
/// a una chat silenziosa.
fn unbound_note(collegati: usize, senza_account: usize) -> String {
    if collegati < 2 || senza_account == 0 {
        return String::new();
    }
    let quali = if senza_account == 1 {
        String::from(
            "Un monitoraggio in corso non ha un account d'ufficio registrato, e non riceve",
        )
    } else {
        format!(
            "{senza_account} monitoraggi in corso non hanno un account d'ufficio registrato, e non \
             ricevono"
        )
    };
    format!(
        "{quali} messaggi finché è collegato più di un account: sono nati prima che il programma \
         registrasse l'account di ogni monitoraggio. Ricevono di nuovo quando resta collegato \
         un account solo."
    )
}

/// Traduce un account nel modello atteso dall'interfaccia.
///
/// Il numero compare **solo mascherato**, quando noto: il numero pieno non è mai
/// né persistito né mostrato.
fn to_account_entry(
    account: &TelegramAccount,
    selected: Option<TelegramAccountId>,
    link: Option<LinkState>,
    kept: bool,
) -> TelegramAccountEntry {
    TelegramAccountEntry {
        linked: link.is_some(),
        link_label: SharedString::from(link.map_or("", LinkState::label)),
        link_trouble: link == Some(LinkState::Failed),
        kept,
        id: i32::try_from(account.id.get()).unwrap_or(0),
        label: SharedString::from(account.label.as_str()),
        status: SharedString::from(status_label(account.auth_status)),
        masked_phone: account
            .masked_phone
            .as_ref()
            .map_or_else(SharedString::default, |masked| {
                SharedString::from(masked.as_str())
            }),
        selected: selected == Some(account.id),
    }
}

/// Riporta nell'interfaccia lo stato osservabile della sessione.
///
/// `message`, quando presente, è il riscontro di un'operazione di gestione
/// (creazione profilo, salvataggio credenziali, …). Se assente, il riscontro
/// precedente resta invariato.
/// Titolo e spiegazione dell'accesso in modalità dimostrativa (F-06).
///
/// I testi del connettore vero dicevano «Telegram ha inviato un codice»
/// anche qui, dove Telegram non riceve nulla: chi si esercitava aspettava un
/// codice che non sarebbe mai arrivato, e non sapeva che cosa scrivere.
const fn demo_texts(stage: AuthStage) -> (&'static str, &'static str) {
    match stage {
        AuthStage::NeedPhoneNumber => (
            "Modalità dimostrativa: scrivere un numero qualunque",
            "Nessun messaggio parte verso Telegram. Va bene un numero inventato, nella forma +39 \
             seguito dalle cifre.",
        ),
        AuthStage::NeedCode => (
            "Modalità dimostrativa: scrivere un codice qualunque",
            "Telegram non ha inviato nulla: in questa modalità non viene contattato. Va bene \
             qualunque codice di cifre, per esempio 12345.",
        ),
        AuthStage::NeedPassword => (
            "Modalità dimostrativa: scrivere una password qualunque",
            "Non c'è una verifica in due passaggi vera: va bene qualunque parola.",
        ),
        AuthStage::Authenticated => (
            "Accesso dimostrativo, nessuna sessione Telegram",
            "In questa modalità un monitoraggio non riceve messaggi. Per esercitarsi con messaggi \
             di prova, avvisi e documenti, aprire l'Esercitazione dalla Guida.",
        ),
        other => (other.headline(), other.detail()),
    }
}

thread_local! {
    /// Quando è cominciata la preparazione dell'accesso in corso.
    static PREPARAZIONE: Cell<Option<Instant>> = const { Cell::new(None) };
}

pub fn refresh(window: &AppWindow, session: &SharedSession, message: Option<&str>) {
    let session = session.borrow();

    // Elenco degli account.
    let collegati = session.linked_accounts();
    let accounts: Vec<TelegramAccountEntry> = match session.accounts.accounts() {
        Ok(list) => list
            .iter()
            .map(|account| {
                to_account_entry(
                    account,
                    session.selected_account,
                    session.link_state(account.id),
                    session.is_kept_active(account.id),
                )
            })
            .collect(),
        Err(error) => {
            tracing::warn!(kind = error.kind(), "account non leggibili");
            Vec::new()
        }
    };
    sync_model(&session.accounts_model, accounts);

    window.set_selected_account_id(
        session
            .selected_account
            .map_or(0, |id| i32::try_from(id.get()).unwrap_or(0)),
    );

    window.set_telegram_configured(session.telegram_configured);
    window.set_account_mode_live(session.mode == RuntimeMode::Live);

    // La capacita' del binario non cambia mentre il programma gira, ma si
    // pubblica qui insieme al resto dello stato dell'account: e' li' che
    // l'interfaccia la usa, ed e' li' che chi legge questo codice la cerca.
    window.set_telegram_runtime_available(lisi_services::TELEGRAM_RUNTIME_AVAILABLE);
    window.set_telegram_runtime_missing_reason(SharedString::from(
        if lisi_services::TELEGRAM_RUNTIME_AVAILABLE {
            ""
        } else {
            lisi_services::TELEGRAM_RUNTIME_MISSING_REASON
        },
    ));
    // Il dettaglio del messaggio SIC-15 viaggia con il testo: senza, il
    // riquadro mostrerebbe «Dettagli tecnici» e aprirebbe una riga vuota.
    window.set_telegram_runtime_missing_detail(SharedString::from(
        if lisi_services::TELEGRAM_RUNTIME_AVAILABLE {
            ""
        } else {
            lisi_services::TELEGRAM_RUNTIME_MISSING_DETAIL
        },
    ));
    window.set_account_selected(session.selected_account.is_some());

    // PIÙ ACCOUNT COLLEGATI INSIEME (MULTI-ACCOUNT-02 parte 3, ADR-0173).
    let scelto_collegato = session
        .selected_account
        .is_some_and(|scelto| collegati.contains(&scelto));
    window.set_selected_account_linked(scelto_collegato);
    window.set_selected_account_kept(
        session
            .selected_account
            .is_some_and(|scelto| session.is_kept_active(scelto)),
    );
    window.set_linked_accounts_line(SharedString::from(linked_line(collegati.len())));
    let senza_account = if collegati.len() > 1 {
        session
            .accounts
            .running_monitorings_without_account()
            .unwrap_or_else(|error| {
                tracing::warn!(
                    kind = error.kind(),
                    "monitoraggi senza account non leggibili"
                );
                0
            })
    } else {
        0
    };
    window.set_unbound_monitorings_note(SharedString::from(unbound_note(
        collegati.len(),
        senza_account,
    )));

    if let Some(text) = message {
        window.set_account_management_message(SharedString::from(text));
    }

    // Stato dell'accesso: dal runtime quando esiste, altrimenti valori di riposo.
    if let Some(runtime) = session.selected_runtime() {
        let view = runtime.view();
        let demo = session.mode == RuntimeMode::Mock;
        window.set_auth_demo(demo);
        let sessione_salvata = || {
            session
                .selected_account
                .and_then(|id| session.accounts.account(id).ok())
                .is_some_and(|account| {
                    account.auth_status == PersistedAuthStatus::Authorized
                        && lisi_services::AccountPaths::new(&session.base_dir, &account.uuid)
                            .has_saved_session()
                })
        };
        let (headline, detail) = if view.stage == AuthStage::FirstRun {
            // Un account c'è — il runtime esiste solo per un account scelto —
            // e l'accesso non è partito (E2E01-02).
            not_started_texts(demo, !demo && sessione_salvata())
        } else if demo {
            demo_texts(view.stage)
        } else {
            (view.stage.headline(), view.stage.detail())
        };
        window.set_auth_headline(crate::lingua::schermo(headline));
        // Una preparazione che dura dice da quanto (OBS-TG-1): il momento in
        // cui è cominciata si ricorda fra un giro di pompaggio e l'altro.
        let preparazione = PREPARAZIONE.with(|inizio| {
            if !demo && view.stage == AuthStage::Preparing {
                let da = inizio.get().unwrap_or_else(Instant::now);
                inizio.set(Some(da));
                Some(da)
            } else {
                inizio.set(None);
                None
            }
        });
        match preparazione {
            Some(da) => window.set_auth_detail(crate::lingua::schermo(
                lisi_services::auth::preparing_detail(da.elapsed()),
            )),
            None => window.set_auth_detail(crate::lingua::schermo(detail)),
        }
        window.set_auth_busy(view.busy);
        window.set_auth_authenticated(view.stage == AuthStage::Authenticated);
        window.set_auth_needs_phone(view.stage == AuthStage::NeedPhoneNumber);
        window.set_auth_needs_code(view.stage == AuthStage::NeedCode);
        window.set_auth_needs_password(view.stage == AuthStage::NeedPassword);
        // `view.account_label` deriva dal numero tenuto **in memoria**
        // (`AuthenticationService::phone`), che si popola solo quando
        // l'operatore invia il numero in questa sessione. Riprendendo una
        // sessione gia' autorizzata dal binlog TDLib quel passaggio non
        // avviene mai, e il pannello dell'account attivo mostrava «Nessun
        // numero configurato» **per un account autorizzato e attivo**: una
        // dicitura falsa, che invitava a configurare qualcosa di gia'
        // configurato (rilevata dall'operatore nel pilot del 2026-07-30).
        // Il numero mascherato e' invece conservato sul database e
        // preservato dagli aggiornamenti di stato (`COALESCE` in
        // `lisi-storage`): quando quello in memoria manca si ricade su
        // quello, che e' la stessa informazione e non rivela piu' delle
        // ultime due cifre.
        let stored_masked = session
            .selected_account
            .and_then(|id| session.accounts.account(id).ok())
            .and_then(|account| account.masked_phone);
        window.set_auth_account_label(active_account_label(
            view.account_label.as_deref(),
            stored_masked.as_ref(),
        ));
        window.set_auth_failure(
            view.failure
                .as_deref()
                .or(session.refusal.as_deref())
                .map_or_else(SharedString::default, SharedString::from),
        );

        // I flag arrivano dal runtime: l'interfaccia non li ricalcola.
        window.set_can_start(view.allows(AuthCommand::Start));
        window.set_can_submit_phone(view.allows(AuthCommand::SubmitPhoneNumber));
        window.set_can_submit_code(view.allows(AuthCommand::SubmitCode));
        window.set_can_submit_password(view.allows(AuthCommand::SubmitPassword));
        window.set_can_cancel(view.allows(AuthCommand::Cancel));
    } else {
        // Nessun account selezionato, o modalità reale non disponibile.
        window.set_auth_demo(false);
        let no_account = session.selected_account.is_none();
        window.set_auth_headline(if no_account {
            crate::lingua::schermo("Nessun account selezionato")
        } else {
            crate::lingua::schermo("Accesso non disponibile")
        });
        window.set_auth_detail(if no_account {
            crate::lingua::schermo(NESSUN_ACCOUNT_PER_L_ACCESSO)
        } else {
            SharedString::default()
        });
        window.set_auth_busy(false);
        window.set_auth_authenticated(false);
        window.set_auth_needs_phone(false);
        window.set_auth_needs_code(false);
        window.set_auth_needs_password(false);
        window.set_auth_account_label(SharedString::default());
        window.set_auth_failure(
            session
                .runtime_error
                .as_deref()
                .map_or_else(SharedString::default, SharedString::from),
        );
        window.set_can_start(false);
        window.set_can_submit_phone(false);
        window.set_can_submit_code(false);
        window.set_can_submit_password(false);
        window.set_can_cancel(false);
    }
}

/// Svuota i campi che hanno contenuto un valore riservato.
///
/// Un valore riservato non deve restare nel widget dopo essere stato usato: la
/// finestra può restare aperta per ore, e un codice ancora visibile è un codice
/// leggibile da chi passa davanti allo schermo.
fn clear_secret_inputs(window: &AppWindow) {
    window.set_phone_input(SharedString::default());
    window.set_code_input(SharedString::default());
    window.set_password_input(SharedString::default());
}

/// Registra i gestori dei comandi della schermata Account.
pub fn wire(window: &AppWindow, session: &SharedSession) {
    // Il modello degli account è assegnato alla finestra **una sola volta**,
    // qui: da questo punto in avanti `refresh()` ne aggiorna il contenuto sul
    // posto (`sync_model`) e non lo sostituisce mai più. Vedere la
    // documentazione di `AccountSession::accounts_model`.
    {
        let session = session.borrow();
        window.set_telegram_accounts(ModelRc::from(Rc::clone(&session.accounts_model)));
    }

    // ----------------------------------------------------- gestione account
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_create_account(move || {
            if crate::lock::refuse_while_locked("create_account") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let outcome = session
                .borrow_mut()
                .create_account(window.get_account_label_input().as_ref());
            window.set_account_label_input(SharedString::default());
            refresh(&window, &session, Some(&message_of(outcome)));
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_select_account(move |id| {
            if crate::lock::refuse_while_locked("select_account") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            session.borrow_mut().select_account(i64::from(id));
            refresh(&window, &session, Some("Account selezionato."));
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_keep_account_linked(move || {
            if crate::lock::refuse_while_locked("keep_account_linked") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let esito = session.borrow_mut().keep_selected_active();
            let frase = match esito {
                Ok(frase) => String::from(frase),
                Err(frase) => frase,
            };
            refresh(&window, &session, Some(&frase));
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_release_account_linked(move || {
            if crate::lock::refuse_while_locked("release_account_linked") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let frase = session.borrow_mut().release_selected();
            refresh(&window, &session, Some(frase));
        });
    }

    // ------------------------------------------------------------ modalità
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_choose_mock(move || {
            if crate::lock::refuse_while_locked("choose_mock") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            session.borrow_mut().set_mode(RuntimeMode::Mock);
            refresh(
                &window,
                &session,
                Some("Modalità dimostrativa selezionata."),
            );
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_choose_live(move || {
            if crate::lock::refuse_while_locked("choose_live") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            session.borrow_mut().set_mode(RuntimeMode::Live);
            refresh(
                &window,
                &session,
                Some("Modalità Telegram reale selezionata: userà l'account d'ufficio autorizzato."),
            );
        });
    }

    // -------------------------------------------------------------- accesso
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_start_login(move || {
            if crate::lock::refuse_while_locked("start_login") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let esito = session.borrow_mut().start_login();
            session.borrow_mut().refusal = esito.err();
            // Un passo dell'accesso rende vecchio l'esito della gestione degli
            // account («Account creato e selezionato…», F-27).
            window.set_account_management_message(SharedString::default());
            refresh(&window, &session, None);
        });
    }

    // Comandi distruttivi. La conferma vive nell'interfaccia (un secondo clic
    // su un pulsante che cambia testo): qui si esegue soltanto, perche' un
    // comando che chiedesse conferma da se' la chiederebbe anche a un
    // chiamante che l'ha gia' ottenuta.
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_remove_account(move || {
            if crate::lock::refuse_while_locked("remove_account") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let message = session.borrow_mut().remove_selected_account();
            refresh(&window, &session, Some(&message));
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_reset_accounts(move || {
            if crate::lock::refuse_while_locked("reset_accounts") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let message = session.borrow_mut().reset_accounts_and_profiles();
            refresh(&window, &session, Some(&message));
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_reset_history(move || {
            if crate::lock::refuse_while_locked("reset_history") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let message = session.borrow_mut().request_history_reset();
            // L'avviso compare **subito**, non al riavvio: fra la richiesta e
            // l'apertura che la esegue puo' passare un tempo qualunque, e in
            // quell'intervallo l'archivio appare intatto perche' lo e'. Chi
            // riapre - anche qualcun altro - deve trovare detto che una
            // cancellazione totale e' in attesa.
            if data_root().is_some_and(|root| lisi_services::reset::reset_is_pending(&root)) {
                window.set_archive_reset_pending_notice(crate::lingua::schermo(
                    "Un azzeramento dell'archivio è stato richiesto e non è ancora avvenuto: alla prossima apertura dell'applicazione monitoraggi, storico, account, profili, fonti e dizionari saranno cancellati.",
                ));
            }
            refresh(&window, &session, Some(&message));
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_submit_phone(move || {
            if crate::lock::refuse_while_locked("submit_phone") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let esito = session
                .borrow_mut()
                .submit_phone(window.get_phone_input().as_ref());
            clear_secret_inputs(&window);
            session.borrow_mut().refusal = esito.err();
            // Un passo dell'accesso rende vecchio l'esito della gestione degli
            // account («Account creato e selezionato…», F-27).
            window.set_account_management_message(SharedString::default());
            refresh(&window, &session, None);
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_submit_code(move || {
            if crate::lock::refuse_while_locked("submit_code") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let esito = session
                .borrow_mut()
                .submit_code(window.get_code_input().as_ref());
            clear_secret_inputs(&window);
            session.borrow_mut().refusal = esito.err();
            // Un passo dell'accesso rende vecchio l'esito della gestione degli
            // account («Account creato e selezionato…», F-27).
            window.set_account_management_message(SharedString::default());
            refresh(&window, &session, None);
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_submit_password(move || {
            if crate::lock::refuse_while_locked("submit_password") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let esito = session
                .borrow_mut()
                .submit_password(window.get_password_input().as_ref());
            clear_secret_inputs(&window);
            session.borrow_mut().refusal = esito.err();
            // Un passo dell'accesso rende vecchio l'esito della gestione degli
            // account («Account creato e selezionato…», F-27).
            window.set_account_management_message(SharedString::default());
            refresh(&window, &session, None);
        });
    }
    {
        let weak = window.as_weak();
        let session = Rc::clone(session);
        window.on_cancel_login(move || {
            if crate::lock::refuse_while_locked("cancel_login") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            session.borrow_mut().reset_login();
            clear_secret_inputs(&window);
            refresh(&window, &session, Some("Accesso ricominciato da capo."));
        });
    }

    refresh(window, session, None);
}

/// Riscrive l'esito di un'operazione di gestione in un messaggio da mostrare.
fn message_of(outcome: Result<&'static str, String>) -> String {
    match outcome {
        Ok(message) => String::from(message),
        Err(message) => message,
    }
}

/// Che cosa fare quando nessun account è selezionato, nella sezione Accesso.
///
/// Dal 2026-11 le credenziali sono dell'applicazione e i loro profili non
/// esistono più (APP-CREDENTIALS-01): la frase della 0.2.2 chiedeva ancora di
/// creare un account «su un profilo» (COLLAUDO-FIX-01, CU01-011). Il comando
/// nominato è quello che la schermata mostra.
const NESSUN_ACCOUNT_PER_L_ACCESSO: &str = "Selezionare un account, o aggiungerne uno con «Aggiungi un altro account…», per avviare \
     l'accesso.";

#[cfg(test)]
mod tests {
    use lisi_core::model::MaskedPhoneNumber;

    use super::active_account_label;

    /// **Senza account, la sezione Accesso non parla di profili che non
    /// esistono più, e nomina il comando che c'è** (COLLAUDO-FIX-01, CU01-011).
    /// Vista rossa con la frase della 0.2.2, «o crearne uno su un profilo».
    #[test]
    fn senza_account_l_accesso_non_parla_di_profili() {
        let frase = super::NESSUN_ACCOUNT_PER_L_ACCESSO;
        assert!(!frase.to_lowercase().contains("profil"), "{frase}");
        let interfaccia = include_str!("../ui/app-window.slint");
        assert!(
            interfaccia.contains("@tr(\"Aggiungi un altro account\\u{2026}\")"),
            "il comando nominato deve esistere nella schermata"
        );
        assert!(frase.contains("«Aggiungi un altro account…»"), "{frase}");
    }

    /// Manifest di questo crate, letto a tempo di compilazione.
    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Sessione di prova su un archivio in memoria e una cartella **propria**.
    ///
    /// La cartella temporanea viene restituita insieme alla sessione e va
    /// tenuta in vita per tutta la durata del test: quando cade, si porta via
    /// i file protetti che il test ha scritto.
    ///
    /// Nessun test deve usare `create_service` direttamente: quella ricava la
    /// radice da `account_data_root()`, cioè la cartella dati dell'operatore.
    fn session_in_own_directory() -> (super::SharedSession, tempfile::TempDir) {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea di prova deve potersi creare");
        };
        let Ok(database) = lisi_services::Database::open_in_memory() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let session = super::create_service_at(database, directory.path().to_path_buf());
        (session, directory)
    }

    /// **Un numero rifiutato resta detto anche dopo il ciclo periodico** (F-11).
    ///
    /// Vista sul programma vero: il motivo si scriveva sulla finestra e il
    /// giro successivo del ciclo, che rilegge la schermata cinque volte al
    /// secondo, lo cancellava. Il campo si svuotava e non si leggeva nulla.
    #[test]
    fn un_numero_rifiutato_resta_detto_dopo_il_ciclo() {
        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        let (session, _cartella) = session_in_own_directory();
        {
            let mut s = session.borrow_mut();
            let Ok(_) = s.create_account("Redazione") else {
                panic!("l'account di prova deve potersi creare");
            };
        }
        super::wire(&window, &session);
        window.invoke_start_login();
        window.set_phone_input(slint::SharedString::from("abc"));
        window.invoke_submit_phone();
        // Il giro del ciclo periodico.
        super::refresh(&window, &session, None);
        let detto = window.get_auth_failure().to_string();
        assert!(!detto.is_empty(), "il rifiuto del numero non si legge più");
        assert!(!detto.contains("abc"), "il motivo ripete il valore scritto");
        // Un accesso che ricomincia non porta il rifiuto di prima.
        window.invoke_cancel_login();
        super::refresh(&window, &session, None);
        assert!(window.get_auth_failure().is_empty());
    }

    /// **Dalla schermata Account si tiene collegato un account e poi lo si
    /// lascia andare** (MULTI-ACCOUNT-02 parte 3, ADR-0173). Il gesto passa dai
    /// comandi della finestra, e la schermata dice quanti account sono
    /// collegati e quali. Prova negativa: senza il gesto, cambiare account
    /// scollega il precedente.
    #[test]
    fn dalla_schermata_si_tiene_collegato_un_account_e_lo_si_lascia() {
        use slint::Model;

        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova deve potersi costruire");
        };
        let (session, _cartella) = session_in_own_directory();
        super::wire(&window, &session);
        let primo = {
            let mut s = session.borrow_mut();
            account_collegato(&mut s, "Ufficio A")
        };
        super::refresh(&window, &session, None);
        assert!(window.get_selected_account_linked());
        assert!(!window.get_selected_account_kept());
        assert!(
            window.get_linked_accounts_line().is_empty(),
            "un account solo: niente da dire"
        );

        window.invoke_keep_account_linked();
        assert!(
            window.get_selected_account_kept(),
            "il gesto tiene collegato A"
        );
        {
            let mut s = session.borrow_mut();
            let _secondo = account_collegato(&mut s, "Ufficio B");
        }
        super::refresh(&window, &session, None);
        assert!(
            window.get_linked_accounts_line().contains("2 su 3"),
            "{}",
            window.get_linked_accounts_line()
        );
        let righe = window.get_telegram_accounts();
        let riga_a = righe
            .iter()
            .find(|riga| i64::from(riga.id) == primo)
            .unwrap_or_else(|| panic!("la riga di A c'è"));
        assert!(
            riga_a.linked && riga_a.kept && !riga_a.selected,
            "A è collegato, non selezionato"
        );

        // Anche B resta collegato; poi si torna su A e lo si lascia andare:
        // scegliendo di nuovo B, A si scollega e B resta.
        window.invoke_keep_account_linked();
        window.invoke_select_account(i32::try_from(primo).unwrap_or(0));
        window.invoke_release_account_linked();
        assert!(!window.get_selected_account_kept());
        let secondo = session
            .borrow()
            .linked_accounts()
            .into_iter()
            .find(|id| id.get() != primo);
        let Some(secondo) = secondo else {
            panic!("B è ancora collegato");
        };
        window.invoke_select_account(i32::try_from(secondo.get()).unwrap_or(0));
        assert_eq!(
            session.borrow().linked_accounts(),
            vec![secondo],
            "lasciato andare, A si scollega quando si sceglie B"
        );
        assert!(window.get_linked_accounts_line().is_empty());
    }

    /// **La riga di un account dice lo stato vero del suo collegamento**
    /// (MULTI-ACCOUNT-02 parte 3): «Collegato» soltanto se è pronto, «In
    /// collegamento» se l'accesso non è finito, «Collegamento in errore» se
    /// l'ultima operazione è fallita. Prova negativa: un account aperto e non
    /// pronto detto «Collegato» → rossa.
    #[test]
    fn la_riga_dice_lo_stato_vero_del_collegamento() {
        use super::LinkState;

        let (session, _directory) = session_in_own_directory();
        let mut session = session.borrow_mut();
        let primo = lisi_core::TelegramAccountId::new(account_collegato(&mut session, "Ufficio A"));
        assert!(session.keep_selected_active().is_ok());
        assert_eq!(session.link_state(primo), Some(LinkState::Ready));

        assert!(session.create_account("Ufficio B").is_ok());
        let Some(secondo) = session.selected_account else {
            panic!("B è selezionato");
        };
        assert_eq!(
            session.link_state(secondo),
            Some(LinkState::Connecting),
            "aperto, accesso non ancora fatto"
        );
        assert_eq!(
            LinkState::of(false, true),
            LinkState::Failed,
            "aperto e fallito"
        );
        assert_eq!(LinkState::of(false, false), LinkState::Connecting);
        assert_eq!(LinkState::of(true, true), LinkState::Ready, "pronto vince");
        assert_eq!(
            session.link_state(primo),
            Some(LinkState::Ready),
            "A non ne risente"
        );
        assert_eq!(LinkState::Ready.label(), "Collegato");
        assert_eq!(LinkState::Connecting.label(), "In collegamento");
        assert_eq!(LinkState::Failed.label(), "Collegamento in errore");
    }

    /// **Le frasi dei più account: niente con uno solo, il conto sul tetto con
    /// più d'uno, e i monitoraggi senza account soltanto se ci sono**
    /// (MULTI-ACCOUNT-02 parte 3).
    #[test]
    fn le_frasi_dei_piu_account() {
        assert!(super::linked_line(0).is_empty());
        assert!(super::linked_line(1).is_empty());
        assert!(super::linked_line(3).starts_with("Account collegati insieme: 3 su 3."));
        assert!(
            super::unbound_note(1, 4).is_empty(),
            "con un account solo ricevono"
        );
        assert!(super::unbound_note(2, 0).is_empty(), "nessuno da avvisare");
        assert!(super::unbound_note(2, 1).starts_with("Un monitoraggio in corso"));
        assert!(super::unbound_note(3, 2).starts_with("2 monitoraggi in corso"));
        assert!(super::unbound_note(2, 2).contains("account solo"));
    }

    /// Questo file, letto a tempo di compilazione.
    const SELF_SOURCE: &str = include_str!("account.rs");

    /// Interfaccia principale, letta a tempo di compilazione.
    const UI: &str = include_str!("../ui/app-window.slint");

    /// **Una postazione ammessa in un Hub rinuncia subito all'autorità**
    /// (FINAL-REVIEW-01, FR-003).
    #[test]
    fn a_station_admitted_into_a_hub_gives_up_its_authority_at_once() {
        let (session, _cartella) = session_in_own_directory();
        let mut session = session.borrow_mut();
        session.relinquish_authority();
        assert!(session.authority().is_none(), "l'autorità non resta");
        assert!(
            session.runtime_mut().is_none(),
            "nessun runtime resta aperto"
        );
        assert!(
            session
                .runtime_error
                .as_deref()
                .is_some_and(|frase| frase.contains("Hub")),
            "l'operatore legge dove si acquisisce: {:?}",
            session.runtime_error
        );
        // E nessun runtime si riapre: senza autorità il percorso si ferma.
        session.rebuild_runtime();
        assert!(session.runtime_mut().is_none());
    }

    /// Il collegamento all'Hub, quando ammette, toglie l'autorità: la
    /// guardia legge il gestore, perché la prova funzionale richiederebbe un
    /// Hub vero (HVQ-104).
    #[test]
    fn the_hub_connection_handler_gives_up_the_authority_when_admitted() {
        const TEAM_LIVE: &str = include_str!("team_live.rs");
        let Some((produzione, _)) = TEAM_LIVE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        assert!(
            produzione.contains("if segue_l_hub && session.borrow_mut().relinquish_authority()"),
            "il gestore del collegamento deve togliere l'autorità alla sessione ammessa"
        );
        assert!(
            produzione.contains("Ok(esito) => (esito.operator_message(), esito.is_connected())"),
            "l'esito dell'arruolamento deve dire se la postazione segue l'Hub"
        );
    }

    #[test]
    fn the_destructive_commands_stay_closed_until_the_operator_opens_them() {
        // Rilievo dell'operatore il 2026-08-04: un blocco distruttivo
        // permanentemente aperto in una schermata che si usa di routine e'
        // pericoloso per **posizione**, non solo per etichetta. Non si puo'
        // cliccare per sbaglio cio' che non e' nemmeno disegnato.
        assert!(
            UI.contains("reset-panel := Rectangle {"),
            "il pannello richiudibile deve esistere"
        );
        assert!(
            UI.contains("property <bool> open: false;"),
            "il pannello distruttivo deve nascere chiuso"
        );

        let Some((_, inside)) = UI.split_once("if reset-panel.open:") else {
            panic!("i comandi distruttivi devono stare dentro il pannello richiudibile");
        };
        assert!(
            inside.contains("Sì, cancella tutto l'archivio"),
            "il comando piu' distruttivo deve stare dentro il pannello, non fuori"
        );
    }

    #[test]
    fn no_test_builds_a_session_on_the_real_data_directory() {
        // Il test precedente prova il proprio isolamento, non quello degli
        // altri: basterebbe un test nuovo scritto per abitudine con
        // `create_service` per riaprire il debito, e nessuno se ne
        // accorgerebbe finche' qualcuno non perde di nuovo la propria
        // configurazione. L'ago si compone, cosi' che non compaia in questo
        // sorgente e il controllo non trovi se stesso.
        let needle = concat!("create_service", "(database)");
        let Some((_, tests)) = SELF_SOURCE.split_once("mod tests {") else {
            panic!("il modulo di prova deve esistere");
        };

        assert!(
            !tests.contains(needle),
            "un test costruisce la sessione sulla cartella dati dell'operatore: usare \
             session_in_own_directory()"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_test_session_reads_its_protected_files_in_its_own_directory() {
        // Il debito segnalato il 2026-07-29: i test scrivevano nella cartella
        // dati reale. Un profilo fittizio salvava un file protetto accanto a
        // quelli dell'operatore, due test paralleli si contendevano lo stesso
        // file, e la suite lasciava residui su una postazione di esercizio.
        //
        // Dal 2026-11-13 la sessione non scrive credenziali (ADR-0204): legge
        // la configurazione dell'applicazione. Il test verifica che la legga
        // **dalla propria cartella**: configurata in una, assente nell'altra.
        use lisi_services::app_credentials::{DISTRIBUTION_FILE, import_distribution_file};

        if lisi_services::app_credentials::is_configured(&std::env::temp_dir().join("vuota")) {
            // Le variabili d'ambiente dello sviluppo valgono ovunque.
            return;
        }
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea di prova deve potersi creare");
        };
        let file = directory.path().join(DISTRIBUTION_FILE);
        assert!(
            std::fs::write(
                &file,
                "api_id=1234567\napi_hash=0123456789abcdef0123456789abcdef\n"
            )
            .is_ok()
        );
        assert!(import_distribution_file(&file, directory.path()).is_ok());
        let Ok(database) = lisi_services::Database::open_in_memory() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let configurata = super::create_service_at(database, directory.path().to_path_buf());
        assert!(configurata.borrow().telegram_configured);

        let (vuota, _cartella) = session_in_own_directory();
        assert!(
            !vuota.borrow().telegram_configured,
            "una sessione non legge la configurazione di un'altra cartella"
        );
    }

    /// Regressione del pilot del 2026-07-30: riprendendo una sessione già
    /// autorizzata dal binlog TDLib, l'operatore non invia il numero in questa
    /// esecuzione, quindi il numero in memoria non esiste. Il pannello
    /// dell'account attivo dichiarava allora «Nessun numero configurato» per un
    /// account **autorizzato e attivo** — una dicitura falsa, che invitava a
    /// configurare qualcosa di già configurato. Il numero mascherato conservato
    /// per l'account sopravvive invece ai riavvii e va usato come ripiego.
    #[test]
    fn the_active_account_label_falls_back_to_the_stored_masked_number() {
        let stored = MaskedPhoneNumber::from_digits("+39 340 1234567");

        // Sessione ripresa: nessun numero in memoria, ma l'account ne ha uno
        // conservato. L'etichetta non deve restare vuota.
        let resumed = active_account_label(None, Some(&stored));
        assert_eq!(resumed.as_str(), stored.as_str());
        assert!(
            !resumed.is_empty(),
            "un account autorizzato non deve risultare senza numero configurato"
        );

        // Sessione in cui il numero è stato inviato ora: la forma resta quella
        // conservata, la stessa dell'elenco degli account (E2E01-20). Prima
        // vinceva la memoria, e lo stesso numero compariva in due forme.
        let fresh = active_account_label(Some("+39 •••• ••67"), Some(&stored));
        assert_eq!(fresh.as_str(), stored.as_str());
        // Finché nulla è conservato, la memoria è l'unica forma che c'è.
        let first = active_account_label(Some("+39 •••• ••67"), None);
        assert_eq!(first.as_str(), "+39 •••• ••67");

        // Account davvero senza numero: l'etichetta resta vuota, e
        // l'interfaccia mostra correttamente «Nessun numero configurato».
        assert!(active_account_label(None, None).is_empty());
    }

    /// Il ripiego non deve allargare ciò che si mostra: il numero mascherato
    /// rivela al più le ultime due cifre, e l'etichetta non aggiunge nulla.
    #[test]
    fn the_fallback_label_never_reveals_more_than_the_masked_number() {
        let stored = MaskedPhoneNumber::from_digits("+39 340 1234567");
        let label = active_account_label(None, Some(&stored));
        assert!(
            !label.as_str().contains("1234567"),
            "l'etichetta non deve contenere il numero in chiaro: {label}"
        );
        assert_eq!(
            label.as_str(),
            stored.as_str(),
            "l'etichetta e' esattamente il numero mascherato, non una sua espansione"
        );
    }

    /// Righe del manifest che dichiarano qualcosa, senza i commenti.
    ///
    /// Un controllo che cercasse il nome nel testo grezzo verrebbe soddisfatto
    /// anche da un commento che *vieta* quella dipendenza, cioè fallirebbe
    /// proprio dove il codice è corretto. È già accaduto scrivendo questo test.
    fn declaring_lines() -> Vec<&'static str> {
        MANIFEST
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    }

    #[test]
    fn the_interface_does_not_depend_on_the_connector_or_the_persistence() {
        // ADR-0010 pone un confine: l'interfaccia passa dai servizi applicativi
        // e non conosce TDLib, la persistenza o i segreti. Un confine dichiarato
        // in un documento e non verificato dura fino alla prima fretta: qui e' il
        // manifest a dirlo.
        for forbidden in ["lisi-telegram", "lisi-storage", "lisi-security"] {
            let declared = declaring_lines()
                .iter()
                .any(|line| line.starts_with(forbidden));
            assert!(
                !declared,
                "l'interfaccia non deve dipendere da {forbidden}: \
                 i tipi necessari vanno riesportati da lisi-services (ADR-0010)"
            );
        }
    }

    #[test]
    fn the_interface_depends_on_the_application_services() {
        let lines = declaring_lines();
        for required in ["lisi-services", "lisi-core"] {
            assert!(
                lines.iter().any(|line| line.starts_with(required)),
                "l'interfaccia deve dipendere da {required}"
            );
        }
    }

    #[test]
    fn a_commented_out_dependency_does_not_satisfy_the_boundary_check() {
        // Verifica del verificatore: il filtro deve scartare i commenti.
        let lines = declaring_lines();
        assert!(!lines.iter().any(|line| line.starts_with('#')));
        assert!(!lines.is_empty());
    }

    /// Ripercorre esattamente il percorso della GUI (M3B.1d): profilo, account,
    /// avvio dell'accesso, numero, codice. Il collaudo manuale aveva trovato la
    /// schermata Account autenticata (`is_authenticated()` vero) ma la
    /// schermata Fonti che si comportava come se non lo fosse: questo test
    /// verifica dallo stesso runtime condiviso ciò che entrambe le schermate
    /// leggono, per accertare se il difetto sta nella sessione condivisa o
    /// altrove (per esempio nel collegamento della schermata Fonti).
    #[test]
    fn after_a_full_mock_login_the_shared_session_reports_authenticated_and_the_runtime_lists_mock_chats()
     {
        use lisi_services::sources::SourceService;

        let (session, _directory) = session_in_own_directory();

        {
            let mut session = session.borrow_mut();
            assert!(
                session.create_account("Redazione test").is_ok(),
                "la creazione dell'account deve riuscire"
            );
            assert!(
                session.start_login().is_ok(),
                "l'avvio dell'accesso deve riuscire"
            );
            assert!(
                session.submit_phone("+390000000000").is_ok(),
                "l'invio del numero fittizio deve riuscire"
            );
            assert!(
                session.submit_code("12345").is_ok(),
                "l'invio del codice fittizio deve riuscire (il Mock accetta qualunque codice valido)"
            );
        }

        assert!(
            session.borrow().is_authenticated(),
            "la sessione deve risultare autenticata dopo il login Mock completo"
        );

        let Ok(sources_database) = lisi_services::Database::open_in_memory() else {
            panic!("l'archivio delle fonti in memoria deve aprirsi");
        };
        let source_service = SourceService::new(sources_database);

        let mut session = session.borrow_mut();
        let Some(runtime) = session.runtime_mut() else {
            panic!("il runtime autorizzato deve esistere dopo il login");
        };
        let Ok(available) = source_service.available_for(runtime) else {
            panic!("le chat accessibili devono essere leggibili dal runtime autorizzato");
        };

        assert!(
            !available.is_empty(),
            "il connettore Mock autorizzato deve mostrare le chat sintetiche, \
             esattamente come dovrebbe fare la schermata Fonti"
        );
    }

    /// Regressione — incidente M3B del 2026-07-26: `main.rs` chiama `pump()`
    /// periodicamente su ogni sessione, che l'operatore abbia gia' selezionato
    /// un account o no. Prima ancora che un account esista non deve fare
    /// nulla di dannoso.
    #[test]
    fn pumping_a_session_without_a_selected_account_does_nothing() {
        let (session, _directory) = session_in_own_directory();

        // Non deve andare in panic ne' richiedere un account selezionato.
        session.borrow_mut().pump();
    }

    /// Crea un account simulato, lo seleziona e ne completa l'accesso.
    fn account_collegato(session: &mut super::AccountSession, nome: &str) -> i64 {
        assert!(session.create_account(nome).is_ok(), "l'account si crea");
        assert!(session.start_login().is_ok());
        assert!(session.submit_phone("+390000000000").is_ok());
        assert!(session.submit_code("12345").is_ok());
        assert!(session.is_authenticated(), "{nome} è collegato");
        let Some(id) = session.selected_account else {
            panic!("l'account creato è selezionato");
        };
        id.get()
    }

    /// **Più account aperti insieme, al più tre: uno tenuto attivo resta
    /// collegato quando se ne seleziona un altro, il quarto non si apre e
    /// nessuno cede il posto** (MULTI-ACCOUNT-02 parte 2, ADR-0173, criterio
    /// 1; prova negativa: il tetto tolto → rossa).
    #[test]
    fn tre_account_aperti_insieme_e_il_quarto_si_rifiuta() {
        let (session, _directory) = session_in_own_directory();
        let mut session = session.borrow_mut();

        let primo = account_collegato(&mut session, "Ufficio A");
        assert!(session.keep_selected_active().is_ok());
        let secondo = account_collegato(&mut session, "Ufficio B");
        assert!(session.keep_selected_active().is_ok());
        let _terzo = account_collegato(&mut session, "Ufficio C");
        assert!(session.keep_selected_active().is_ok());
        assert_eq!(session.runtimes_for_acquisition().len(), 3);

        // Il quarto: non si apre, e i tre restano come sono.
        assert!(session.create_account("Ufficio D").is_ok());
        assert!(session.runtime_mut().is_none(), "il quarto non ha runtime");
        assert!(
            session
                .runtime_error
                .as_deref()
                .is_some_and(|frase| frase.contains("Sono già attivi 3 account")),
            "{:?}",
            session.runtime_error
        );
        assert_eq!(session.runtimes_for_acquisition().len(), 3);

        // Ritornando al primo, l'accesso è com'era: non ricomincia.
        session.select_account(primo);
        assert!(
            session.is_authenticated(),
            "un account tenuto attivo resta collegato"
        );

        // Il secondo lasciato andare si chiude, e libera il posto.
        session.release_active(lisi_core::TelegramAccountId::new(secondo));
        assert_eq!(session.runtimes_for_acquisition().len(), 2);
    }

    /// **Il guasto di un account non interrompe il pompaggio degli altri**
    /// (MULTI-ACCOUNT-02 parte 2, DEC-441). Il giro passa da tutti i runtime e
    /// un errore si registra e si va avanti: un `?`, un `return` o un `break`
    /// nel giro lascerebbero gli account successivi senza aggiornamenti, in
    /// silenzio. Prova negativa: `break` dopo l'errore → rossa.
    #[test]
    fn il_guasto_di_un_account_non_ferma_il_pompaggio_degli_altri() {
        const QUESTO: &str = include_str!("account.rs");
        let Some((produzione, _)) = QUESTO.split_once(
            "#[cfg(test)]
mod tests {",
        ) else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some((_, dopo)) = produzione.split_once("    pub fn pump(&mut self) {") else {
            panic!("`pump` non è dove questa guardia lo cerca");
        };
        let Some((corpo, _)) = dopo.split_once(
            "
    }
",
        ) else {
            panic!("`pump` deve finire");
        };
        assert!(
            corpo.contains("for runtime in &mut self.runtimes {"),
            "il giro passa da tutti i runtime aperti"
        );
        for vietato in ["?", "return", "break", "panic!", "expect("] {
            assert!(
                !corpo.contains(vietato),
                "il giro non si interrompe al primo errore («{vietato}»)"
            );
        }
    }

    /// **Un account non tenuto attivo si chiude quando se ne seleziona un
    /// altro, come prima di MULTI-ACCOUNT-02** (criterio 1): nessun account
    /// resta collegato in silenzio.
    #[test]
    fn senza_tenerlo_attivo_cambiare_account_lo_chiude() {
        let (session, _directory) = session_in_own_directory();
        let mut session = session.borrow_mut();
        let primo = account_collegato(&mut session, "Ufficio A");
        let _secondo = account_collegato(&mut session, "Ufficio B");
        assert_eq!(session.runtimes_for_acquisition().len(), 1);
        session.select_account(primo);
        assert!(
            !session.is_authenticated(),
            "riaperto, l'accesso ricomincia"
        );
    }

    /// **Un monitoraggio nasce legato all'account selezionato e aperto**
    /// (criterio 2).
    #[test]
    fn il_monitoraggio_nasce_con_l_account_selezionato() {
        let (session, _directory) = session_in_own_directory();
        let mut session = session.borrow_mut();
        assert!(session.binding_for_new_monitoring().is_none());
        let _ = account_collegato(&mut session, "Ufficio A");
        let Some(legame) = session.binding_for_new_monitoring() else {
            panic!("con un account aperto il monitoraggio ha un account");
        };
        assert_eq!(legame.label.as_str(), "Ufficio A");
    }

    /// **Nessun codice ruota gli account** (MULTI-ACCOUNT-02 parte 2,
    /// ADR-0173, decisione 4; prova negativa: un ripiego su «un altro
    /// account pronto» in `runtime_mut` → rossa).
    ///
    /// Strutturale, e lo dichiara: un account limitato, scollegato o bloccato
    /// non si simula qui. Si sorveglia che il solo accesso a un account per
    /// interrogare Telegram sia quello **selezionato dall'operatore**, che
    /// l'elenco di tutti gli account lo usi soltanto il ciclo d'acquisizione,
    /// e che il ciclo non interroghi Telegram.
    #[test]
    fn nessun_codice_ruota_gli_account() {
        const QUESTO: &str = include_str!("account.rs");
        const ACQUISIZIONE: &str = include_str!("acquisition.rs");
        let codice = |testo: &str| -> String {
            let produzione = testo
                .split_once("#[cfg(test)]\nmod tests {")
                .map_or(testo, |(prima, _)| prima);
            produzione
                .lines()
                .map(str::trim_start)
                .filter(|riga| !riga.starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let corpo = |testo: &str, firma: &str| -> String {
            let Some((_, dopo)) = testo.split_once(firma) else {
                panic!("«{firma}» non è dove questa guardia lo cerca");
            };
            let Some((corpo, _)) = dopo.split_once("\n}") else {
                panic!("«{firma}» deve finire");
            };
            corpo.to_owned()
        };

        let account = codice(QUESTO);
        // L'account per le richieste a Telegram è quello scelto, e basta.
        let scelto = corpo(&account, "pub fn runtime_mut(&mut self)");
        assert_eq!(
            scelto.trim().trim_end_matches('}').trim(),
            "-> Option<&mut AccountRuntime> {\nselected_in(&mut self.runtimes, self.selected_account)",
            "`runtime_mut` restituisce soltanto l'account selezionato"
        );
        let scelta = corpo(&account, "fn selected_in(");
        for vietato in ["is_ready", "view()", "stage", "dropped", "error"] {
            assert!(
                !scelta.contains(vietato),
                "la scelta del runtime non guarda lo stato dell'account («{vietato}»)"
            );
        }

        // L'elenco di tutti gli account: soltanto i due cicli d'acquisizione,
        // quello della finestra in main.rs e quello del servizio in background
        // (SERVICE-01, ADR-0203), che non stanno mai insieme.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut chiamanti = Vec::new();
        let Ok(voci) = std::fs::read_dir(&src) else {
            panic!("i sorgenti dell'applicazione si leggono");
        };
        for voce in voci.flatten() {
            let Ok(testo) = std::fs::read_to_string(voce.path()) else {
                continue;
            };
            for riga in codice(&testo).lines() {
                if riga.contains(".runtimes_for_acquisition(") {
                    chiamanti.push(format!("{}: {riga}", voce.path().display()));
                }
            }
        }
        assert_eq!(chiamanti.len(), 2, "{chiamanti:#?}");
        for file in ["main.rs", "servizio.rs"] {
            assert_eq!(
                chiamanti.iter().filter(|c| c.contains(file)).count(),
                1,
                "{chiamanti:#?}"
            );
        }

        // E il ciclo ritira eventi: non interroga Telegram, non sceglie.
        let ciclo = codice(ACQUISIZIONE);
        for vietato in [
            "connector_mut",
            "select_account",
            "keep_selected_active",
            "runtime_mut(",
            ".start(",
        ] {
            assert!(
                !ciclo.contains(vietato),
                "il ciclo d'acquisizione non usa «{vietato}»"
            );
        }
    }

    /// Lo stesso pompaggio, ma con un account mock gia' selezionato e
    /// autenticato: deve restare innocuo anche a login completato.
    #[test]
    fn pumping_a_session_with_an_authenticated_mock_account_does_nothing_harmful() {
        let (session, _directory) = session_in_own_directory();

        {
            let mut session = session.borrow_mut();
            // Il mock non legge mai le credenziali del profilo (solo la
            // modalita' Live lo fa): non serve salvarle qui, ed e' anche cio'
            // che evita di scrivere nel file protetto reale usato in
            // parallelo da altri test.
            assert!(session.create_account("Redazione test").is_ok());
            assert!(session.start_login().is_ok());
            assert!(session.submit_phone("+390000000000").is_ok());
            assert!(session.submit_code("12345").is_ok());
        }

        session.borrow_mut().pump();

        assert!(
            session.borrow().is_authenticated(),
            "il pompaggio non deve alterare lo stato di autenticazione gia' raggiunto"
        );
    }

    /// Correttezza di [`sync_model`] nei quattro casi che le importano:
    /// nessun cambiamento, una riga cambiata, una riga aggiunta, una riga
    /// rimossa. **Non** verifica la proprietà "nessun reset completo quando
    /// cambia solo il contenuto" (vedere la documentazione di `sync_model`):
    /// `row_count()`/`row_data()` restituirebbero lo stesso risultato anche
    /// se la funzione chiamasse sempre `set_vec`, perché l'API pubblica di
    /// `slint` non espone un modo per osservare dall'esterno quale notifica
    /// (reset o riga cambiata) sia stata emessa. Quella proprietà è garantita
    /// solo dalla lettura del codice di `sync_model` (guardia sul conteggio
    /// prima del ciclo), non da questo test.
    #[test]
    fn sync_model_keeps_the_rows_consistent_in_all_four_cases() {
        use slint::{Model, SharedString, VecModel};

        use crate::TelegramAccountEntry;

        use super::sync_model;

        fn entry(id: i32, selected: bool) -> TelegramAccountEntry {
            TelegramAccountEntry {
                id,
                label: SharedString::from("Account"),
                selected,
                ..TelegramAccountEntry::default()
            }
        }

        let model = VecModel::from(vec![entry(1, false), entry(2, false)]);

        // Nessun cambiamento reale: il conteggio non deve cambiare.
        sync_model(&model, vec![entry(1, false), entry(2, false)]);
        assert_eq!(model.row_count(), 2);

        // Una sola riga cambia (per esempio: viene selezionata da un clic).
        sync_model(&model, vec![entry(1, true), entry(2, false)]);
        assert_eq!(model.row_data(0), Some(entry(1, true)));
        assert_eq!(model.row_data(1), Some(entry(2, false)));

        // Una riga in più: solo qui il conteggio cambia, ed è accettabile un
        // reset completo.
        sync_model(
            &model,
            vec![entry(1, true), entry(2, false), entry(3, false)],
        );
        assert_eq!(model.row_count(), 3);

        // Una riga in meno.
        sync_model(&model, vec![entry(1, true)]);
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.row_data(0), Some(entry(1, true)));
    }

    /// Regressione — stesso incidente: selezionare un account **già
    /// esistente** (non appena creato, che si autoseleziona da solo) deve
    /// aggiornare `selected_account` esattamente come fa il clic sulla riga
    /// nell'interfaccia (`on_select_account` in [`wire`] chiama proprio
    /// questo metodo).
    #[test]
    fn selecting_an_already_existing_account_updates_the_selection() {
        let (session, _directory) = session_in_own_directory();
        let mut session = session.borrow_mut();

        assert!(session.create_account("Account uno").is_ok());
        let Ok(accounts) = session.accounts.accounts() else {
            panic!("gli account devono essere leggibili");
        };
        let Some(first_account) = accounts
            .iter()
            .find(|account| account.label.as_str() == "Account uno")
        else {
            panic!("il primo account deve esistere");
        };
        let first_account_id = first_account.id;

        assert!(session.create_account("Account due").is_ok());
        assert_ne!(session.selected_account, Some(first_account_id));

        session.select_account(first_account_id.get());
        assert_eq!(
            session.selected_account,
            Some(first_account_id),
            "selezionare un account già salvato deve aggiornare la selezione, \
             esattamente come il clic sulla riga (on_select_account)"
        );
    }

    /// **I nuovi account usano il profilo dell'applicazione** (ADR-0204): uno
    /// solo, creato dal programma, senza che nessuno lo scelga.
    #[test]
    fn i_nuovi_account_usano_il_profilo_dell_applicazione() {
        let (session, _directory) = session_in_own_directory();
        let mut session = session.borrow_mut();
        assert!(session.create_account("Redazione").is_ok());
        assert!(session.create_account("Turno di notte").is_ok());
        let (Ok(accounts), Ok(profiles)) =
            (session.accounts.accounts(), session.accounts.api_profiles())
        else {
            panic!("account e profili devono essere leggibili");
        };
        assert_eq!(accounts.len(), 2);
        assert_eq!(
            profiles.len(),
            1,
            "un profilo solo, quello dell'applicazione"
        );
        assert!(
            accounts
                .iter()
                .all(|account| account.profile_id == profiles[0].id)
        );
        assert_eq!(
            profiles[0].label.as_str(),
            lisi_services::accounts::APPLICATION_PROFILE_LABEL
        );
    }

    /// **Nessuna superficie per le credenziali dell'applicazione** (ADR-0204
    /// decisione 4): né campi, né comandi, né rimandi al sito di Telegram per
    /// gli sviluppatori, in nessuna modalità.
    #[test]
    fn la_schermata_non_mostra_ne_chiede_le_credenziali_dell_applicazione() {
        const UI: &str = include_str!("../ui/app-window.slint");
        for vietato in [
            "api-id-input",
            "api-hash-input",
            "save-credentials",
            "create-profile",
            "select-profile",
            "api-profiles",
            "ApiProfileEntry",
            "@tr(\"API ID\")",
            "@tr(\"API hash\")",
            "my.telegram.org",
            "profilo delle credenziali",
            "profilo di credenziali",
        ] {
            assert!(
                !UI.contains(vietato),
                "la schermata contiene ancora «{vietato}»"
            );
        }
        assert!(
            crate::surface_text::assegna(
                UI,
                "text",
                "Questa installazione di NEXUM/97 non è configurata per collegarsi a Telegram. Rivolgersi all'amministratore. L'esercitazione funziona comunque."
            ),
            "senza configurazione la schermata rimanda all'amministratore"
        );
    }

    /// **D-18: un messaggio di recupero nomina solo comandi che esistono.**
    ///
    /// Fino al 2026-10-02 due messaggi dicevano di usare «Ripristina accesso»,
    /// che l'interfaccia non ha. La guardia prende ogni etichetta fra «» dei
    /// messaggi di recupero e la cerca **nella schermata Account**, dove il
    /// messaggio manda l'operatore; e cerca le schermate nominate fra le voci
    /// del menu. Un comando rinominato, o inventato, la fa diventare rossa.
    #[test]
    fn i_messaggi_di_recupero_nominano_solo_comandi_che_esistono() {
        const UI: &str = include_str!("../ui/app-window.slint");
        let messaggi = [
            lisi_services::error::SESSION_UNAVAILABLE_MESSAGE,
            lisi_services::session::CORRUPTED_SESSION_MESSAGE,
        ];
        // Le etichette dello .slint scrivono i puntini come sequenza: si
        // confronta ciò che l'operatore legge.
        let account = crate::page_guard::corpo_della_pagina(2).replace("\\u{2026}", "…");

        let mut nominati = 0;
        for messaggio in messaggi {
            for pezzo in messaggio.split('«').skip(1) {
                let Some((etichetta, _)) = pezzo.split_once('»') else {
                    panic!("una virgoletta aperta non si chiude: «{messaggio}»");
                };
                nominati += 1;
                assert!(
                    account.contains(&format!("\"{etichetta}\"")),
                    "il messaggio nomina «{etichetta}», che la schermata Account non ha"
                );
            }
            for schermata in ["Account", "Diagnostica"] {
                if messaggio.contains(&format!(" {schermata} ")) {
                    assert!(
                        crate::surface_text::assegna(UI, "label", schermata),
                        "il messaggio nomina la schermata «{schermata}», che il menu non ha"
                    );
                }
            }
            // NESSUN GIRO A VUOTO: il percorso non rimanda a ciò che ha
            // appena fallito, né al comando che non esisteva.
            for vietato in ["Ripristina accesso", "Annulla e ricomincia"] {
                assert!(
                    !messaggio.contains(vietato),
                    "il messaggio rimanda a «{vietato}»: «{messaggio}»"
                );
            }
        }
        assert!(nominati >= 3, "la guardia non ha letto alcuna etichetta");
    }
}

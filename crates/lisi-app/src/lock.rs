//! Collegamento fra la schermata di blocco e il servizio del blocco.
//!
//! # Che cosa il blocco fa, e che cosa non fa
//!
//! Nasconde i **dati dell'account**. Non ferma il monitoraggio, e non chiude
//! l'applicazione: fermarlo trasformerebbe una pausa in un buco nell'archivio,
//! che è l'opposto di ciò che l'ufficio ha chiesto.
//!
//! Mentre è bloccata, la schermata dice **il fatto** — un monitoraggio è in
//! corso, quanti avvisi attendono — e non il contenuto. Su un computer condiviso
//! mostrare fonte e motivazione esporrebbe materiale acquisito a chi passa; non
//! mostrare nulla toglierebbe a chi rientra il modo di capire a colpo d'occhio
//! se è successo qualcosa.
//!
//! # Lo stato del blocco non è conservato
//!
//! Vive in memoria e muore con il processo. Riavviando, la postazione **non** è
//! bloccata: sarebbe una serratura che non protegge nulla — chi riavvia il
//! programma la aprirebbe — e in cambio chiuderebbe fuori chi ha dimenticato la
//! parola. La protezione che regge fra un avvio e l'altro è quella di Windows,
//! e questo prodotto non finge di sostituirla (si veda `lisi_services::lock`).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Instant;

use lisi_core::text::Actor;
use lisi_services::lock::{self, LockService};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;
use crate::settings::SharedSettings;

/// Stato del blocco, condiviso fra i gestori.
pub struct LockState {
    /// Servizio che conserva le parole di ogni account.
    ///
    /// Il file protetto sta dentro il servizio e non qui: l'interfaccia non
    /// deve dipendere da lisi-security (ADR-0010).
    service: LockService,
    /// UUID dell'account attivo, quando ce n'è uno.
    ///
    /// Senza account attivo non c'è nulla da bloccare: il blocco protegge i dati
    /// di un account, e un account che non c'è non ha dati da nascondere.
    account_uuid: Option<String>,
    /// Se la postazione è bloccata **adesso**.
    locked: bool,
    /// Quando qualcuno ha usato l'applicazione per l'ultima volta.
    ///
    /// È un `Instant` e non un `Timestamp`: serve a misurare un intervallo, e
    /// l'orologio a muro può essere spostato — all'indietro da un cambio d'ora,
    /// in avanti da una sincronizzazione — mentre `Instant` è monotono. Un
    /// blocco automatico che sbagliasse per un cambio d'ora scatterebbe con
    /// un'ora di ritardo il giorno in cui serve.
    last_activity: Instant,
    /// Ultimo valore dei minuti **scritto nell'interfaccia**.
    ///
    /// # Perché non basta rileggerlo dal servizio
    ///
    /// `refresh` gira a ogni giro della pompa, e finché scriveva i minuti a
    /// ogni giro **il campo non si poteva cambiare**: qualunque cifra digitata,
    /// e qualunque pressione di «−» o «+», veniva riscritta con il valore
    /// salvato prima che l'occhio se ne accorgesse. Il campo sembrava rotto, e
    /// il comando «Applica» salvava il numero che c'era già.
    ///
    /// Lo ha trovato il pilot alla voce L8, provando due strade indipendenti —
    /// la tastiera e i due comandi — e vedendole fallire entrambe allo stesso
    /// modo. Nessun test lo vedeva: ognuna delle due parti, da sola, e'
    /// corretta.
    ///
    /// Con questo valore l'interfaccia si aggiorna **solo quando cambia il
    /// valore salvato** - all'avvio, dopo un salvataggio, al cambio di account
    /// - e non quando lo tocca chi sta scrivendo.
    pushed_minutes: Option<u32>,
    /// Tentativi di sblocco sbagliati di fila (OPERATOR-E2E-REMEDIATION-01,
    /// F-01).
    failed_attempts: u32,
    /// Prima di quando non si accetta un altro tentativo.
    ///
    /// La parola minima è di quattro caratteri e la verifica è rapida: senza
    /// un'attesa crescente, chi passa davanti potrebbe provarne molte in poco
    /// tempo. Non è una serratura contro chi controlla la macchina — quella è
    /// il blocco di Windows — ma rende lento indovinare.
    retry_after: Option<Instant>,
}

/// Quanto attendere dopo `failures` tentativi sbagliati di fila.
///
/// I primi tre sono liberi: chi sbaglia una lettera non deve aspettare. Poi
/// dieci secondi, raddoppiati a ogni errore, fino a cinque minuti.
fn backoff_after(failures: u32) -> Option<std::time::Duration> {
    const LIBERI: u32 = 3;
    const PRIMA_ATTESA_S: u64 = 10;
    const MASSIMO_S: u64 = 300;
    if failures < LIBERI {
        return None;
    }
    let esponente = (failures - LIBERI).min(10);
    let secondi = PRIMA_ATTESA_S
        .saturating_mul(1_u64 << esponente)
        .min(MASSIMO_S);
    Some(std::time::Duration::from_secs(secondi))
}

/// Stato condiviso fra i gestori dell'interfaccia.
pub type SharedLock = Rc<RefCell<LockState>>;

thread_local! {
    /// Se la postazione è bloccata, leggibile da qualunque gestore senza che
    /// gli si passi lo stato (OPERATOR-E2E-REMEDIATION-01, F-01).
    ///
    /// # Perché una copia, e perché non diverge
    ///
    /// I gestori dei comandi che cambiano o cancellano stanno in trenta
    /// moduli, e passare a ognuno lo stato del blocco avrebbe toccato ogni
    /// costruzione per una domanda di un bit. Questo valore lo scrive **solo**
    /// [`LockState::set_locked`], che è anche l'unico punto che scrive
    /// `locked`: le due cose cambiano insieme o non cambiano.
    ///
    /// È la terza barriera, dopo il contenuto nascosto e i comandi condivisi
    /// che non rispondono: se un giorno un comando nuovo sfuggisse alle prime
    /// due, quelli che cambiano o cancellano qualcosa rifiutano comunque.
    ///
    /// Vive nel filo dell'interfaccia, che è l'unico da cui i comandi partono:
    /// un valore di processo si farebbe vedere anche alle prove che girano in
    /// parallelo, e una che blocca ne spegnerebbe un'altra.
    static ENGAGED: Cell<bool> = const { Cell::new(false) };
}

/// Se la postazione è bloccata adesso.
#[must_use]
pub fn station_is_locked() -> bool {
    ENGAGED.with(Cell::get)
}

/// Rifiuta un comando arrivato a postazione bloccata, e lo scrive nel registro.
///
/// Restituisce `true` quando il comando **non** va eseguito. Il nome del
/// comando entra nel registro applicativo, mai i suoi argomenti: un tentativo
/// alla cieca su una postazione bloccata è un fatto da sapere, e il contenuto
/// che il comando avrebbe toccato non lo è.
pub fn refuse_while_locked(command: &'static str) -> bool {
    if !station_is_locked() {
        return false;
    }
    tracing::warn!(
        comando = command,
        "comando rifiutato: la postazione è bloccata"
    );
    true
}

/// Crea lo stato del blocco sul file protetto predefinito.
#[must_use]
pub fn create_state() -> Option<SharedLock> {
    let service = LockService::open_default()
        .map_err(|error| {
            tracing::warn!(
                kind = error.kind(),
                "blocco non disponibile in questa esecuzione"
            );
        })
        .ok()?;

    Some(Rc::new(RefCell::new(LockState {
        service,
        account_uuid: None,
        locked: false,
        last_activity: Instant::now(),
        pushed_minutes: None,
        failed_attempts: 0,
        retry_after: None,
    })))
}

/// La parola delle prove che bloccano davvero la finestra.
#[cfg(test)]
const TEST_WORD: &str = "parola-di-prova";

/// Uno stato del blocco su un file temporaneo, con un account protetto: serve
/// alle prove che devono passare da `engage` e `release` invece di impostare la
/// proprietà a mano.
#[cfg(test)]
pub(crate) fn state_for_tests(path: &std::path::Path) -> SharedLock {
    const ACCOUNT: &str = "33333333333333333333333333333333";
    let service = LockService::at(path.to_path_buf());
    let Ok(()) = service.protect(ACCOUNT, TEST_WORD) else {
        panic!("la protezione di prova deve potersi fissare");
    };
    Rc::new(RefCell::new(LockState {
        service,
        account_uuid: Some(String::from(ACCOUNT)),
        locked: false,
        last_activity: Instant::now(),
        pushed_minutes: None,
        failed_attempts: 0,
        retry_after: None,
    }))
}

/// Sblocca con la parola giusta, come farebbe chi la conosce.
#[cfg(test)]
pub(crate) fn release_for_tests(window: &AppWindow, state: &SharedLock) {
    window.set_lock_attempt(crate::lingua::schermo(TEST_WORD));
    release(window, state);
}

impl LockState {
    /// Se la postazione è bloccata adesso.
    ///
    /// La schermata lo legge dalla propria proprietà, che `refresh` tiene
    /// allineata; **il vassoio no**, perché non ha una proprietà in cui
    /// guardare, e perché ciò che mostra è visto da chi passa davanti a una
    /// postazione bloccata (ADR-0063).
    pub const fn is_locked(&self) -> bool {
        self.locked
    }

    /// Se c'è un account attivo da proteggere.
    ///
    /// Serve al vassoio per dire **perché** non si può bloccare, invece di
    /// offrire una voce che non fa nulla.
    pub const fn has_account(&self) -> bool {
        self.account_uuid.is_some()
    }

    /// Se l'account attivo ha una parola di sblocco fissata.
    ///
    /// Stessa lettura che decide se il comando «Blocca» compare nella
    /// schermata: **una sola**, perché due letture divergono.
    pub fn has_unlock_word(&self) -> bool {
        self.protected()
    }

    /// Blocca o sblocca, tenendo allineato il valore che leggono i gestori.
    ///
    /// È l'unico punto che scrive `locked`: [`station_is_locked`] lo legge
    /// dalla copia che si scrive qui, e due scritture separate sarebbero due
    /// valori che prima o poi dicono cose diverse.
    fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
        ENGAGED.with(|engaged| engaged.set(locked));
    }

    /// Registra quale account è attivo.
    ///
    /// # A postazione bloccata l'account non cambia (OPERATOR-E2E-REMEDIATION-01, F-01)
    ///
    /// Fino a questa correzione cambiare account **sbloccava**, con questa
    /// ragione: cambiarlo richiede di passare da schermate che il blocco copre.
    /// Era vero solo finché il blocco teneva — e non teneva: il Tab ci
    /// passava. E restava una seconda porta, peggiore: questa funzione la
    /// chiama il ciclo periodico ogni duecento millisecondi, e l'account attivo
    /// risulta **assente** anche quando la sua riga non si riesce a leggere, per
    /// esempio con l'archivio occupato un istante da una copia di sicurezza.
    /// Un errore di lettura apriva la postazione.
    ///
    /// Ora, a postazione bloccata, l'account a cui il blocco appartiene resta
    /// quello: la parola che sblocca è la sua. Il cambio, se c'è stato davvero,
    /// si raccoglie al primo giro dopo lo sblocco.
    pub fn set_account(&mut self, uuid: Option<String>) {
        if self.locked {
            return;
        }
        self.account_uuid = uuid;
    }

    /// Segna che qualcuno sta usando l'applicazione.
    ///
    /// **Non** rimanda il blocco se la postazione è già bloccata: i comandi
    /// della schermata di blocco emettono anch'essi il segnale, e conteggiarli
    /// significherebbe che chi tenta parole a caso tiene viva la sessione.
    pub fn note_activity(&mut self) {
        if !self.locked {
            self.last_activity = Instant::now();
        }
    }

    /// Se è ora di bloccare da soli.
    ///
    /// Vero solo quando la postazione è **protetta e sbloccata** e il tempo è
    /// passato: senza protezione non c'è nulla da bloccare, e bloccare
    /// comunque chiuderebbe fuori chi non ha una parola da digitare.
    fn should_engage(&self, minutes: u32, at: Instant) -> bool {
        if self.locked || !self.protected() {
            return false;
        }
        let elapsed = at.saturating_duration_since(self.last_activity);
        elapsed.as_secs() >= u64::from(minutes).saturating_mul(60)
    }

    /// Se l'account attivo ha una parola di sblocco.
    fn protected(&self) -> bool {
        let Some(uuid) = self.account_uuid.as_deref() else {
            return false;
        };
        self.service.is_protected(uuid).unwrap_or_else(|error| {
            tracing::warn!(kind = error.kind(), "stato della protezione non leggibile");
            // Non leggibile non è «protetto»: dirlo protetto mostrerebbe il
            // comando «Blocca» a chi poi non potrebbe sbloccare, perché la
            // verifica fallirebbe per la stessa ragione della lettura.
            false
        })
    }
}

/// Istante corrente, dall'ancora dell'avvio se l'orologio non è leggibile.
fn now() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Attore dell'audit.
fn actor() -> Option<Actor> {
    crate::operator::audit_actor().ok()
}

/// Riporta nell'interfaccia lo stato del blocco.
pub fn refresh(window: &AppWindow, shared: &SharedLock) {
    let (protected, locked, minutes, pushed, has_account) = {
        let state = shared.borrow();
        let minutes = state.service.auto_lock_minutes().unwrap_or_else(|error| {
            tracing::warn!(kind = error.kind(), "minuti del blocco non leggibili");
            lock::DEFAULT_AUTO_LOCK_MINUTES
        });
        (
            state.protected(),
            state.locked,
            minutes,
            state.pushed_minutes,
            state.account_uuid.is_some(),
        )
    };
    // SENZA ACCOUNT ATTIVO SI DICE (CAPABILITY-AUDIT-02, CA02-07): la frase
    // diceva «l'account attivo non ha una parola di sblocco» anche quando un
    // account attivo non c'era.
    window.set_lock_has_account(has_account);

    window.set_station_locked(locked);
    // LA SCHERMATA DI BLOCCO DICE QUALE ACCOUNT (FINAL-REVIEW-01, FR-052): la
    // proprietà esisteva e nessuno la impostava. È lo stesso numero mascherato
    // che la schermata Account mostra già, non una cifra in più.
    window.set_lock_account_label(window.get_auth_account_label());
    window.set_lock_protected(protected);
    // Il comando «Blocca» compare solo se si potrà sbloccare: un pulsante che
    // chiude fuori chi lo preme è peggio di un pulsante che manca.
    window.set_lock_available(protected);

    // Il campo si riscrive **solo se e' cambiato il valore salvato**. Scriverlo
    // a ogni giro lo rendeva immodificabile: vedi `pushed_minutes`.
    if should_push_minutes(minutes, pushed) {
        window.set_lock_minutes(i32::try_from(minutes).unwrap_or(10));
        shared.borrow_mut().pushed_minutes = Some(minutes);
    }
}

/// Se il valore salvato va riportato nel campo.
///
/// Funzione pura, e sta qui perche' e' l'intera decisione: riscrivere un campo
/// che qualcuno sta modificando e' il difetto L8, e riconoscerlo non richiede
/// una finestra.
const fn should_push_minutes(stored: u32, pushed: Option<u32>) -> bool {
    match pushed {
        None => true,
        Some(last) => last != stored,
    }
}

/// Compone **il fatto** mostrato a schermo bloccato.
///
/// Legge ciò che le altre schermate hanno già scritto nella finestra invece di
/// interrogare i servizi: la frase deve dire ciò che l'operatore vedrebbe se
/// fosse davanti allo schermo, e ricalcolarla da un'altra fonte la farebbe
/// divergere da quella.
///
/// Il contenuto non entra mai: né fonte, né motivazione, né estratto. Solo che
/// qualcosa è successo, e quanto.
pub fn refresh_fact(window: &AppWindow) {
    // LA FRASE LA COMPONE UN POSTO SOLO.
    //
    // La stessa frase la mostra anche il vassoio, e due composizioni sono due
    // frasi che divergono alla prima modifica: la seconda a divergere sarebbe
    // quella che nessuno guarda (ADR-0063).
    let fatto = lisi_services::tray::station_fact(
        &window.get_monitoring_state(),
        u32::try_from(window.get_alert_pending()).unwrap_or(0),
    );
    window.set_lock_fact(SharedString::from(fatto));
}

/// Blocca da sé se l'inattività ha superato i minuti impostati.
///
/// Chiamata dal ciclo periodico. È qui e non in un timer proprio perché un
/// secondo timer avrebbe una propria cadenza da tenere allineata a questa, e
/// due cadenze che devono restare d'accordo prima o poi non lo sono.
pub fn engage_if_idle(window: &AppWindow, state: &SharedLock) {
    let minutes = {
        let state = state.borrow();
        state.service.auto_lock_minutes().unwrap_or_else(|error| {
            tracing::warn!(kind = error.kind(), "minuti del blocco non leggibili");
            lock::DEFAULT_AUTO_LOCK_MINUTES
        })
    };

    let due = state.borrow().should_engage(minutes, Instant::now());
    if due {
        tracing::info!(minuti = minutes, "postazione bloccata per inattivita'");
        engage(window, state);
    }
}

/// Blocca la postazione.
pub(crate) fn engage(window: &AppWindow, state: &SharedLock) {
    {
        let mut state = state.borrow_mut();
        if !state.protected() {
            return;
        }
        state.set_locked(true);
    }

    // La domanda prima di chiudere non sopravvive al blocco: aveva «Chiudi
    // comunque», e chi passa davanti non deve trovarsela pronta (F-01).
    window.set_close_question_open(false);

    refresh_fact(window);

    // Il campo si svuota **entrando**, non uscendo: un tentativo rimasto scritto
    // sarebbe visibile a chi si siede dopo, che è precisamente chi il blocco
    // tiene fuori.
    window.set_lock_attempt(SharedString::default());
    window.set_lock_message(SharedString::default());
    refresh(window, state);
}

/// Verifica il tentativo e, se corrisponde, sblocca.
fn release(window: &AppWindow, state: &SharedLock) {
    let attempt = window.get_lock_attempt().to_string();
    // Il campo si svuota sempre, anche quando il tentativo non si esamina:
    // lasciare la parola scritta invita a ritentare la stessa.
    window.set_lock_attempt(SharedString::default());

    // TROPPI TENTATIVI SBAGLIATI DI FILA: SI ASPETTA (F-01).
    let ora = Instant::now();
    if let Some(quando) = state.borrow().retry_after
        && quando > ora
    {
        let secondi = quando.saturating_duration_since(ora).as_secs().max(1);
        window.set_lock_message(crate::lingua::schermo(format!(
            "Troppi tentativi sbagliati di fila: il prossimo si accetta fra {secondi} {}.",
            if secondi == 1 { "secondo" } else { "secondi" }
        )));
        return;
    }

    // Un campo vuoto non è un tentativo: non si conta e lo si dice (F-11).
    // Contarlo farebbe aspettare chi ha premuto Invio per sbaglio, e tacere
    // lascerebbe chi guarda la schermata senza sapere che cosa manca.
    if attempt.trim().is_empty() {
        window.set_lock_message(crate::lingua::schermo(
            "Scrivere la parola di sblocco, poi premere «Sblocca».",
        ));
        return;
    }

    let outcome = {
        let state = state.borrow();
        let Some(uuid) = state.account_uuid.as_deref() else {
            // Senza account attivo non c'è nulla da verificare. Non può accadere
            // — senza account non si blocca — ma restare bloccati per sempre
            // sarebbe il modo peggiore di scoprirlo.
            return;
        };
        state.service.unlock(uuid, &attempt)
    };

    match outcome {
        Ok(()) => {
            {
                let mut state = state.borrow_mut();
                state.set_locked(false);
                state.failed_attempts = 0;
                state.retry_after = None;
            }
            window.set_lock_message(SharedString::default());
            refresh(window, state);
        }
        Err(error) => {
            let attesa = {
                let mut state = state.borrow_mut();
                state.failed_attempts = state.failed_attempts.saturating_add(1);
                let attesa = backoff_after(state.failed_attempts);
                state.retry_after = attesa.map(|durata| ora + durata);
                attesa
            };
            let mut frase = error.operator_message();
            if let Some(durata) = attesa {
                frase.push_str(&format!(
                    " Dopo troppi tentativi sbagliati di fila il prossimo si accetta fra {} \
                     secondi.",
                    durata.as_secs()
                ));
            }
            tracing::warn!("tentativo di sblocco non riuscito");
            window.set_lock_message(crate::lingua::schermo(frase));
        }
    }
}

/// Fissa o sostituisce la parola dell'account attivo.
fn protect(
    window: &AppWindow,
    state: &SharedLock,
    settings: Option<&SharedSettings>,
) -> Result<String, String> {
    // Senza archivio la parola non si cambia: l'audit del cambio passa di li',
    // e una protezione cambiata senza traccia e' peggio di una non cambiata.
    let Some(settings) = settings else {
        window.set_lock_new_word(SharedString::default());
        return Err(String::from(SENZA_ARCHIVIO));
    };
    let word = window.get_lock_new_word().to_string();

    let outcome = {
        let state = state.borrow();
        let Some(uuid) = state.account_uuid.as_deref() else {
            return Err(String::from(
                "Nessun account attivo: la parola di sblocco appartiene a un account, \
                 e senza account non c'è nulla da proteggere.",
            ));
        };
        state.service.protect(uuid, &word)
    };

    // Il campo si svuota comunque: una parola lasciata scritta in chiaro nella
    // schermata è esattamente ciò che il file protetto evita.
    window.set_lock_new_word(SharedString::default());

    match outcome {
        Ok(()) => {
            audit(settings, state, true);
            Ok(String::from(
                "Parola di sblocco impostata per l'account attivo.",
            ))
        }
        Err(error) => Err(error.operator_message()),
    }
}

/// Toglie la protezione dell'account attivo.
fn unprotect(state: &SharedLock, settings: Option<&SharedSettings>) -> Result<String, String> {
    let Some(settings) = settings else {
        return Err(String::from(SENZA_ARCHIVIO));
    };
    let outcome = {
        let state = state.borrow();
        let Some(uuid) = state.account_uuid.as_deref() else {
            return Err(String::from("Nessun account attivo."));
        };
        state.service.unprotect(uuid)
    };

    match outcome {
        Ok(()) => {
            audit(settings, state, false);
            Ok(String::from(
                "Protezione tolta: l'account attivo non ha più una parola di sblocco, \
                 e la postazione non si può bloccare finché non se ne imposta un'altra.",
            ))
        }
        Err(error) => Err(error.operator_message()),
    }
}

/// Applica i minuti scelti, riportando quelli effettivamente conservati.
fn save_minutes(window: &AppWindow, state: &SharedLock) -> Result<String, String> {
    let wanted =
        u32::try_from(window.get_lock_minutes()).unwrap_or(lock::DEFAULT_AUTO_LOCK_MINUTES);

    let outcome = {
        let state = state.borrow();
        state.service.set_auto_lock_minutes(wanted)
    };

    match outcome {
        Ok(saved) => {
            // Si rimostra ciò che è stato davvero conservato: se il valore era
            // fuori scala, l'operatore vede quello ricondotto invece di credere
            // che valga quello che aveva scritto.
            window.set_lock_minutes(i32::try_from(saved).unwrap_or(10));
            // E si registra che quello e' il valore ora mostrato, altrimenti il
            // primo giro della pompa lo riscriverebbe credendolo diverso.
            state.borrow_mut().pushed_minutes = Some(saved);
            Ok(format!(
                "Blocco automatico dopo {saved} minuti di inattività."
            ))
        }
        Err(error) => Err(error.operator_message()),
    }
}

/// Registra nell'audit un cambiamento della protezione.
///
/// Che un account acquisti o perda la propria parola è un fatto della
/// postazione: il file protetto conserva *lo stato*, l'audit conserva *chi e
/// quando*. Un audit non riuscito **non annulla** il cambiamento, che è già
/// avvenuto nel file: si segnala e si prosegue, invece di riferire un guasto
/// per qualcosa che ha funzionato.
fn audit(settings: &SharedSettings, state: &SharedLock, protected: bool) {
    let Some(uuid) = state.borrow().account_uuid.clone() else {
        return;
    };
    let Some(actor) = actor() else {
        tracing::error!("nome dell'attore di audit non valido");
        return;
    };

    if let Err(error) = settings.record_lock_change(&uuid, protected, &actor, now()) {
        tracing::warn!(
            kind = error.kind(),
            "cambio della protezione non registrato in audit"
        );
    }
}

/// Mostra l'esito di un comando delle impostazioni del blocco, in ambra se è
/// un rifiuto (F-11).
fn show_settings_outcome(window: &AppWindow, outcome: Result<String, String>) {
    let (message, failed) = match outcome {
        Ok(message) => (message, false),
        Err(message) => (message, true),
    };
    window.set_lock_settings_message(crate::lingua::schermo(message));
    window.set_lock_settings_failed(failed);
}

/// Frase per chi cambia la parola quando l'archivio non c'è.
const SENZA_ARCHIVIO: &str = "L'archivio non è disponibile: la parola di sblocco non si cambia senza \
     lasciarne traccia nel registro delle operazioni. Sbloccare e bloccare restano possibili.";

/// Collega i comandi del blocco.
///
/// # Si collega anche senza archivio (OPERATOR-E2E-REMEDIATION-01, F-01)
///
/// Lo stato del blocco nasce sempre, e il ciclo periodico lo fa scattare. Finche'
/// il collegamento dipendeva dal servizio delle impostazioni, senza archivio la
/// postazione si bloccava da sola e «Sblocca» non faceva nulla: restava solo
/// Gestione attivita'. Ora sblocco, blocco e segnale di attivita' si collegano
/// sempre; senza archivio non si cambia soltanto la parola, perche' il cambio va
/// registrato.
pub fn wire(window: &AppWindow, state: &SharedLock, settings: Option<&SharedSettings>) {
    {
        // Il segnale di attività arriva da un `global` dei token, che ogni
        // comando emette: legarlo qui invece che a ogni schermata significa che
        // un comando nuovo lo emette senza che nessuno debba ricordarsene.
        let state = Rc::clone(state);
        window
            .global::<crate::Activity>()
            .on_touched(move || state.borrow_mut().note_activity());
    }

    {
        let handle = window.as_weak();
        let state = Rc::clone(state);
        window.on_lock_station(move || {
            if let Some(window) = handle.upgrade() {
                engage(&window, &state);
            }
        });
    }

    {
        let handle = window.as_weak();
        let state = Rc::clone(state);
        window.on_unlock_station(move || {
            if let Some(window) = handle.upgrade() {
                release(&window, &state);
            }
        });
    }

    {
        let handle = window.as_weak();
        let state = Rc::clone(state);
        let settings = settings.map(Rc::clone);
        window.on_protect_account(move || {
            if crate::lock::refuse_while_locked("protect_account") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            show_settings_outcome(&window, protect(&window, &state, settings.as_ref()));
            refresh(&window, &state);
        });
    }

    {
        let handle = window.as_weak();
        let state = Rc::clone(state);
        let settings = settings.map(Rc::clone);
        window.on_unprotect_account(move || {
            if crate::lock::refuse_while_locked("unprotect_account") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            show_settings_outcome(&window, unprotect(&state, settings.as_ref()));
            refresh(&window, &state);
        });
    }

    {
        let handle = window.as_weak();
        let state = Rc::clone(state);
        window.on_save_lock_minutes(move || {
            if crate::lock::refuse_while_locked("save_lock_minutes") {
                return;
            }
            let Some(window) = handle.upgrade() else {
                return;
            };
            show_settings_outcome(&window, save_minutes(&window, &state));
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use lisi_services::lock::LockService;

    use super::{LockState, should_push_minutes};

    const FIRST: &str = "11111111111111111111111111111111";
    const SECOND: &str = "22222222222222222222222222222222";

    fn state() -> (LockState, tempfile::TempDir) {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let service = LockService::at(directory.path().join("blocco.protetto"));
        (
            LockState {
                service,
                account_uuid: Some(String::from(FIRST)),
                locked: false,
                last_activity: Instant::now(),
                pushed_minutes: None,
                failed_attempts: 0,
                retry_after: None,
            },
            directory,
        )
    }

    /// **A postazione bloccata un cambio d'account non apre il blocco**
    /// (OPERATOR-E2E-REMEDIATION-01, F-01).
    ///
    /// Questa prova diceva il contrario — `changing_account_releases_the_lock`
    /// — e la ragione era che cambiare account richiede schermate che il blocco
    /// copre. Il blocco non le copriva dalla tastiera, e il cambio d'account era
    /// diventato una seconda porta. La prova è stata rovesciata perché
    /// codificava il difetto, non perché desse fastidio.
    #[test]
    fn changing_account_does_not_release_the_lock() {
        let (mut state, _guard) = state();
        state.set_locked(true);

        state.set_account(Some(String::from(SECOND)));
        assert!(state.is_locked(), "un altro account non apre il blocco");
        assert_eq!(
            state.account_uuid.as_deref(),
            Some(FIRST),
            "la parola che sblocca resta quella dell'account bloccato"
        );
        state.set_locked(false);
    }

    /// **Un account che non si riesce a leggere non apre il blocco.**
    ///
    /// Il ciclo periodico passa `None` quando la riga dell'account attivo non
    /// è leggibile — l'archivio occupato un istante basta. Prima di F-01 quel
    /// `None` era un cambio d'account, e sbloccava.
    #[test]
    fn an_unreadable_account_does_not_release_the_lock() {
        let (mut state, _guard) = state();
        state.set_locked(true);

        state.set_account(None);
        assert!(state.is_locked(), "un errore di lettura non apre il blocco");
        assert!(super::station_is_locked(), "e i gestori lo vedono bloccato");
        state.set_locked(false);
        assert!(!super::station_is_locked());
    }

    #[test]
    fn staying_on_the_same_account_keeps_the_lock() {
        // Un aggiornamento periodico che rileggesse lo stesso account non deve
        // sbloccare la postazione, che e' il modo in cui un blocco si apre da
        // solo dopo pochi secondi.
        let (mut state, _guard) = state();
        state.set_locked(true);

        state.set_account(Some(String::from(FIRST)));
        assert!(state.is_locked(), "lo stesso account non deve sbloccare");
        state.set_locked(false);
    }

    /// **Sbloccata, la postazione riprende l'account che c'è adesso.**
    #[test]
    fn after_unlocking_the_current_account_is_taken() {
        let (mut state, _guard) = state();
        state.set_account(Some(String::from(SECOND)));
        assert_eq!(state.account_uuid.as_deref(), Some(SECOND));
    }

    /// **I primi tre errori sono liberi, poi l'attesa cresce fino a cinque
    /// minuti** (F-01).
    #[test]
    fn wrong_words_slow_down_the_next_attempt() {
        use super::backoff_after;
        assert_eq!(backoff_after(0), None);
        assert_eq!(
            backoff_after(2),
            None,
            "chi sbaglia una lettera non aspetta"
        );
        assert_eq!(backoff_after(3), Some(Duration::from_secs(10)));
        assert_eq!(backoff_after(4), Some(Duration::from_secs(20)));
        assert_eq!(backoff_after(8), Some(Duration::from_secs(300)));
        assert_eq!(
            backoff_after(u32::MAX),
            Some(Duration::from_secs(300)),
            "l'attesa ha un tetto, e non trabocca"
        );
    }

    /// **A postazione bloccata i comandi che cambiano o cancellano si
    /// rifiutano, e sbloccata no.**
    #[test]
    fn the_handlers_refuse_only_while_locked() {
        let (mut state, _guard) = state();
        assert!(!super::refuse_while_locked("prova"));
        state.set_locked(true);
        assert!(super::refuse_while_locked("prova"));
        state.set_locked(false);
        assert!(!super::refuse_while_locked("prova"));
    }

    #[test]
    fn an_unprotected_station_never_locks_itself() {
        // Bloccare senza parola chiuderebbe fuori chi non ha nulla da digitare:
        // e' il difetto peggiore che questa funzione possa avere, perche' non
        // ha rimedio dall'interfaccia.
        let (state, _guard) = state();
        let much_later = Instant::now() + Duration::from_secs(60 * 60 * 24);
        assert!(!state.should_engage(10, much_later));
    }

    #[test]
    fn a_protected_station_locks_itself_only_after_the_time_has_passed() {
        let (mut state, _guard) = state();
        let Ok(()) = state.service.protect(FIRST, "parola-di-prova") else {
            panic!("la protezione deve potersi fissare");
        };
        state.last_activity = Instant::now();

        let almost = Instant::now() + Duration::from_secs(10 * 60 - 1);
        assert!(
            !state.should_engage(10, almost),
            "un secondo prima non deve bloccare"
        );

        let due = Instant::now() + Duration::from_secs(10 * 60);
        assert!(state.should_engage(10, due), "allo scadere deve bloccare");
    }

    #[test]
    fn activity_postpones_the_automatic_lock_but_not_while_locked() {
        let (mut state, _guard) = state();
        let Ok(()) = state.service.protect(FIRST, "parola-di-prova") else {
            panic!("la protezione deve potersi fissare");
        };

        state.last_activity = Instant::now() - Duration::from_secs(60 * 60);
        state.note_activity();
        assert!(
            !state.should_engage(10, Instant::now()),
            "un comando premuto rimanda il blocco"
        );

        // A postazione bloccata il segnale non conta: i comandi della schermata
        // di blocco lo emettono anch'essi, e conteggiarli significherebbe che
        // chi tenta parole a caso tiene viva la sessione.
        state.locked = true;
        let before = state.last_activity;
        state.note_activity();
        assert_eq!(
            state.last_activity, before,
            "a postazione bloccata l'attivita' non sposta nulla"
        );
    }

    #[test]
    fn an_account_without_a_word_cannot_be_locked() {
        let (state, _guard) = state();
        assert!(
            !state.protected(),
            "senza parola l'account non risulta protetto"
        );
    }

    #[test]
    fn an_account_with_a_word_is_reported_as_protected() {
        let (state, _guard) = state();
        let Ok(()) = state.service.protect(FIRST, "parola-di-prova") else {
            panic!("la protezione deve potersi fissare");
        };
        assert!(state.protected());
    }

    // I minuti del blocco: il campo si riscrive solo quando cambia il valore
    // salvato. E' la correzione del difetto L8 del pilot — la pompa riscriveva
    // il campo a ogni giro, e nessuna cifra digitata sopravviveva.

    #[test]
    fn the_first_refresh_writes_the_stored_minutes() {
        // All'avvio nell'interfaccia non c'e' ancora nulla: va scritto.
        assert!(should_push_minutes(10, None));
    }

    #[test]
    fn a_refresh_that_finds_the_same_value_writes_nothing() {
        // E' il giro della pompa mentre qualcuno sta digitando: se riscrivesse,
        // la cifra appena battuta sparirebbe sotto le dita.
        assert!(!should_push_minutes(10, Some(10)));
    }

    #[test]
    fn a_changed_stored_value_reaches_the_field() {
        // Un salvataggio riuscito, o un cambio di account con un'altra
        // impostazione: quello va mostrato.
        assert!(should_push_minutes(45, Some(10)));
    }
}

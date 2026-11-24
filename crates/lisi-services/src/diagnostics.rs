//! «Come sta questa postazione?», in un posto solo.
//!
//! # Perché un centro, e non tredici angoli
//!
//! Le risposte c'erano già, sparse: l'idoneità della postazione e lo stato
//! dell'archivio in Impostazioni, la salute delle fonti in Fonti, la firma in
//! «Informazioni e licenze», gli avvisi di Windows fra le capacità. Un
//! operatore a cui il monitoraggio ha smesso di registrare non sa da quale
//! angolo cominciare, e chi lo assiste al telefono nemmeno.
//!
//! Questo modulo compone **una** risposta di tredici aree, ciascuna con
//! l'esito, la frase che lo dice e — quando c'è qualcosa da fare — il gesto.
//!
//! # La regola che governa tutto il modulo
//!
//! **«Non misurato» non è «a posto».** È lo stesso principio di ADR-0053
//! applicato a tutta la postazione: un'area che non si è potuta osservare
//! resta [`CheckOutcome::Unmeasured`], mai [`CheckOutcome::Good`]. Un centro
//! diagnostico che dipinge di verde ciò che non ha guardato è peggio di
//! nessun centro diagnostico, perché insegna a fidarsi del verde.
//!
//! # Perché non compare mai un percorso
//!
//! Perché questa composizione è la stessa che DIAG-02 esporterà in un file
//! destinato a essere spedito a chi assiste. Un percorso reale su Windows
//! contiene **il nome dell'account Windows** con cui si è entrati, che è un
//! dato personale: farlo comparire qui lo porterebbe fuori dalla postazione.
//!
//! Le frasi che il percorso lo contengono esistono e restano dove servono — in
//! Impostazioni, dove chi deve correggere i permessi ha bisogno di sapere su
//! quale cartella intervenire. Qui il centro dice **che cosa** non va e **dove
//! si rimedia**, non dove sta il file. Una prova negativa ispeziona ogni frase
//! prodotta e la fa fallire se contiene un percorso.
//!
//! # Il centro guarda, non tocca
//!
//! Nessuna voce di questo modulo esegue un'azione, scrive nell'archivio o
//! interroga Telegram. Comporre la diagnostica è una **lettura**, e chi la
//! consulta due volte di fila non deve produrre nulla di diverso dal
//! consultarla una volta. Dove esiste un gesto, il centro dice **dove** si
//! compie: un secondo pannello di comandi accanto a quello vero è due pannelli
//! che divergono.

use lisi_core::Timestamp;
use lisi_core::model::telegram_account::PersistedAuthStatus;
use lisi_core::role::OperatingMode;
use lisi_storage::Database;

use crate::capability::{Availability, station_capabilities};
use crate::error::ServiceResult;
use crate::source_health::HealthSummary;

/// Azione di audit con cui una copia di sicurezza si registra.
///
/// È la stessa costante che [`crate::backup`] scrive. Vive qui perché la
/// diagnostica la **cerca**, e cercarla con una stringa scritta a mano in due
/// posti significherebbe che il giorno in cui l'una cambia l'altra smette di
/// trovare qualcosa senza dirlo.
pub const BACKUP_AUDIT_ACTION: &str = "copia_di_sicurezza_prodotta";

/// Che cosa una voce della diagnostica ha constatato.
///
/// # Perché «non misurato» è una variante e non un'assenza
///
/// Perché è un fatto: dice che il prodotto **ha provato** e non c'è riuscito,
/// oppure che quella misura su questa postazione non è possibile. Trattarlo
/// come «va bene» renderebbe verde un centro che non ha guardato niente;
/// trattarlo come un guasto renderebbe rossa una postazione sana.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Misurato, e non c'è nulla da fare.
    Good,
    /// Misurato, e una persona dovrebbe guardarci.
    Attention,
    /// Misurato, ed è un guasto che impedisce al prodotto di lavorare bene.
    Problem,
    /// **Non** misurato.
    Unmeasured,
}

impl CheckOutcome {
    /// La parola che l'operatore legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Good => "In ordine",
            Self::Attention => "Da guardare",
            Self::Problem => "Guasto",
            Self::Unmeasured => "Non misurato",
        }
    }

    /// Se una persona deve intervenire.
    ///
    /// **«Non misurato» non chiede attenzione e non la nega**: chiede una
    /// lettura, ed è per questo che si conta a parte.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::Attention | Self::Problem)
    }

    /// Se la misura è stata presa.
    #[must_use]
    pub const fn is_measured(self) -> bool {
        !matches!(self, Self::Unmeasured)
    }
}

/// Area della postazione su cui la diagnostica risponde.
///
/// Sono le tredici del congelamento di prodotto, nell'ordine in cui si leggono:
/// prima ciò che riguarda il lavoro di oggi, poi ciò che riguarda la macchina.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticArea {
    /// Che cosa sta girando.
    Application,
    /// Dove i dati si conservano.
    Archive,
    /// Se l'archivio è coerente.
    ArchiveIntegrity,
    /// Se la libreria di Telegram è presente in questo binario.
    Tdlib,
    /// Se un account risulta utilizzabile.
    TelegramRuntime,
    /// Come stanno le fonti configurate.
    SourceHealth,
    /// Se Windows accetta gli avvisi.
    WindowsNotifications,
    /// Quanto spazio resta.
    DiskSpace,
    /// Quando è stata prodotta l'ultima copia.
    LastBackup,
    /// Se questa copia dell'applicazione è firmata.
    ApplicationSignature,
    /// Che cosa la postazione offre.
    WindowsCapabilities,
    /// A che punto sta l'aggiornamento.
    UpdateState,
    /// Se il disco è cifrato.
    DiskEncryption,
}

impl DiagnosticArea {
    /// Tutte le aree, nell'ordine di lettura.
    pub const ALL: &'static [Self] = &[
        Self::Application,
        Self::Archive,
        Self::ArchiveIntegrity,
        Self::Tdlib,
        Self::TelegramRuntime,
        Self::SourceHealth,
        Self::WindowsNotifications,
        Self::DiskSpace,
        Self::LastBackup,
        Self::ApplicationSignature,
        Self::WindowsCapabilities,
        Self::UpdateState,
        Self::DiskEncryption,
    ];

    /// Il titolo con cui l'area compare.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Application => "Applicazione",
            Self::Archive => "Archivio",
            Self::ArchiveIntegrity => "Integrità dell'archivio",
            Self::Tdlib => "Libreria di Telegram",
            Self::TelegramRuntime => "Account Telegram",
            Self::SourceHealth => "Fonti monitorate",
            Self::WindowsNotifications => "Avvisi di Windows",
            Self::DiskSpace => "Spazio su disco",
            Self::LastBackup => "Copia di sicurezza",
            Self::ApplicationSignature => "Firma dell'applicazione",
            Self::WindowsCapabilities => "Capacità della postazione",
            Self::UpdateState => "Aggiornamenti",
            Self::DiskEncryption => "Cifratura del disco",
        }
    }
}

/// Una voce della diagnostica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticCheck {
    /// A che cosa si riferisce.
    pub area: DiagnosticArea,
    /// Che cosa si è constatato.
    pub outcome: CheckOutcome,
    /// La frase che lo dice. **Mai un percorso, mai un segreto.**
    pub detail: String,
    /// Il gesto, quando ce n'è uno. Dice **dove** si compie, non lo compie.
    pub action: Option<String>,
}

impl DiagnosticCheck {
    /// Compone una voce misurata.
    fn measured(area: DiagnosticArea, outcome: CheckOutcome, detail: impl Into<String>) -> Self {
        Self {
            area,
            outcome,
            detail: detail.into(),
            action: None,
        }
    }

    /// Aggiunge il gesto.
    fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Compone una voce **non** misurata, con la ragione.
    fn unmeasured(area: DiagnosticArea, reason: impl Into<String>) -> Self {
        Self {
            area,
            outcome: CheckOutcome::Unmeasured,
            detail: reason.into(),
            action: None,
        }
    }
}

/// La fotografia della postazione a un istante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticReport {
    /// Quando è stata presa.
    pub taken_at: Timestamp,
    /// Le tredici voci, nell'ordine di lettura.
    pub checks: Vec<DiagnosticCheck>,
}

impl DiagnosticReport {
    /// Quante voci chiedono una persona.
    #[must_use]
    pub fn needing_attention(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.outcome.needs_attention())
            .count()
    }

    /// Quante voci non è stato possibile misurare.
    #[must_use]
    pub fn unmeasured(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| !check.outcome.is_measured())
            .count()
    }

    /// Il riepilogo, che **non nasconde le voci non misurate**.
    ///
    /// «Tutto in ordine» detto di una postazione di cui tre aree non sono state
    /// osservate è una frase falsa, ed è la stessa falsità che il congelamento
    /// vieta per le fonti.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let totali = self.checks.len();
        let misurate = totali - self.unmeasured();
        let attenzione = self.needing_attention();

        let mut frase = format!("{misurate}/{totali} aree misurate");
        if attenzione > 0 {
            frase.push_str(&format!(", {attenzione} da guardare"));
        }
        if self.unmeasured() > 0 {
            frase.push_str(&format!(
                ", {} non misurabili su questa postazione",
                self.unmeasured()
            ));
        }
        if attenzione == 0 && self.unmeasured() == 0 {
            frase.push_str(", nessuna da guardare");
        }
        frase.push('.');
        frase
    }
}

/// Ciò che solo l'applicazione in esecuzione sa.
///
/// Non si legge dall'archivio perché non ci sta: la modalità in vigore e il
/// fatto che il connettore sia stato avviato appartengono a questa esecuzione,
/// e leggerli da una tabella significherebbe leggere che cosa era vero
/// l'ultima volta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StationFacts {
    /// Modalità operativa in vigore adesso.
    pub mode: OperatingMode,
    /// Se in questa esecuzione Telegram è **collegato davvero**: connettore
    /// reale, accesso autenticato (E2E01-02). Il connettore dimostrativo, anche
    /// autenticato, non conta: non riceve nulla da Telegram.
    pub telegram_runtime_started: bool,
    /// Lo stato delle fonti, già composto da chi lo compone.
    pub sources: HealthSummary,
}

/// Compone la diagnostica della postazione.
#[derive(Debug)]
pub struct DiagnosticsService {
    database: Database,
}

impl DiagnosticsService {
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

    /// La fotografia della postazione.
    ///
    /// # Che cosa costa
    ///
    /// Le letture dell'archivio sono **tre**: gli account, l'ultima copia di
    /// sicurezza e la dimensione dell'archivio. Le altre voci interrogano il
    /// sistema, non l'archivio, e nessuna legge l'intero file.
    ///
    /// # Non scrive nulla
    ///
    /// Comporre la diagnostica è una lettura. Se registrasse qualcosa, aprire
    /// la schermata cambierebbe ciò che la schermata sta fotografando.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se una lettura non riesce.
    pub fn compose(&self, facts: &StationFacts, now: Timestamp) -> ServiceResult<DiagnosticReport> {
        let dimensione = self.database.archive_size();

        let checks = vec![
            application_check(facts),
            archive_check(dimensione),
            integrity_check(),
            tdlib_check(),
            self.telegram_check(facts)?,
            sources_check(facts),
            notifications_check(),
            disk_check(dimensione),
            self.backup_check()?,
            signature_check(),
            capabilities_check(),
            update_check(),
            encryption_check(),
        ];

        Ok(DiagnosticReport {
            taken_at: now,
            checks,
        })
    }

    /// Gli account configurati, e quanti risultano autorizzati.
    fn telegram_check(&self, facts: &StationFacts) -> ServiceResult<DiagnosticCheck> {
        // IN ESERCITAZIONE L'ACCOUNT NON SERVE, E LA DIAGNOSTICA LO DICE COME IL
        // CRUSCOTTO (UX-EXCELLENCE-02, SIM3-20). Diceva «Da guardare: nessun
        // account configurato», e chi si esercitava pensava di dover riparare
        // l'account per usare dati sintetici. Fuori dall'Esercitazione la
        // misura resta quella di sempre: un problema vero non si nasconde.
        if crate::run_mode::is_exercise() {
            return Ok(DiagnosticCheck::measured(
                DiagnosticArea::TelegramRuntime,
                CheckOutcome::Good,
                "In Esercitazione non serve: il programma non si collega a Telegram e i \
                 messaggi di prova sono già nell'archivio. Sulla postazione operativa qui \
                 si legge lo stato dell'account d'ufficio.",
            ));
        }

        let accounts = self.database.telegram_accounts()?;
        let totali = accounts.len();
        let autorizzati = accounts
            .iter()
            .filter(|account| matches!(account.auth_status, PersistedAuthStatus::Authorized))
            .count();

        if totali == 0 {
            return Ok(DiagnosticCheck::measured(
                DiagnosticArea::TelegramRuntime,
                CheckOutcome::Attention,
                "Nessun account Telegram configurato: senza, non si può acquisire nulla.",
            )
            .with_action("Account › «Aggiungi un account»."));
        }

        if autorizzati == 0 {
            return Ok(DiagnosticCheck::measured(
                DiagnosticArea::TelegramRuntime,
                CheckOutcome::Attention,
                format!(
                    "{}, nessuno autorizzato. Finché nessuno lo è, il monitoraggio non può \
                     leggere alcuna fonte.",
                    lisi_core::text::counted(totali, "account configurato", "account configurati")
                ),
            )
            .with_action("Account › scegliere l'account e completare l'accesso."));
        }

        // NON si nominano gli account. L'etichetta la sceglie l'operatore e
        // può contenere qualunque cosa — un nome di persona, un numero, il
        // nome dell'ufficio — e questa frase esce dalla postazione dentro il
        // pacchetto diagnostico. Si contano, non si elencano.
        //
        // AUTORIZZATO NON È COLLEGATO (INSTALLED-APP-E2E-01, E2E01-02). Fino al
        // 2026-10-17 la voce era «Buono» anche quando, dopo un riavvio, il
        // connettore non era avviato o era quello dimostrativo: la fascia
        // diceva «Pronto per lavorare» su una postazione che non avrebbe
        // ricevuto nulla. L'autorizzazione registrata dice che l'accesso c'è
        // stato; soltanto un connettore reale autenticato in questa esecuzione
        // dice che c'è adesso.
        if !facts.telegram_runtime_started {
            return Ok(DiagnosticCheck::measured(
                DiagnosticArea::TelegramRuntime,
                CheckOutcome::Attention,
                format!(
                    "{}, ma Telegram non è collegato in questa esecuzione: finché l'accesso non \
                     viene ripreso, nessun monitoraggio riceve messaggi.",
                    autorizzati_su(autorizzati, totali)
                ),
            )
            .with_action(
                "Account › «Telegram reale» › «Avvia accesso»: con la sessione salvata non \
                 serve un codice nuovo. I monitoraggi non si riprendono da soli.",
            ));
        }

        Ok(DiagnosticCheck::measured(
            DiagnosticArea::TelegramRuntime,
            CheckOutcome::Good,
            format!(
                "{}. Telegram è collegato in questa esecuzione.",
                autorizzati_su(autorizzati, totali)
            ),
        ))
    }

    /// Quando è stata prodotta l'ultima copia di sicurezza.
    ///
    /// # Perché non esiste una soglia di anzianità
    ///
    /// Perché sarebbe inventata: nessun fatto del prodotto dice dopo quanti
    /// giorni una copia smetta di valere. La voce dice **quando**, e chi legge
    /// giudica. È la stessa disciplina di ADR-0053 Decisione 4.
    ///
    /// Che una copia non sia **mai** stata prodotta, invece, non è una soglia:
    /// è un fatto, ed è quello che chiede attenzione.
    fn backup_check(&self) -> ServiceResult<DiagnosticCheck> {
        // Si legge SOLO l'istante: il dettaglio di questa azione di audit
        // contiene la cartella di destinazione, e questa composizione è
        // destinata a essere esportata.
        let ultima = self.database.last_audit_at(BACKUP_AUDIT_ACTION)?;

        // UNA COPIA PIANIFICATA FALLITA NON TACE (BACKUP-SCHEDULE-01,
        // ADR-0191, decisione 5): resta un guasto finché una copia non riesce.
        if let Some((quando, motivo)) = crate::backup_schedule::pending_failure(&self.database)? {
            return Ok(DiagnosticCheck::measured(
                DiagnosticArea::LastBackup,
                CheckOutcome::Problem,
                format!(
                    "La copia pianificata del {} NON è riuscita: {motivo} Finché una copia \
                     non riesce, l'archivio non ha la copia che si aspetta.",
                    quando.to_readable_local()
                ),
            )
            .with_action(
                "Impostazioni › «Copia di sicurezza»: correggere la cartella, o «Produci una \
                 copia».",
            ));
        }

        Ok(match ultima {
            Some(istante) => DiagnosticCheck::measured(
                DiagnosticArea::LastBackup,
                CheckOutcome::Good,
                format!(
                    "Ultima copia di sicurezza prodotta il {}. Quanto sia recente \
                     abbastanza lo decide l'ufficio: il prodotto non fissa una scadenza.",
                    istante.to_readable_local()
                ),
            ),
            None => DiagnosticCheck::measured(
                DiagnosticArea::LastBackup,
                CheckOutcome::Attention,
                "Nessuna copia di sicurezza risulta prodotta da questa postazione. \
                 Se l'archivio si perdesse, non ci sarebbe nulla da rimettere.",
            )
            .with_action("Impostazioni › «Copia di sicurezza» › «Produci una copia»."),
        })
    }
}

/// Che cosa sta girando.
fn application_check(facts: &StationFacts) -> DiagnosticCheck {
    let modalita = match facts.mode {
        OperatingMode::Administrator => "modalità amministratore",
        OperatingMode::Operator => "modalità operatore",
    };
    DiagnosticCheck::measured(
        DiagnosticArea::Application,
        CheckOutcome::Good,
        format!(
            "NEXUM/97 versione {}, in {modalita}.",
            env!("CARGO_PKG_VERSION")
        ),
    )
}

/// Dove i dati si conservano.
///
/// **Il percorso non compare.** Chi deve correggere i permessi lo trova in
/// Impostazioni, dove la frase è scritta per quel gesto; qui la stessa frase
/// porterebbe il nome dell'account Windows dentro un documento esportabile.
fn archive_check(dimensione: Option<u64>) -> DiagnosticCheck {
    let stato = crate::data_directory::check();
    if !stato.is_writable() {
        return DiagnosticCheck::measured(
            DiagnosticArea::Archive,
            CheckOutcome::Problem,
            "La cartella dei dati non è utilizzabile: ciò che si acquisisce ora \
             NON viene conservato.",
        )
        .with_action("Impostazioni › «Stato dell'archivio»: la schermata dice quale cartella.");
    }

    DiagnosticCheck::measured(
        DiagnosticArea::Archive,
        CheckOutcome::Good,
        match dimensione {
            Some(byte) => format!(
                "La cartella dei dati è scrivibile. L'archivio occupa {}.",
                readable_size(byte)
            ),
            None => String::from(
                "La cartella dei dati è scrivibile. L'archivio è in memoria e non \
                 occupa spazio su disco.",
            ),
        },
    )
}

/// Se l'archivio è coerente.
///
/// # Perché il centro non lo verifica da sé
///
/// Perché la verifica legge **tutte** le pagine dell'archivio, e un controllo
/// che rallenta l'apertura di una schermata è un controllo che qualcuno prima o
/// poi spegne. Il centro guarda; il gesto sta dove è sempre stato.
fn integrity_check() -> DiagnosticCheck {
    DiagnosticCheck::unmeasured(
        DiagnosticArea::ArchiveIntegrity,
        "Non verificata in questa fotografia. La verifica legge l'intero archivio, e \
         eseguirla a ogni apertura di questa schermata la renderebbe un controllo che \
         si finisce per saltare.",
    )
    .with_action("Impostazioni › «Stato dell'archivio» › «Verifica l'archivio».")
}

/// Se la libreria di Telegram è presente in questo binario.
fn tdlib_check() -> DiagnosticCheck {
    if crate::telegram_runtime::TELEGRAM_RUNTIME_AVAILABLE {
        return DiagnosticCheck::measured(
            DiagnosticArea::Tdlib,
            CheckOutcome::Good,
            "Questa copia è stata compilata con la libreria ufficiale di Telegram: \
             la modalità reale è disponibile.",
        );
    }

    DiagnosticCheck::measured(
        DiagnosticArea::Tdlib,
        CheckOutcome::Attention,
        "Questa copia è stata compilata SENZA la libreria di Telegram: la modalità \
         reale non è disponibile, e nessun contenuto reale può essere acquisito. \
         Non è un guasto della postazione: è come questa copia è stata costruita.",
    )
}

/// Come stanno le fonti configurate.
fn sources_check(facts: &StationFacts) -> DiagnosticCheck {
    let riepilogo = facts.sources;
    if riepilogo.total == 0 {
        return DiagnosticCheck::measured(
            DiagnosticArea::SourceHealth,
            CheckOutcome::Attention,
            "Nessuna fonte configurata.",
        )
        .with_action("Fonti › scegliere una chat accessibile all'account.");
    }

    let esito = if riepilogo.needing_attention() > 0 {
        CheckOutcome::Attention
    } else {
        CheckOutcome::Good
    };

    let voce =
        DiagnosticCheck::measured(DiagnosticArea::SourceHealth, esito, riepilogo.as_sentence());
    if riepilogo.needing_attention() > 0 || riepilogo.unknown > 0 {
        return voce.with_action("Fonti › «Perché questo stato?» sulla riga della fonte.");
    }
    voce
}

/// Se Windows accetta gli avvisi.
fn notifications_check() -> DiagnosticCheck {
    let stato = lisi_platform::toast::notification_state();
    let messaggio = stato.operator_message();

    if stato.is_enabled() {
        return DiagnosticCheck::measured(
            DiagnosticArea::WindowsNotifications,
            CheckOutcome::Good,
            messaggio,
        );
    }

    if let lisi_platform::toast::NotificationState::Undeterminable { .. } = stato {
        // Non leggibile NON è «disattivato»: dirlo manderebbe l'operatore a
        // cercare un interruttore che è già acceso.
        return DiagnosticCheck::unmeasured(DiagnosticArea::WindowsNotifications, messaggio);
    }

    DiagnosticCheck::measured(
        DiagnosticArea::WindowsNotifications,
        CheckOutcome::Attention,
        messaggio,
    )
}

/// Quanto spazio resta.
///
/// # La sola soglia di questo modulo, e da dove viene
///
/// **Lo spazio libero misurato contro la dimensione dell'archivio**, non contro
/// un numero tondo. Sotto il doppio dell'archivio si chiede attenzione, sotto
/// l'archivio stesso è un guasto, e la ragione è un fatto del prodotto e non un
/// gusto: una copia di sicurezza è grande quanto l'archivio, e la manutenzione
/// di SQLite ne scrive una copia temporanea prima di sostituire l'originale.
/// Sotto quella soglia le due operazioni non riescono.
///
/// # Che cosa questa scelta NON fa, dichiarato
///
/// **Non dice quando il disco sta per riempirsi.** Su un archivio appena nato,
/// grande pochi megabyte, la soglia è soddisfatta anche su un volume quasi
/// pieno. Il numero è mostrato per esteso proprio per questo: chi legge vede
/// quanto resta e giudica, invece di fidarsi di un verde che deriva da una
/// soglia scelta da noi.
fn disk_check(archivio: Option<u64>) -> DiagnosticCheck {
    let cartella = match crate::data_directory::application_directory() {
        Ok(percorso) => percorso,
        Err(_) => {
            return DiagnosticCheck::unmeasured(
                DiagnosticArea::DiskSpace,
                "Non è stato possibile stabilire su quale volume si conservano i dati, \
                 quindi non si è potuto misurare lo spazio.",
            );
        }
    };

    let lisi_platform::DiskSpace::Measured {
        available_to_user,
        total,
    } = lisi_platform::disk_space::for_directory(&cartella)
    else {
        return DiagnosticCheck::unmeasured(
            DiagnosticArea::DiskSpace,
            "Non è stato possibile misurare lo spazio libero su questa postazione. \
             Questo NON significa che sia finito.",
        );
    };

    let misura = format!(
        "Restano {} liberi su {} di capienza.",
        readable_size(available_to_user),
        readable_size(total)
    );

    let Some(archivio) = archivio else {
        return DiagnosticCheck::measured(DiagnosticArea::DiskSpace, CheckOutcome::Good, misura);
    };

    if available_to_user < archivio {
        return DiagnosticCheck::measured(
            DiagnosticArea::DiskSpace,
            CheckOutcome::Problem,
            format!(
                "{misura} È meno di quanto l'archivio stesso occupi: una copia di \
                 sicurezza non ci starebbe, e la manutenzione dell'archivio potrebbe \
                 non riuscire."
            ),
        )
        .with_action("Liberare spazio sul volume, oppure spostare la cartella dei dati.");
    }

    if available_to_user < archivio.saturating_mul(2) {
        return DiagnosticCheck::measured(
            DiagnosticArea::DiskSpace,
            CheckOutcome::Attention,
            format!(
                "{misura} È meno del doppio dell'archivio: la manutenzione scrive una \
                 copia temporanea grande quanto l'archivio prima di sostituirlo."
            ),
        )
        .with_action("Liberare spazio prima che la manutenzione serva.");
    }

    DiagnosticCheck::measured(DiagnosticArea::DiskSpace, CheckOutcome::Good, misura)
}

/// Se questa copia dell'applicazione è firmata.
fn signature_check() -> DiagnosticCheck {
    use lisi_platform::SignatureState;

    match lisi_platform::signature::verify_self() {
        SignatureState::Trusted => DiagnosticCheck::measured(
            DiagnosticArea::ApplicationSignature,
            CheckOutcome::Good,
            "Questa copia è firmata, e Windows riconosce chi l'ha firmata.",
        ),
        SignatureState::Unsigned => DiagnosticCheck::measured(
            DiagnosticArea::ApplicationSignature,
            CheckOutcome::Attention,
            "Questa copia NON è firmata. Windows non può dire da chi provenga, e \
             l'aggiornamento automatico non potrà verificarne l'origine.",
        ),
        // Manomessa: è il caso peggiore, e non si confonde con «non
        // riconosciuta». Qui il contenuto NON corrisponde alla firma, e la sola
        // frase utile è quella che dice di non eseguirlo.
        SignatureState::Tampered => DiagnosticCheck::measured(
            DiagnosticArea::ApplicationSignature,
            CheckOutcome::Problem,
            "Questa copia è firmata ma il contenuto NON corrisponde alla firma: è \
             stata modificata dopo essere stata firmata. Non usarla, e segnalarlo.",
        )
        .with_action("Reinstallare dal Setup.exe originale e segnalare l'accaduto."),
        SignatureState::Untrusted { code } => DiagnosticCheck::measured(
            DiagnosticArea::ApplicationSignature,
            CheckOutcome::Problem,
            format!(
                "Questa copia è firmata, ma Windows NON riconosce la firma \
                 (codice {code:#010x}). Non usarla per un account reale e segnalarlo."
            ),
        ),
        SignatureState::Undeterminable { .. } => DiagnosticCheck::unmeasured(
            DiagnosticArea::ApplicationSignature,
            "Non è stato possibile chiedere a Windows se questa copia sia firmata.",
        ),
    }
}

/// Che cosa la postazione offre.
fn capabilities_check() -> DiagnosticCheck {
    let capacita = station_capabilities();
    let bloccanti = capacita.blocking().len();
    let versione = lisi_platform::os_version::windows_version().operator_message();

    if bloccanti > 0 {
        return DiagnosticCheck::measured(
            DiagnosticArea::WindowsCapabilities,
            CheckOutcome::Problem,
            format!(
                "{versione} {bloccanti} capacità necessarie mancano su questa \
                 postazione: senza, il prodotto non può lavorare in modo sicuro."
            ),
        )
        .with_action("Impostazioni › «Idoneità della postazione»: l'elenco dice quali.");
    }

    let sconosciute = capacita
        .capabilities
        .iter()
        .filter(|singola| singola.availability == Availability::Unknown)
        .count();

    if sconosciute > 0 {
        return DiagnosticCheck::measured(
            DiagnosticArea::WindowsCapabilities,
            CheckOutcome::Attention,
            format!(
                "{versione} Tutte le capacità necessarie sono presenti, ma di \
                 {sconosciute} non si è potuto stabilire lo stato."
            ),
        )
        .with_action("Impostazioni › «Idoneità della postazione».");
    }

    DiagnosticCheck::measured(
        DiagnosticArea::WindowsCapabilities,
        CheckOutcome::Good,
        format!("{versione} Tutte le capacità necessarie sono presenti."),
    )
}

/// A che punto sta l'aggiornamento.
///
/// # Perché è «non misurato» e non «aggiornato»
///
/// Perché questa versione **non cerca** aggiornamenti: non esiste un client
/// HTTP in questo percorso, e il manifesto da esaminare lo indica una persona
/// (ADR-0037). Dire «sei aggiornato» significherebbe dichiarare l'esito di un
/// confronto che nessuno ha fatto.
fn update_check() -> DiagnosticCheck {
    DiagnosticCheck::unmeasured(
        DiagnosticArea::UpdateState,
        format!(
            "In esecuzione la versione {}. Questa versione non cerca aggiornamenti da \
             sé. Il file che descrive un aggiornamento lo indica una persona. Finché non lo \
             si indica, non si sa se ne esista uno più recente.",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .with_action("Impostazioni › «Aggiornamenti» › «Esamina un aggiornamento…».")
}

/// Se il disco è cifrato.
///
/// # Perché non si misura, e perché si dice invece di tacere
///
/// Lo stato di BitLocker si legge da `Win32_EncryptableVolume`, che richiede i
/// privilegi di amministratore. NEXUM/97 si installa **per utente e senza
/// elevazione** (ADR-0023, ADR-0041): chiederli qui significherebbe chiedere
/// all'operatore un privilegio che il prodotto ha deciso di non avere, per una
/// riga di diagnostica.
///
/// Il congelamento dice «BitLocker **dove misurabile senza ipotesi non
/// supportate**»: qui non lo è, e dedurlo da un indizio — una lettera di unità,
/// una chiave di registro — sarebbe esattamente l'ipotesi non supportata. La
/// voce resta, e dice perché è vuota: toglierla farebbe credere che nessuno se
/// lo sia chiesto.
fn encryption_check() -> DiagnosticCheck {
    DiagnosticCheck::unmeasured(
        DiagnosticArea::DiskEncryption,
        "Non misurabile senza privilegi di amministratore, che questo prodotto non \
         chiede. Dedurla da un indizio darebbe una risposta che potrebbe essere \
         sbagliata proprio quando conta.",
    )
    .with_action("Chiedere a chi amministra la postazione se il disco sia cifrato.")
}

/// Una quantità di byte, come la si dice a voce.
///
/// Non in byte: «2 281 472 byte» non si legge, e chi deve decidere se
/// preoccuparsi ragiona in megabyte o in gigabyte.
fn readable_size(byte: u64) -> String {
    const MEGA: u64 = 1024 * 1024;
    const GIGA: u64 = 1024 * MEGA;

    if byte >= GIGA {
        let giga = byte as f64 / GIGA as f64;
        return format!("{giga:.1} GB");
    }
    if byte >= MEGA {
        let mega = byte as f64 / MEGA as f64;
        return format!("{mega:.0} MB");
    }
    String::from("meno di un megabyte")
}

// ---------------------------------------------------------------------------
// DIAG-02 — il pacchetto esportabile
// ---------------------------------------------------------------------------

/// Azione di audit con cui l'esportazione della diagnostica si registra.
pub const EXPORT_AUDIT_ACTION: &str = "diagnostica_esportata";

/// Estensione del file prodotto.
const PACKAGE_EXTENSION: &str = "txt";

/// Le cose che il pacchetto **non** contiene, elencate nel pacchetto stesso.
///
/// # Perché stanno nel file e non solo nella documentazione
///
/// Perché chi lo riceve deve sapere che cosa **non** sta guardando, e chi lo
/// manda deve poter leggere, prima di premere invio, che non sta mandando il
/// contenuto del monitoraggio. Una promessa scritta altrove non la legge
/// nessuno dei due.
const WHAT_IS_NOT_INSIDE: &[&str] = &[
    "il testo dei messaggi acquisiti, e nessun loro frammento",
    "i nomi delle fonti monitorate e degli autori osservati",
    "le credenziali dell'account: API ID e API hash, numero di \
     telefono, codici ricevuti, password di verifica in due passaggi",
    "la sessione di Telegram, che resta legata a questa postazione",
    "i segreti del dispositivo e i codici di arruolamento",
    "chiavi private e certificati",
    "i percorsi delle cartelle, che conterrebbero il nome dell'account Windows",
];

/// Compone il testo del pacchetto diagnostico.
///
/// # Perché è una funzione pura
///
/// Perché il testo si possa **ispezionare in una prova** senza scrivere su un
/// disco, e perché scriverlo e comporlo restino due errori diversi. La prova
/// che conta legge però il **file**: è ciò che verrebbe spedito, ed è quello che
/// va guardato.
///
/// # L'ordine, che non è casuale
///
/// Prima che cosa il file **non** contiene, poi il riepilogo, poi le tredici
/// aree. Chi legge un pacchetto diagnostico cerca rassicurazione: se la parte
/// che manca stesse in fondo, la leggerebbe dopo aver già concluso.
#[must_use]
pub fn render_package(report: &DiagnosticReport) -> String {
    let mut testo = String::new();

    testo.push_str("NEXUM/97 — Telegram Intelligence Monitor\n");
    testo.push_str("Pacchetto diagnostico della postazione\n\n");
    testo.push_str(&format!(
        // `to_readable_utc` scrive già «UTC»: «(UTC)» lo ripeteva (F-25).
        "Prodotto il {}\nVersione dell'applicazione: {}\n\n",
        report.taken_at.to_readable_utc(),
        env!("CARGO_PKG_VERSION")
    ));

    testo.push_str("CHE COSA QUESTO FILE NON CONTIENE\n\n");
    for voce in WHAT_IS_NOT_INSIDE {
        testo.push_str(&format!("  - {voce}\n"));
    }
    testo.push_str(
        "\n  Il file descrive lo STATO della postazione, non ciò che la postazione\n  \
         ha osservato. Si può inviare a chi assiste.\n\n",
    );

    testo.push_str("RIEPILOGO\n\n");
    testo.push_str(&format!("  {}\n\n", report.as_sentence()));

    testo.push_str("LE AREE, UNA PER UNA\n\n");
    for check in &report.checks {
        testo.push_str(&format!(
            "  [{}] {}\n      {}\n",
            check.outcome.label(),
            check.area.title(),
            check.detail
        ));
        if let Some(azione) = &check.action {
            testo.push_str(&format!("      Dove si rimedia: {azione}\n"));
        }
        testo.push('\n');
    }

    testo.push_str(
        "Questo file dice che cosa è stato osservato in un istante, non che tutto\n\
         funzionerà. Un'area «Non misurato» non è un'area a posto: è un'area che il\n\
         prodotto non ha potuto guardare, e la riga dice perché.\n",
    );

    testo
}

/// Nome del file, ordinabile e senza calendario.
fn package_file_stem(now: Timestamp) -> String {
    // In Esercitazione il nome porta il prefisso (PR-13, ADR-0129).
    crate::run_mode::file_name(&format!(
        "nexum97-diagnostica-{:013}",
        now.as_millis().max(0)
    ))
}

impl DiagnosticsService {
    /// Scrive il pacchetto diagnostico nella cartella indicata.
    ///
    /// # Che cosa esce, e che cosa non esce
    ///
    /// Esce **la stessa composizione** che la schermata mostra, che per
    /// costruzione non contiene percorsi (ADR-0054 Decisione 3). Non esce nulla
    /// di ciò che il monitoraggio ha osservato: non un testo di messaggio, non
    /// un nome di fonte, non l'etichetta di un account.
    ///
    /// La garanzia non è una promessa: **prove negative leggono il file
    /// prodotto** su un archivio deliberatamente avvelenato con marcatori in
    /// ogni posto sensibile, e falliscono se anche uno solo ricompare.
    ///
    /// # Perché non c'è un manifesto di integrità
    ///
    /// Perché questo file **non è una prova**: è un rapporto di assistenza.
    /// Un manifesto SHA-256 accanto suggerirebbe che lo sia, e un giorno
    /// qualcuno lo allegherebbe a un atto. I documenti che sono prove hanno il
    /// proprio manifesto, e questo non è uno di essi.
    ///
    /// # Errori
    ///
    /// Restituisce [`crate::ServiceError::ExportNotWritten`] se la cartella non
    /// è utilizzabile o la scrittura non riesce, e l'errore della persistenza
    /// se la lettura o l'audit non riescono.
    pub fn export_to(
        &self,
        directory: &std::path::Path,
        facts: &StationFacts,
        actor: &lisi_core::text::Actor,
        now: Timestamp,
    ) -> ServiceResult<std::path::PathBuf> {
        if !directory.is_dir() {
            return Err(crate::ServiceError::ExportNotWritten {
                reason: String::from("la destinazione non è una cartella"),
            });
        }

        let report = self.compose(facts, now)?;
        let radice = package_file_stem(now);
        let nome = format!("{radice}.{PACKAGE_EXTENSION}");

        // DEL SOLO UTENTE, O NIENTE (SEC-02, ADR-0157): non contiene segreti,
        // ma descrive la postazione e l'archivio. Lo si porta all'assistenza
        // copiandolo, e la copia prende i permessi del posto in cui arriva.
        let consegnati = crate::protected_output::Delivery::begin(
            directory,
            &radice,
            "Il pacchetto per l'assistenza NON è stato scritto",
        )
        .and_then(|mut consegna| {
            consegna.write(
                &nome,
                crate::run_mode::marked_text(render_package(&report)).as_bytes(),
            )?;
            consegna.deliver(crate::protected_output::Existing::Replace)
        })
        .inspect_err(|errore| {
            crate::protected_output::record_refusal(
                &self.database,
                actor,
                now,
                crate::protected_output::REFUSED_AUDIT_ACTION,
                "pacchetto_assistenza",
                errore,
            );
        })?;
        let percorso = consegnati
            .files
            .into_iter()
            .next()
            .unwrap_or_else(|| directory.join(&nome));

        // Nell'audit finisce il FATTO e la cartella, mai il contenuto: è la
        // stessa regola della copia di sicurezza. L'audit resta sulla
        // postazione; il pacchetto no, ed è per questo che il percorso può
        // stare nell'uno e non nell'altro.
        self.database
            .append_audit(&lisi_core::model::NewAuditEntry {
                actor: actor.clone(),
                action: lisi_core::text::AuditAction::try_new(EXPORT_AUDIT_ACTION)?,
                entity: lisi_core::text::AuditEntity::try_new("postazione")?,
                entity_id: None,
                actor_mode: Some(facts.mode),
                detail: Some(lisi_core::text::AuditDetail::try_new(&format!(
                    "pacchetto diagnostico prodotto in {}",
                    directory.display()
                ))?),
                recorded_at: now,
            })?;

        Ok(percorso)
    }
}

/// «1 account autorizzato su 1», «2 account autorizzati su 3»: il participio
/// concorda con il numero (BUG-UX-1: «1 account autorizzati su 1»).
fn autorizzati_su(autorizzati: usize, totali: usize) -> String {
    format!(
        "{} su {totali}",
        lisi_core::text::counted(autorizzati, "account autorizzato", "account autorizzati")
    )
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::{NewAuditEntry, NewSource, SourceKind};
    use lisi_core::role::OperatingMode;
    use lisi_core::text::{
        Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, SourceIdentifier,
    };

    use super::{
        BACKUP_AUDIT_ACTION, CheckOutcome, DiagnosticArea, DiagnosticsService, EXPORT_AUDIT_ACTION,
        StationFacts, WHAT_IS_NOT_INSIDE, readable_size, render_package,
    };
    use crate::source_health::{HealthSummary, SourceHealthService};
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    fn service() -> DiagnosticsService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        DiagnosticsService::new(database)
    }

    fn facts() -> StationFacts {
        StationFacts {
            mode: OperatingMode::Administrator,
            telegram_runtime_started: false,
            sources: HealthSummary::default(),
        }
    }

    fn compose(service: &DiagnosticsService, facts: &StationFacts) -> super::DiagnosticReport {
        let Ok(rapporto) = service.compose(facts, now()) else {
            panic!("la diagnostica deve potersi comporre");
        };
        rapporto
    }

    /// Le tredici aree ci sono tutte, e ciascuna una volta sola.
    ///
    /// Sono quelle del congelamento di prodotto. Una che scomparisse non
    /// lascerebbe alcun buco visibile: la schermata avrebbe semplicemente una
    /// riga in meno, e nessuno se ne accorgerebbe.
    #[test]
    fn tutte_le_aree_del_congelamento_compaiono_una_volta_sola() {
        let rapporto = compose(&service(), &facts());

        assert_eq!(rapporto.checks.len(), DiagnosticArea::ALL.len());
        for area in DiagnosticArea::ALL {
            let quante = rapporto
                .checks
                .iter()
                .filter(|check| check.area == *area)
                .count();
            assert_eq!(
                quante,
                1,
                "l'area «{}» deve comparire una volta",
                area.title()
            );
        }
    }

    /// Nessuna frase prodotta contiene un percorso.
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un percorso reale su Windows contiene il nome dell'account Windows con
    /// cui si è entrati. Questa composizione è la stessa che DIAG-02
    /// esporterà in un file destinato a essere spedito: una frase che porti un
    /// percorso porta quel nome fuori dalla postazione.
    #[test]
    fn nessuna_frase_della_diagnostica_contiene_un_percorso() {
        let rapporto = compose(&service(), &facts());

        for check in &rapporto.checks {
            for testo in [Some(&check.detail), check.action.as_ref()]
                .into_iter()
                .flatten()
            {
                for spia in [":\\", "\\\\", "/Users/", "%USERPROFILE%", "AppData"] {
                    assert!(
                        !testo.contains(spia),
                        "la voce «{}» contiene «{spia}»: un percorso porta fuori dalla \
                         postazione il nome dell'account Windows — «{testo}»",
                        check.area.title()
                    );
                }
            }
        }
    }

    /// «Non misurato» non si conta fra le misurate, e non è «in ordine».
    #[test]
    fn cio_che_non_si_e_misurato_non_risulta_in_ordine() {
        let rapporto = compose(&service(), &facts());

        assert!(
            rapporto.unmeasured() > 0,
            "su questa postazione almeno la cifratura del disco non è misurabile"
        );
        for check in &rapporto.checks {
            if check.outcome == CheckOutcome::Unmeasured {
                assert!(!check.outcome.is_measured());
                assert!(
                    !check.outcome.needs_attention(),
                    "«non misurato» non è un guasto, ed è la ragione per cui è una \
                     variante propria"
                );
                assert_ne!(check.outcome, CheckOutcome::Good);
            }
        }

        let frase = rapporto.as_sentence();
        assert!(
            frase.contains("non misurabili"),
            "il riepilogo non deve nascondere le aree non misurate: «{frase}»"
        );
    }

    /// La cifratura del disco non si dichiara mai in ordine.
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Lo stato di BitLocker richiede privilegi di amministratore, che questo
    /// prodotto non chiede. Dedurlo da un indizio — una lettera di unità, una
    /// chiave di registro — darebbe una risposta che può essere sbagliata
    /// proprio quando conta, e la darebbe **in verde**: chi legge «disco
    /// cifrato» e porta la macchina fuori dall'ufficio ha preso una decisione
    /// su una parola che nessuno ha verificato.
    #[test]
    fn la_cifratura_del_disco_non_si_dichiara_mai_in_ordine() {
        let rapporto = compose(&service(), &facts());

        let Some(voce) = rapporto
            .checks
            .iter()
            .find(|check| check.area == DiagnosticArea::DiskEncryption)
        else {
            panic!(
                "la cifratura deve comparire: toglierla farebbe credere che nessuno se lo sia chiesto"
            );
        };

        assert_eq!(
            voce.outcome,
            CheckOutcome::Unmeasured,
            "la cifratura non è misurabile senza privilegi che il prodotto non chiede: \
             dichiararla in un modo qualsiasi sarebbe inventarla"
        );
        assert!(
            voce.detail.contains("Non misurabile"),
            "la voce deve dire perché è vuota: «{}»",
            voce.detail
        );
    }

    /// Il riepilogo non dichiara mai che vada tutto bene se qualcosa manca.
    #[test]
    fn il_riepilogo_dice_quante_aree_su_quante() {
        let rapporto = compose(&service(), &facts());
        let frase = rapporto.as_sentence();

        assert!(
            frase.contains(&format!("/{} aree misurate", DiagnosticArea::ALL.len())),
            "il riepilogo dice quante su quante: «{frase}»"
        );
        for vietato in ["tutto in ordine", "100%", "copertura"] {
            assert!(
                !frase.to_lowercase().contains(vietato),
                "il riepilogo contiene «{vietato}»: «{frase}»"
            );
        }
    }

    /// L'integrità non si verifica componendo la diagnostica.
    ///
    /// La verifica legge l'intero archivio: eseguirla a ogni apertura di
    /// schermata la renderebbe un controllo che qualcuno finisce per saltare.
    #[test]
    fn l_integrita_non_viene_verificata_dalla_composizione() {
        let rapporto = compose(&service(), &facts());

        let Some(voce) = rapporto
            .checks
            .iter()
            .find(|check| check.area == DiagnosticArea::ArchiveIntegrity)
        else {
            panic!("l'integrità deve comparire");
        };
        assert_eq!(voce.outcome, CheckOutcome::Unmeasured);
        assert!(
            voce.action.is_some(),
            "una voce non misurata deve dire dove si misura"
        );
    }

    /// Comporre la diagnostica non scrive nulla.
    #[test]
    fn comporre_la_diagnostica_non_scrive_nulla() {
        let service = service();
        let Ok(prima) = service.database().audit_entries().map(|voci| voci.len()) else {
            panic!("la lettura deve riuscire");
        };

        for _ in 0..3 {
            let _ = compose(&service, &facts());
        }

        let Ok(dopo) = service.database().audit_entries().map(|voci| voci.len()) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(prima, dopo, "consultare la diagnostica non tocca l'audit");
    }

    /// Una copia mai prodotta chiede attenzione; una prodotta dice quando.
    #[test]
    fn l_ultima_copia_di_sicurezza_si_legge_dall_audit() {
        let service = service();

        let mai = compose(&service, &facts());
        let Some(voce) = mai
            .checks
            .iter()
            .find(|check| check.area == DiagnosticArea::LastBackup)
        else {
            panic!("la copia di sicurezza deve comparire");
        };
        assert_eq!(voce.outcome, CheckOutcome::Attention);
        assert!(voce.detail.contains("Nessuna copia"));

        // Una copia prodotta, registrata come la registra il servizio vero.
        let (Ok(action), Ok(entity), Ok(detail)) = (
            AuditAction::try_new(BACKUP_AUDIT_ACTION),
            AuditEntity::try_new("archivio"),
            AuditDetail::try_new("copia prodotta in una cartella"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(_) = service.database().append_audit(&NewAuditEntry {
            actor: operator(),
            action,
            entity,
            entity_id: None,
            actor_mode: None,
            detail: Some(detail),
            recorded_at: Timestamp::from_millis(1_700_000_500_000),
        }) else {
            panic!("la voce deve potersi registrare");
        };

        let dopo = compose(&service, &facts());
        let Some(voce) = dopo
            .checks
            .iter()
            .find(|check| check.area == DiagnosticArea::LastBackup)
        else {
            panic!("la copia di sicurezza deve comparire");
        };
        assert_eq!(voce.outcome, CheckOutcome::Good);
        assert!(
            !voce.detail.contains("cartella"),
            "il dettaglio dell'audit non deve entrare nella diagnostica: «{}»",
            voce.detail
        );
    }

    /// **Una copia pianificata fallita è un guasto, con la data e il motivo**
    /// (BACKUP-SCHEDULE-01, ADR-0191, decisione 5).
    #[test]
    fn una_copia_pianificata_fallita_e_un_guasto() {
        let Ok(mut database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(action), Ok(entity), Ok(detail)) = (
            AuditAction::try_new(crate::backup_schedule::FAILED_AUDIT_ACTION),
            AuditEntity::try_new("archivio"),
            AuditDetail::try_new("la cartella non c'è"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(_) = database.insert_scheduled_backup(
            &lisi_storage::repository::backup_schedule::NewScheduledBackup {
                attempted_at: Timestamp::from_millis(1_700_000_500_000),
                outcome: String::from("fallita"),
                file_name: None,
                detail: Some(String::from("la cartella non c'è.")),
            },
            &NewAuditEntry {
                actor: operator(),
                action,
                entity,
                entity_id: None,
                actor_mode: None,
                detail: Some(detail),
                recorded_at: Timestamp::from_millis(1_700_000_500_000),
            },
        ) else {
            panic!("il tentativo deve registrarsi");
        };
        let rapporto = compose(&DiagnosticsService::new(database), &facts());
        let Some(voce) = rapporto
            .checks
            .iter()
            .find(|check| check.area == DiagnosticArea::LastBackup)
        else {
            panic!("la copia di sicurezza deve comparire");
        };
        assert_eq!(voce.outcome, CheckOutcome::Problem);
        assert!(
            voce.detail.contains("NON è riuscita: la cartella non c'è."),
            "{}",
            voce.detail
        );
    }

    /// Senza account configurati la diagnostica lo dice e indica il gesto.
    #[test]
    fn senza_account_la_diagnostica_indica_il_gesto() {
        let rapporto = compose(&service(), &facts());

        let Some(voce) = rapporto
            .checks
            .iter()
            .find(|check| check.area == DiagnosticArea::TelegramRuntime)
        else {
            panic!("l'account deve comparire");
        };
        assert_eq!(voce.outcome, CheckOutcome::Attention);
        assert!(
            voce.action.is_some(),
            "deve dire dove si aggiunge un account"
        );
    }

    /// **Autorizzato non è collegato** (E2E01-02, ADR-0146). Un account
    /// autorizzato nell'archivio, con Telegram non collegato in questa
    /// esecuzione, è «Da guardare» con il gesto; collegato, è «Buono».
    #[test]
    fn un_account_autorizzato_ma_non_collegato_e_da_guardare() {
        let (servizio, mut fatti) = service_avvelenato();
        let voce_account = |fatti: &StationFacts| {
            compose(&servizio, fatti)
                .checks
                .into_iter()
                .find(|check| check.area == DiagnosticArea::TelegramRuntime)
                .unwrap_or_else(|| panic!("l'account deve comparire"))
        };

        fatti.telegram_runtime_started = false;
        let scollegato = voce_account(&fatti);
        assert_eq!(scollegato.outcome, CheckOutcome::Attention);
        assert!(
            scollegato
                .action
                .as_deref()
                .is_some_and(|gesto| gesto.contains("Avvia accesso")),
            "deve dire come si riprende l'accesso"
        );
        // Un account solo: il participio concorda (BUG-UX-1).
        assert!(
            scollegato.detail.starts_with("1 account autorizzato su 1,"),
            "{}",
            scollegato.detail
        );

        fatti.telegram_runtime_started = true;
        let collegato = voce_account(&fatti);
        assert_eq!(collegato.outcome, CheckOutcome::Good);
        assert!(
            collegato.detail.starts_with("1 account autorizzato su 1."),
            "{}",
            collegato.detail
        );
    }

    /// Il participio concorda anche al plurale.
    #[test]
    fn gli_autorizzati_concordano_con_il_numero() {
        assert_eq!(super::autorizzati_su(1, 1), "1 account autorizzato su 1");
        assert_eq!(super::autorizzati_su(2, 3), "2 account autorizzati su 3");
    }

    /// Le fonti entrano dal riepilogo già composto, non ricomposte qui.
    #[test]
    fn le_fonti_entrano_dal_riepilogo_gia_composto() {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(display_name)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(_) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name,
                authorized_by: operator(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };

        let health = SourceHealthService::new(database);
        let Ok(riepilogo) = health.summary() else {
            panic!("il riepilogo deve potersi comporre");
        };
        let mut fatti = facts();
        fatti.sources = riepilogo;

        let diagnostica = DiagnosticsService::new(health.into_database());
        let rapporto = compose(&diagnostica, &fatti);

        let Some(voce) = rapporto
            .checks
            .iter()
            .find(|check| check.area == DiagnosticArea::SourceHealth)
        else {
            panic!("le fonti devono comparire");
        };
        assert!(
            voce.detail.contains("0/1 fonti configurate operative"),
            "la voce deve portare la frase del riepilogo: «{}»",
            voce.detail
        );
    }

    /// Le dimensioni si dicono come le direbbe una persona.
    #[test]
    fn le_dimensioni_si_leggono() {
        assert_eq!(readable_size(1_000), "meno di un megabyte");
        assert_eq!(readable_size(5 * 1024 * 1024), "5 MB");
        assert_eq!(readable_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    // ------------------------------------------------------------------
    // DIAG-02 — il pacchetto esportabile
    // ------------------------------------------------------------------

    /// I marcatori con cui l'archivio viene avvelenato.
    ///
    /// Ciascuno sta in un posto diverso e sensibile: il corpo di un messaggio,
    /// il nome di una fonte, l'etichetta di un account, il dettaglio di una
    /// voce di audit — che contiene un percorso, come lo contiene davvero
    /// quello della copia di sicurezza — e una stringa della forma di una
    /// chiave dell'API.
    ///
    /// Nessuno di essi deve ricomparire nel file prodotto.
    const MARCATORI: &[&str] = &[
        "CORPODELMESSAGGIOSEGRETO",
        "NOMEDELLAFONTESEGRETO",
        "ETICHETTAACCOUNTSEGRETA",
        "PERCORSOSEGRETONELLAUDIT",
        "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    ];

    /// Un archivio con un marcatore in ogni posto sensibile.
    ///
    /// # Perché si avvelena invece di verificare a occhio
    ///
    /// Perché «il file non contiene segreti» non si dimostra guardandolo: si
    /// dimostra mettendo qualcosa di riconoscibile in ogni posto da cui
    /// potrebbe uscire, e cercandolo in ciò che è uscito. Se un giorno una
    /// riga della diagnostica cominciasse a nominare una fonte, questa prova
    /// diventerebbe rossa senza che nessuno se lo debba ricordare.
    fn service_avvelenato() -> (DiagnosticsService, StationFacts) {
        use lisi_core::model::telegram_account::{
            AccountUuid, NewApiCredentialProfile, NewTelegramAccount,
        };
        use lisi_core::model::{
            AcquisitionOrigin, AnalysisLevel, NewContent, NewSession, SessionDuration,
        };
        use lisi_core::text::{ContentBody, RemoteMessageId};

        let Ok(mut database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };

        // 1. Una FONTE con un nome riconoscibile.
        let (Ok(identifier), Ok(display_name), Ok(label)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new(MARCATORI[1]),
            DisplayName::try_new("Monitoraggio"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name,
                authorized_by: operator(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };

        // 2. Un CONTENUTO con un corpo riconoscibile.
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new("42"),
            ContentBody::try_new(MARCATORI[0]),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let Ok(_) = database.insert_content(&NewContent {
            session_id,
            source_id,
            remote_message_id: remote,
            author: None,
            author_identifier: None,
            author_username: None,
            body,
            url: None,
            published_at: now(),
            acquired_at: now(),
            origin: AcquisitionOrigin::Observed,
            analysis_level: AnalysisLevel::NOT_RELEVANT,
        }) else {
            panic!("il contenuto deve potersi registrare");
        };

        // 3. Un ACCOUNT con un'etichetta riconoscibile, e un profilo la cui
        //    etichetta ha la forma di una chiave dell'API.
        let (Ok(etichetta), Ok(profilo), Ok(uuid)) = (
            DisplayName::try_new(MARCATORI[2]),
            DisplayName::try_new(MARCATORI[4]),
            AccountUuid::from_hex("0123456789abcdef0123456789abcdef"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(profile_id) =
            database.insert_api_profile(&NewApiCredentialProfile { label: profilo }, now())
        else {
            panic!("il profilo deve potersi registrare");
        };
        let Ok(account_id) = database.insert_telegram_account(
            &NewTelegramAccount {
                uuid,
                label: etichetta,
                profile_id,
            },
            now(),
        ) else {
            panic!("l'account deve potersi registrare");
        };
        // AUTORIZZATO, e non è un dettaglio: senza, la voce dell'account
        // esce dal ramo «nessuno autorizzato» e la prova non attraverserebbe
        // il ramo da cui un'etichetta potrebbe davvero uscire. Un archivio
        // avvelenato che non passa dove il veleno uscirebbe non prova niente.
        let Ok(()) = database.update_account_state(
            account_id,
            lisi_core::model::telegram_account::PersistedAuthStatus::Authorized,
            lisi_core::model::telegram_account::PersistedConnectionStatus::Connected,
            None,
            None,
            now(),
        ) else {
            panic!("la condizione dell'account deve potersi scrivere");
        };

        // 4. Una voce di AUDIT il cui dettaglio contiene un percorso, come lo
        //    contiene davvero quella della copia di sicurezza.
        let (Ok(action), Ok(entity), Ok(detail)) = (
            AuditAction::try_new(BACKUP_AUDIT_ACTION),
            AuditEntity::try_new("archivio"),
            AuditDetail::try_new(&format!("copia prodotta in {}", MARCATORI[3])),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(_) = database.append_audit(&NewAuditEntry {
            actor: operator(),
            action,
            entity,
            entity_id: None,
            actor_mode: None,
            detail: Some(detail),
            recorded_at: now(),
        }) else {
            panic!("la voce deve potersi registrare");
        };

        let health = SourceHealthService::new(database);
        let Ok(riepilogo) = health.summary() else {
            panic!("il riepilogo deve potersi comporre");
        };
        let mut fatti = facts();
        fatti.sources = riepilogo;

        (DiagnosticsService::new(health.into_database()), fatti)
    }

    /// **SEC-02: il pacchetto per l'assistenza del solo utente, o niente**
    /// (ADR-0157). Vista rossa il 2026-10-22 con la protezione tolta (mutazione di SEC-02).
    #[cfg(windows)]
    #[test]
    fn il_pacchetto_per_l_assistenza_e_del_solo_utente_o_non_si_scrive() {
        let (service, fatti) = service_avvelenato();
        crate::permessi_di_prova::prova_un_uscita("pacchetto per l'assistenza", |cartella| {
            service
                .export_to(cartella, &fatti, &operator(), now())
                .map(|percorso| vec![percorso])
        });
    }

    /// **Il file esportato non contiene nulla di ciò che è vietato.**
    ///
    /// È la prova che DIAG-02 esiste per avere. Non guarda la composizione in
    /// memoria: legge i **byte del file**, che è ciò che verrebbe spedito.
    #[test]
    fn il_pacchetto_esportato_non_contiene_materiale_vietato() {
        let (service, fatti) = service_avvelenato();
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella di prova deve potersi creare");
        };

        let Ok(percorso) = service.export_to(cartella.path(), &fatti, &operator(), now()) else {
            panic!("il pacchetto deve potersi scrivere");
        };
        let Ok(scritto) = std::fs::read_to_string(&percorso) else {
            panic!("il pacchetto scritto deve potersi rileggere");
        };

        for marcatore in MARCATORI {
            assert!(
                !scritto.contains(marcatore),
                "il pacchetto contiene «{marcatore}»: è materiale che non deve \
                 uscire dalla postazione"
            );
        }

        // E nessun percorso, per la stessa ragione per cui non ne contiene la
        // schermata: un percorso reale porta fuori il nome dell'account Windows.
        for spia in [":\\", "\\\\", "/Users/", "%USERPROFILE%", "AppData"] {
            assert!(
                !scritto.contains(spia),
                "il pacchetto contiene «{spia}»: un percorso porta fuori dalla \
                 postazione il nome dell'account Windows"
            );
        }
    }

    /// Il pacchetto dice, in testa, che cosa non contiene.
    ///
    /// Chi lo riceve deve sapere che cosa **non** sta guardando; chi lo manda
    /// deve poter leggere, prima di premere invio, che non sta mandando il
    /// contenuto del monitoraggio.
    #[test]
    fn il_pacchetto_dichiara_in_testa_che_cosa_non_contiene() {
        let (service, fatti) = service_avvelenato();
        let Ok(rapporto) = service.compose(&fatti, now()) else {
            panic!("la diagnostica deve potersi comporre");
        };
        let testo = render_package(&rapporto);

        let (Some(assenze), Some(riepilogo)) =
            (testo.find("NON CONTIENE"), testo.find("RIEPILOGO"))
        else {
            panic!("il pacchetto deve avere entrambe le sezioni");
        };
        assert!(
            assenze < riepilogo,
            "ciò che manca va detto PRIMA del riepilogo: in fondo lo si leggerebbe \
             dopo aver già concluso"
        );
        assert_eq!(
            testo.matches("  - ").count(),
            WHAT_IS_NOT_INSIDE.len(),
            "l'elenco delle assenze deve essere completo"
        );
    }

    /// Il pacchetto porta tutte le aree, con il proprio esito scritto.
    #[test]
    fn il_pacchetto_porta_tutte_le_aree_con_il_proprio_esito() {
        let (service, fatti) = service_avvelenato();
        let Ok(rapporto) = service.compose(&fatti, now()) else {
            panic!("la diagnostica deve potersi comporre");
        };
        let testo = render_package(&rapporto);

        for area in DiagnosticArea::ALL {
            assert!(
                testo.contains(area.title()),
                "il pacchetto deve portare l'area «{}»",
                area.title()
            );
        }
        assert!(
            testo.contains("[Non misurato]"),
            "l'esito non misurato deve essere SCRITTO: in un file di testo non \
             c'è colore che possa dirlo al posto delle parole"
        );
    }

    /// Esportare si registra nell'audit, con la cartella e non con il contenuto.
    #[test]
    fn esportare_si_registra_nell_audit() {
        let (service, fatti) = service_avvelenato();
        let Ok(prima) = service.database().audit_entries().map(|voci| voci.len()) else {
            panic!("la lettura deve riuscire");
        };
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella di prova deve potersi creare");
        };

        let Ok(_) = service.export_to(cartella.path(), &fatti, &operator(), now()) else {
            panic!("il pacchetto deve potersi scrivere");
        };

        let Ok(dopo) = service.database().audit_entries() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(dopo.len(), prima + 1, "l'esportazione va registrata");

        let Some(voce) = dopo.last() else {
            panic!("la voce appena scritta deve esistere");
        };
        assert_eq!(voce.action.as_str(), EXPORT_AUDIT_ACTION);
    }

    /// Una destinazione che non è una cartella non produce un file a caso.
    #[test]
    fn una_destinazione_non_valida_non_produce_nulla() {
        let (service, fatti) = service_avvelenato();

        let esito = service.export_to(
            std::path::Path::new("Z:\\cartella-che-non-esiste"),
            &fatti,
            &operator(),
            now(),
        );

        assert!(esito.is_err(), "una destinazione inesistente deve fallire");
        let Ok(voci) = service.database().audit_entries() else {
            panic!("la lettura deve riuscire");
        };
        assert!(
            voci.iter()
                .all(|voce| voce.action.as_str() != EXPORT_AUDIT_ACTION),
            "un'esportazione non avvenuta non va registrata come avvenuta"
        );
    }
}

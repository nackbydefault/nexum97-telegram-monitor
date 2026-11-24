//! Diagnostica tipizzata dell'avvio della modalità Live.
//!
//! Il pilot Live del 2026-07-29 e' avanzato senza alcun errore visibile
//! all'operatore oltre alla categoria generica `errore_connettore`
//! ([`crate::error::ServiceError::kind`] per [`crate::error::ServiceError::Connector`]):
//! nessun dettaglio su **quale** fase dell'avvio fosse fallita. Questo modulo
//! risponde a quella lacuna: ogni fase dell'avvio Live (ADR-0019) ha un codice
//! stabile `LIVE-E0NN`, un messaggio per l'operatore e un'azione suggerita.
//!
//! # Redazione (perche' `technical_cause` e' una `String` e non trasporta segreti)
//!
//! `technical_cause` e' sempre una tra un piccolo numero di costanti scritte a
//! mano da chi genera la diagnostica al sito di chiamata — mai il `Display` o
//! `.to_string()` dell'errore sottostante, e mai un percorso (un percorso
//! reale su Windows puo' contenere il nome dell'account Windows con cui e'
//! stata effettuata l'accesso, che e' un dato personale vietato). Vincolare la
//! provenienza rende la perdita di un segreto strutturalmente impossibile,
//! invece di affidarsi a una successiva opera di redazione.

use lisi_core::Timestamp;

/// Fase dell'avvio della modalità Live in cui un guasto può presentarsi.
///
/// L'ordine qui dichiarato è quello **canonico** della numerazione dei codici
/// `LIVE-E0NN` (indice di posizione = numero del codice): non coincide
/// necessariamente con l'ordine effettivo delle chiamate in
/// `crate::telegram_runtime`, perché alcune fasi concettualmente vicine (per
/// esempio le due aperture dei dati protetti DPAPI) sono raggiunte da siti di
/// chiamata diversi in momenti diversi dell'avvio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveStartupPhase {
    /// 1: caricamento del profilo delle credenziali API.
    ApiProfileLoad,
    /// 2: apertura e decifratura dei dati protetti DPAPI (profilo o chiave).
    DpapiOpen,
    /// 3: preparazione delle cartelle isolate dell'account.
    AccountDirectoryPrepare,
    /// 4: caricamento della libreria `tdjson`.
    TdjsonLoad,
    /// 5: risoluzione dei simboli TDLib attesi nella libreria caricata.
    TdlibSymbolResolve,
    /// 6: creazione del client TDLib.
    ClientCreate,
    /// 7: avvio del connettore.
    ConnectorStart,
    /// 8: invio della configurazione iniziale (`setTdlibParameters`).
    TdlibParametersSet,
    /// 9: avvio della ricezione degli aggiornamenti (polling).
    PollingStart,
    /// 10: attesa del primo stato di autorizzazione.
    FirstAuthorizationStateWait,
    /// 11: ricezione del primo stato di autorizzazione.
    ///
    /// **Non è un fallimento**: è il successo che annulla l'attesa della fase
    /// precedente. Il codice e i messaggi esistono per completezza della
    /// numerazione e non vengono mai mostrati.
    FirstAuthorizationStateReceived,
    /// 12: aggiornamento dello stato conservato dell'account.
    ServiceUpdate,
    /// 13: aggiornamento della GUI.
    ///
    /// **Riservata**: `crates/lisi-app/src/account.rs::refresh()` è oggi
    /// infallibile, quindi questa fase non può fallire nella build corrente.
    /// Non le si è inventato un percorso di fallimento fittizio.
    GuiUpdate,
    /// 14: invio del numero e attesa del codice successivo.
    ///
    /// Nasce dalla lacuna diagnostica osservata nel pilot Live ripetuto del
    /// 2026-07-29: nessuna fase copriva l'intervallo fra "numero inviato con
    /// successo" e "`authorizationStateWaitCode` ricevuto", cosicché un
    /// blocco in questo intervallo restava senza alcuna diagnosi nuova (o
    /// mostrava, immutato, il codice di una fase precedente ormai superata).
    /// Copre **due** guasti distinti sotto lo stesso codice, sul modello
    /// della fase 7 ([`Self::ConnectorStart`], che distingue "già avviato" da
    /// un guasto generico con la stessa fase e messaggi diversi solo nel
    /// registro): un guasto immediato nell'invio del numero al connettore, e
    /// il timeout dell'attesa che segue un invio riuscito. È l'analogo,
    /// spostato di una fase più avanti nell'accesso, della fase 10
    /// ([`Self::FirstAuthorizationStateWait`]), che copre invece l'attesa del
    /// *primo* stato dopo `start()`: le due attese non condividono
    /// l'orologio, perché coprono momenti diversi dell'accesso.
    CodeWaitAfterPhoneNumber,
    /// 15: il client Telegram non risulta mai creato.
    ///
    /// Nasce dal buco diagnostico più grave rilevato dal pilot Live ripetuto
    /// del 2026-07-30: prima di questa fase, un connettore mai avviato (o il
    /// cui avvio è fallito prima di creare il client) veniva interrogato dal
    /// pompaggio e produceva lo stesso codice della fase 9
    /// ([`Self::PollingStart`], "nessun aggiornamento ricevuto"), un
    /// messaggio fuorviante perché il client, in questo caso, non esiste
    /// affatto: non si tratta di una fonte silenziosa, ma di un collegamento
    /// mai stabilito.
    ClientNotCreated,
    /// 16: il client è stato creato ma il risveglio iniziale non è
    /// confermato.
    ///
    /// Distinta dalla fase 15: qui il client esiste per davvero dentro
    /// TDLib (creato con successo), ma la richiesta di risveglio che lo fa
    /// emettere il primo stato di autorizzazione (vedere
    /// `crates/lisi-telegram/src/tdlib/live.rs::LiveTdlibConnector::start`)
    /// non è mai stata consegnata con successo: un client in questo stato
    /// resta silenzioso per sempre, non temporaneamente.
    WakeupNotConfirmed,
}

impl LiveStartupPhase {
    /// Tutte le fasi, nell'ordine canonico, per i test di esaustività e per
    /// l'interfaccia.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::ApiProfileLoad,
            Self::DpapiOpen,
            Self::AccountDirectoryPrepare,
            Self::TdjsonLoad,
            Self::TdlibSymbolResolve,
            Self::ClientCreate,
            Self::ConnectorStart,
            Self::TdlibParametersSet,
            Self::PollingStart,
            Self::FirstAuthorizationStateWait,
            Self::FirstAuthorizationStateReceived,
            Self::ServiceUpdate,
            Self::GuiUpdate,
            Self::CodeWaitAfterPhoneNumber,
            Self::ClientNotCreated,
            Self::WakeupNotConfirmed,
        ]
    }

    /// Codice diagnostico stabile, da `LIVE-E001` a `LIVE-E016`.
    #[must_use]
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::ApiProfileLoad => "LIVE-E001",
            Self::DpapiOpen => "LIVE-E002",
            Self::AccountDirectoryPrepare => "LIVE-E003",
            Self::TdjsonLoad => "LIVE-E004",
            Self::TdlibSymbolResolve => "LIVE-E005",
            Self::ClientCreate => "LIVE-E006",
            Self::ConnectorStart => "LIVE-E007",
            Self::TdlibParametersSet => "LIVE-E008",
            Self::PollingStart => "LIVE-E009",
            Self::FirstAuthorizationStateWait => "LIVE-E010",
            Self::FirstAuthorizationStateReceived => "LIVE-E011",
            Self::ServiceUpdate => "LIVE-E012",
            Self::GuiUpdate => "LIVE-E013",
            Self::CodeWaitAfterPhoneNumber => "LIVE-E014",
            Self::ClientNotCreated => "LIVE-E015",
            Self::WakeupNotConfirmed => "LIVE-E016",
        }
    }

    /// Nome breve della fase, usato nel registro applicativo.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ApiProfileLoad => "caricamento del profilo delle credenziali",
            Self::DpapiOpen => "apertura dei dati protetti",
            Self::AccountDirectoryPrepare => "preparazione delle cartelle dell'account",
            Self::TdjsonLoad => "caricamento della libreria Telegram",
            Self::TdlibSymbolResolve => "controllo del componente per Telegram",
            Self::ClientCreate => "creazione del collegamento",
            Self::ConnectorStart => "avvio del connettore",
            Self::TdlibParametersSet => "impostazione del componente per Telegram",
            Self::PollingStart => "avvio dell'ascolto",
            Self::FirstAuthorizationStateWait => "attesa del primo stato di autorizzazione",
            Self::FirstAuthorizationStateReceived => "ricezione del primo stato di autorizzazione",
            Self::ServiceUpdate => "aggiornamento dello stato del servizio",
            Self::GuiUpdate => "aggiornamento della finestra",
            Self::CodeWaitAfterPhoneNumber => "invio del numero e attesa del codice",
            Self::ClientNotCreated => "collegamento a Telegram non creato",
            Self::WakeupNotConfirmed => "risveglio del collegamento non confermato",
        }
    }

    /// Messaggio per l'operatore, senza alcun dato riservato.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::ApiProfileLoad => {
                "Impossibile leggere il profilo delle credenziali di Telegram collegato \
                 all'account. La configurazione locale è stata preservata."
            }
            Self::DpapiOpen => {
                "Impossibile leggere o decifrare i dati protetti dell'account. \
                 La configurazione locale è stata preservata."
            }
            Self::AccountDirectoryPrepare => {
                "Impossibile preparare le cartelle locali riservate all'account. \
                 La configurazione locale è stata preservata."
            }
            Self::TdjsonLoad => {
                "La libreria Telegram non è stata trovata o non è stata caricata. \
                 La configurazione locale è stata preservata."
            }
            Self::TdlibSymbolResolve => {
                "La libreria Telegram caricata non è risultata compatibile. \
                 La configurazione locale è stata preservata."
            }
            Self::ClientCreate => {
                "Impossibile preparare il collegamento a Telegram. \
                 La configurazione locale è stata preservata."
            }
            Self::ConnectorStart => {
                "Impossibile avviare il collegamento con Telegram. \
                 La configurazione locale è stata preservata."
            }
            Self::TdlibParametersSet => {
                "Impossibile inviare la configurazione iniziale alla libreria Telegram. \
                 La configurazione locale è stata preservata."
            }
            Self::PollingStart => {
                "Impossibile avviare la ricezione degli aggiornamenti da Telegram. \
                 La configurazione locale è stata preservata."
            }
            Self::FirstAuthorizationStateWait => {
                "Nessuna risposta da Telegram entro il tempo previsto. \
                 La configurazione locale è stata preservata."
            }
            // Fase 11: successo, mai mostrata.
            Self::FirstAuthorizationStateReceived => "",
            Self::ServiceUpdate => "Lo stato dell'accesso non è stato salvato.",
            // Fase 13: riservata, oggi irraggiungibile.
            Self::GuiUpdate => "",
            Self::CodeWaitAfterPhoneNumber => {
                "Non è stato possibile completare l'invio del numero, oppure non è \
                 arrivata alcuna richiesta del codice entro il tempo previsto. \
                 La configurazione locale è stata preservata."
            }
            Self::ClientNotCreated => {
                "Il collegamento con Telegram non risulta mai stabilito. \
                 La configurazione locale è stata preservata."
            }
            Self::WakeupNotConfirmed => {
                "Il collegamento con Telegram è stato creato ma non risulta avviato \
                 correttamente. La configurazione locale è stata preservata."
            }
        }
    }

    /// Azione suggerita all'operatore, senza alcun dato riservato.
    #[must_use]
    pub const fn operator_action(self) -> &'static str {
        match self {
            Self::ApiProfileLoad => {
                "Verificare che il profilo delle credenziali sia ancora configurato e riprovare."
            }
            Self::DpapiOpen => {
                "Verificare l'account Windows in uso; se il problema persiste, \
                 ripristinare l'accesso."
            }
            Self::AccountDirectoryPrepare => {
                "Verificare spazio disponibile e permessi sulla cartella dati, \
                 quindi riprovare."
            }
            Self::TdjsonLoad => {
                "Verificare che la copia del programma per la modalità reale sia completa, quindi riprovare."
            }
            Self::TdlibSymbolResolve => {
                "Sostituire la libreria con quella verificata, quindi riprovare."
            }
            Self::ClientCreate => {
                "Riprovare l'accesso; se il problema persiste, segnalarlo all'amministratore."
            }
            Self::ConnectorStart => {
                "Usare «Annulla» per ripristinare un connettore pulito, quindi riprovare."
            }
            Self::TdlibParametersSet => {
                "Riprovare l'accesso; se il problema persiste, segnalarlo all'amministratore."
            }
            Self::PollingStart => {
                "Riprovare l'accesso; se il problema persiste, segnalarlo all'amministratore."
            }
            Self::FirstAuthorizationStateWait => {
                "Verificare la rete e riprovare; se il problema persiste, \
                 segnalarlo all'amministratore."
            }
            Self::FirstAuthorizationStateReceived => "",
            Self::ServiceUpdate => {
                "Il collegamento resta attivo in memoria; se il problema persiste, \
                 segnalarlo all'amministratore."
            }
            Self::GuiUpdate => "",
            Self::CodeWaitAfterPhoneNumber => {
                "Verificare che il numero inserito sia corretto e che la rete sia \
                 raggiungibile. Poi riprovare, inviando di nuovo il numero. Se il problema \
                 resta, segnalarlo all'amministratore."
            }
            Self::ClientNotCreated | Self::WakeupNotConfirmed => {
                "Riprovare l'accesso; se il problema persiste, segnalarlo all'amministratore."
            }
        }
    }
}

/// Guasto diagnosticato durante l'avvio della modalità Live, con la fase
/// esatta in cui si è presentato.
///
/// `technical_cause` non è mai costruita interpolando il `Display`
/// dell'errore sottostante o un percorso: vedere la documentazione del modulo.
#[derive(Clone, PartialEq, Eq)]
pub struct LiveDiagnostic {
    phase: LiveStartupPhase,
    /// Categoria dell'errore originale (per esempio `errore_connettore`),
    /// catturata **prima** dell'incapsulamento in questa diagnostica.
    category: &'static str,
    /// Causa tecnica, sempre una costante scelta dal chiamante: mai il testo
    /// dell'errore sottostante.
    technical_cause: String,
    timestamp: Timestamp,
    /// UUID dell'account interessato, mai il numero di telefono.
    account_uuid: Option<String>,
}

impl LiveDiagnostic {
    /// Costruisce una diagnostica classificata.
    #[must_use]
    pub fn new(
        phase: LiveStartupPhase,
        category: &'static str,
        technical_cause: impl Into<String>,
        timestamp: Timestamp,
        account_uuid: Option<String>,
    ) -> Self {
        Self {
            phase,
            category,
            technical_cause: technical_cause.into(),
            timestamp,
            account_uuid,
        }
    }

    /// Codice diagnostico stabile della fase.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.phase.diagnostic_code()
    }

    /// Fase dell'avvio in cui il guasto si è presentato.
    #[must_use]
    pub const fn phase(&self) -> LiveStartupPhase {
        self.phase
    }

    /// Sintesi per l'operatore: codice, messaggio e azione suggerita.
    #[must_use]
    pub fn operator_summary(&self) -> String {
        format!(
            "{} — {} {}",
            self.code(),
            self.phase.operator_message(),
            self.phase.operator_action()
        )
    }

    /// Registra la diagnostica nel registro applicativo, una sola volta.
    ///
    /// Nessun valore riservato compare: `technical_cause` è già vincolata a un
    /// vocabolario di costanti e l'account compare solo come UUID.
    pub fn log(&self) {
        tracing::warn!(
            codice = self.code(),
            fase = self.phase.name(),
            categoria = self.category,
            causa = %self.technical_cause,
            account = self.account_uuid.as_deref().unwrap_or("-"),
            "avvio Live non riuscito"
        );
    }
}

impl core::fmt::Debug for LiveDiagnostic {
    /// Resa `Debug` che redige `technical_cause` per difesa in profondità.
    ///
    /// `technical_cause` è già vincolata a un vocabolario di costanti sicure
    /// (vedere la documentazione del modulo): questa redazione non è l'unica
    /// difesa, ma segue lo stesso principio già adottato dal tipo `Redacted`
    /// di `crates/lisi-telegram/src/tdlib/live.rs`.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LiveDiagnostic")
            .field("phase", &self.phase)
            .field("category", &self.category)
            .field("technical_cause", &"[redatto]")
            .field("timestamp", &self.timestamp)
            .field("account_uuid", &self.account_uuid)
            .finish()
    }
}

impl core::fmt::Display for LiveDiagnostic {
    /// Stampa **solo** il codice diagnostico: serve a `ServiceError` per
    /// derivare `#[error("{0}")]` senza esporre alcun dettaglio.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::{LiveDiagnostic, LiveStartupPhase};
    use lisi_core::Timestamp;

    fn timestamp() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    #[test]
    fn every_phase_has_a_unique_correctly_ordered_code() {
        let phases = LiveStartupPhase::all();
        assert_eq!(phases.len(), 16, "le fasi documentate sono sedici");

        for (index, phase) in phases.iter().enumerate() {
            let expected = format!("LIVE-E{:03}", index + 1);
            assert_eq!(
                phase.diagnostic_code(),
                expected,
                "la fase in posizione {index} deve avere il codice {expected}"
            );
            for other in phases.iter().skip(index + 1) {
                assert_ne!(
                    phase.diagnostic_code(),
                    other.diagnostic_code(),
                    "due fasi non devono condividere lo stesso codice"
                );
            }
        }
    }

    #[test]
    fn every_code_follows_the_stable_prefix_pattern() {
        for phase in LiveStartupPhase::all() {
            assert!(phase.diagnostic_code().starts_with("LIVE-E0"));
            assert!(!phase.name().is_empty());
        }
    }

    #[test]
    fn the_debug_rendering_never_leaks_the_technical_cause() {
        let poisoned = "api_hash=deadbeef numero=+391234567890";
        let diagnostic = LiveDiagnostic::new(
            LiveStartupPhase::ClientCreate,
            "errore_connettore",
            poisoned.to_string(),
            timestamp(),
            Some(String::from("account-di-prova")),
        );

        let rendered = format!("{diagnostic:?}");
        assert!(!rendered.contains(poisoned));
        assert!(rendered.contains("[redatto]"));
    }

    #[test]
    fn the_operator_summary_never_leaks_the_technical_cause() {
        let poisoned = "api_hash=deadbeef numero=+391234567890";
        let diagnostic = LiveDiagnostic::new(
            LiveStartupPhase::ClientCreate,
            "errore_connettore",
            poisoned.to_string(),
            timestamp(),
            Some(String::from("account-di-prova")),
        );

        assert!(!diagnostic.operator_summary().contains(poisoned));
    }

    #[test]
    fn the_display_rendering_is_only_the_code() {
        let diagnostic = LiveDiagnostic::new(
            LiveStartupPhase::ConnectorStart,
            "errore_connettore",
            "avvio del connettore non riuscito",
            timestamp(),
            None,
        );

        assert_eq!(diagnostic.to_string(), "LIVE-E007");
    }
}

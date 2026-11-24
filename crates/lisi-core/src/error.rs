//! Errori di dominio.
//!
//! Ogni valore di dominio è validato alla costruzione e restituisce un errore
//! tipizzato: i requisiti di sicurezza vietano `panic`, `unwrap` ed `expect` nel
//! codice di produzione, quindi la validazione non può basarsi su asserzioni.

use core::fmt;

/// Errore prodotto dalla costruzione o dalla conversione di un valore di dominio.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// Un campo obbligatorio è vuoto o composto solo da spazi.
    #[error("il campo '{field}' non puo' essere vuoto")]
    Empty {
        /// Nome del campo rifiutato.
        field: &'static str,
    },

    /// Un campo supera la lunghezza massima ammessa.
    #[error(
        "il campo '{field}' supera la lunghezza massima di {max} caratteri (ricevuti {actual})"
    )]
    TooLong {
        /// Nome del campo rifiutato.
        field: &'static str,
        /// Lunghezza massima ammessa, in caratteri.
        max: usize,
        /// Lunghezza effettiva ricevuta.
        actual: usize,
    },

    /// Un campo contiene caratteri di controllo non ammessi.
    #[error("il campo '{field}' contiene caratteri di controllo non ammessi")]
    ControlCharacters {
        /// Nome del campo rifiutato.
        field: &'static str,
    },

    /// Un campo contiene caratteri che alterano l'ordine di lettura.
    ///
    /// Non sono caratteri di controllo secondo Unicode — `char::is_control`
    /// non li vede — ma cambiano il **verso** con cui il testo viene reso.
    /// Un valore che li contenesse potrebbe far leggere all'operatore una
    /// frase diversa da quella scritta dal prodotto, perché questi testi
    /// finiscono interpolati in messaggi, in report e negli export.
    #[error("il campo '{field}' contiene caratteri che alterano l'ordine di lettura")]
    BidirectionalOverride {
        /// Nome del campo rifiutato.
        field: &'static str,
    },

    /// Il livello di analisi è fuori dall'intervallo 0..=4.
    #[error("livello di analisi non valido: {0}; sono ammessi i valori da 0 a 4")]
    InvalidAnalysisLevel(u8),

    /// Un alert è stato costruito con un livello che non genera allarme.
    #[error("un alert richiede un livello da 1 a 4; il livello 0 indica assenza di allarme")]
    AlertLevelWithoutAlarm,

    /// L'URL non ha superato la sanitizzazione.
    #[error("URL non valido: {reason}")]
    InvalidUrl {
        /// Motivo del rifiuto.
        reason: &'static str,
    },

    /// Un valore testuale non corrisponde ad alcuna variante conosciuta.
    #[error("valore '{value}' non riconosciuto per {kind}")]
    UnknownVariant {
        /// Tipo di enumerazione atteso.
        kind: &'static str,
        /// Valore ricevuto.
        value: String,
    },

    /// L'orologio di sistema precede l'epoca Unix.
    #[error("l'orologio di sistema precede l'epoca Unix")]
    ClockBeforeEpoch,

    /// Il timestamp non è rappresentabile.
    #[error("timestamp fuori dall'intervallo rappresentabile")]
    TimestampOutOfRange,

    /// La durata pianificata di una sessione non è coerente con la modalità scelta.
    #[error("durata pianificata non coerente con la modalita' '{mode}'")]
    InconsistentPlannedDuration {
        /// Modalità di durata dichiarata.
        mode: &'static str,
    },

    /// Un intervallo temporale termina prima di iniziare.
    #[error("intervallo temporale non valido: la fine precede l'inizio")]
    EndBeforeStart,

    /// L'impronta non è un SHA-256 esadecimale valido.
    #[error("impronta SHA-256 non valida: sono attesi 64 caratteri esadecimali")]
    InvalidDigest,

    /// Gli estremi di un match non sono coerenti.
    #[error("intervallo di match non valido: fine {end} non successiva a inizio {start}")]
    InvalidMatchRange {
        /// Offset iniziale.
        start: usize,
        /// Offset finale.
        end: usize,
    },

    /// L'UUID di un account non e' 32 cifre esadecimali minuscole.
    #[error("UUID account non valido: attese 32 cifre esadecimali minuscole")]
    InvalidAccountUuid,

    /// Una forma mascherata di numero conserva troppe cifre in chiaro, o e' vuota.
    #[error("numero mascherato non valido")]
    InvalidMaskedPhone,

    /// Un valore di stato conservato non corrisponde ad alcuna variante nota.
    #[error("stato conservato non riconosciuto")]
    InvalidStatus,

    /// L'immagine proposta come stemma non e' utilizzabile.
    ///
    /// Il motivo e' una costante e non un testo dell'operatore: finisce in un
    /// messaggio, e un messaggio composto da un dato d'ingresso e' un messaggio
    /// che un dato d'ingresso puo' riscrivere.
    #[error("immagine non utilizzabile: {reason}")]
    InvalidImage {
        /// Perche' l'immagine e' stata rifiutata.
        reason: &'static str,
    },

    /// La cartella proposta come destinazione non e' utilizzabile.
    ///
    /// Il motivo e' una costante e non un testo dell'operatore, per la stessa
    /// ragione di [`Self::InvalidImage`].
    #[error("cartella non utilizzabile: {reason}")]
    InvalidDestination {
        /// Perche' la cartella e' stata rifiutata.
        reason: &'static str,
    },

    /// Un identificativo di dispositivo non ha la forma prevista.
    ///
    /// Il motivo e' una costante e non il valore ricevuto: un identificativo
    /// rifiutato arriva, in HUB-03, dalla rete, e un messaggio composto da un
    /// dato d'ingresso e' un messaggio che un dato d'ingresso puo' riscrivere.
    #[error("identificativo di dispositivo non valido: {reason}")]
    InvalidDeviceId {
        /// Perche' l'identificativo e' stato rifiutato.
        reason: &'static str,
    },

    /// Un codice di arruolamento non ha la forma prevista.
    ///
    /// Il motivo e' una costante e non il valore ricevuto: un codice arriva da
    /// chi lo ridigita e, con HUB-04, dalla rete.
    #[error("codice di arruolamento non valido: {reason}")]
    InvalidEnrollmentCode {
        /// Perche' il codice e' stato rifiutato.
        reason: &'static str,
    },

    /// Un identificativo di persona non ha la forma prevista.
    ///
    /// Il motivo e' una costante e non il valore ricevuto: un identificativo di
    /// persona arriva dalla rete, e un messaggio composto da un dato
    /// d'ingresso e' un messaggio che un dato d'ingresso puo' riscrivere.
    #[error("identificativo di persona non valido: {reason}")]
    InvalidPersonId {
        /// Perche' l'identificativo e' stato rifiutato.
        reason: &'static str,
    },

    /// Una frase di accesso non e' utilizzabile.
    ///
    /// Il motivo e' una costante, e **non contiene mai la frase**: un errore
    /// che la citasse la scriverebbe in ogni posto in cui l'errore finisce.
    #[error("frase di accesso non valida: {reason}")]
    InvalidPassphrase {
        /// Perche' la frase e' stata rifiutata.
        reason: &'static str,
    },

    /// Un identificativo di comando non e' utilizzabile.
    #[error("identificativo di comando non valido: {reason}")]
    InvalidCommandId {
        /// Perche' e' stato rifiutato.
        reason: &'static str,
    },

    /// Un evento dell'Hub non e' interpretabile.
    #[error("evento dell'Hub non valido: {reason}")]
    InvalidHubEvent {
        /// Perche' l'evento e' stato rifiutato.
        reason: &'static str,
    },

    /// Un ruolo dell'Hub non e' riconoscibile.
    #[error("ruolo dell'Hub non valido: {reason}")]
    InvalidHubRole {
        /// Perche' il ruolo e' stato rifiutato.
        reason: &'static str,
    },

    /// Un'impronta dell'Hub non e' riconoscibile.
    ///
    /// Il motivo e' una costante: l'impronta arriva da chi la ricopia da un
    /// foglietto o da un archivio, e un messaggio composto dal dato ricevuto e'
    /// un messaggio che il dato ricevuto puo' riscrivere.
    #[error("impronta dell'Hub non valida: {reason}")]
    InvalidHubFingerprint {
        /// Perche' l'impronta e' stata rifiutata.
        reason: &'static str,
    },

    /// L'indirizzo di un Hub non e' utilizzabile per raggiungerlo.
    ///
    /// Il motivo e' una costante, per la stessa ragione di
    /// [`Self::InvalidHubFingerprint`]: l'indirizzo arriva da chi lo scrive o
    /// da un file che qualcuno puo' aver riscritto.
    #[error("indirizzo dell'Hub non valido: {reason}")]
    InvalidHubAddress {
        /// Perche' l'indirizzo e' stato rifiutato.
        reason: &'static str,
    },

    /// Una rete dell'ufficio non utilizzabile (HUB-SITES-01, ADR-0198).
    #[error("rete dell'ufficio non valida: {reason}")]
    InvalidOfficeNetwork {
        /// Perche' la rete e' stata rifiutata.
        reason: &'static str,
    },

    /// Un dispositivo non puo' passare allo stato richiesto.
    #[error("passaggio di stato non ammesso per il dispositivo: {reason}")]
    DeviceStateTransition {
        /// Perche' il passaggio e' stato rifiutato.
        reason: &'static str,
    },

    /// Una dichiarazione di organizzazione sorvegliata non e' utilizzabile.
    ///
    /// La dichiara un amministratore, quindi la ragione va scritta in modo che
    /// gli dica **che cosa correggere**: un rifiuto senza ragione manda a
    /// indovinare, e chi indovina la seconda volta dichiara qualcosa di piu'
    /// permissivo per farlo passare.
    #[error("organizzazione sorvegliata non valida: {reason}")]
    InvalidWatchedOrganisation {
        /// Perche' la dichiarazione e' stata rifiutata.
        reason: &'static str,
    },

    /// Un elemento della fotografia ATT&CK non ha la forma prevista.
    ///
    /// Il motivo e' una costante e non il valore ricevuto: il pacchetto ATT&CK
    /// arriva da fuori, e un messaggio composto da un dato d'ingresso e' un
    /// messaggio che un dato d'ingresso puo' riscrivere.
    #[error("elemento della fotografia ATT&CK non valido: {reason}")]
    InvalidAttackElement {
        /// Perche' l'elemento e' stato rifiutato.
        reason: &'static str,
    },

    /// Un termine non rispetta la regola del codice numerico (DICT-CODES-01,
    /// ADR-0170).
    ///
    /// Il motivo e' una costante scritta per chi compila il dizionario, e si
    /// mostra cosi' com'e'.
    #[error("codice numerico non valido: {reason}")]
    InvalidNumericCode {
        /// Perche' il termine e' stato rifiutato.
        reason: &'static str,
    },

    /// Un'espressione regolare che non si puo' cercare (DICT-REGEX-01,
    /// ADR-0187).
    #[error("espressione non valida: {reason}")]
    InvalidExpression {
        /// Perche' l'espressione e' stata rifiutata.
        reason: &'static str,
    },
}

/// Esito di una operazione di dominio.
pub type DomainResult<T> = Result<T, DomainError>;

/// Verifica che un testo obbligatorio sia non vuoto, entro il limite e privo di
/// caratteri di controllo. Restituisce la forma normalizzata senza spazi ai bordi.
pub(crate) fn validate_required_text(
    field: &'static str,
    raw: &str,
    max: usize,
) -> DomainResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Empty { field });
    }
    validate_optional_text(field, trimmed, max)
}

/// Come [`validate_required_text`], ma ammette il testo vuoto.
///
/// I caratteri di controllo sono rifiutati perché il testo confluisce in log,
/// report ed export: un ritorno a capo o un byte NUL inseriti da una fonte
/// remota potrebbero alterare la struttura di quei documenti.
pub(crate) fn validate_optional_text(
    field: &'static str,
    raw: &str,
    max: usize,
) -> DomainResult<String> {
    let trimmed = raw.trim();
    let actual = trimmed.chars().count();
    if actual > max {
        return Err(DomainError::TooLong { field, max, actual });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(DomainError::ControlCharacters { field });
    }
    if trimmed.chars().any(alters_reading_order) {
        return Err(DomainError::BidirectionalOverride { field });
    }
    Ok(trimmed.to_owned())
}

/// Se il carattere altera il verso o la larghezza con cui il testo viene reso.
///
/// `char::is_control` copre la sola categoria Cc e non vede questi. Un nome che
/// li contenesse verrebbe interpolato in messaggi all'operatore, in report e
/// negli export, e potrebbe far leggere una frase diversa da quella scritta dal
/// prodotto: chi fornisce il valore sceglierebbe che cosa l'operatore capisce.
pub(crate) const fn alters_reading_order(character: char) -> bool {
    matches!(
        character,
        // Marcatori e sovrascritture di direzione.
        '\u{200e}' | '\u{200f}' | '\u{061c}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}'
        // Caratteri a larghezza nulla: invisibili, ma presenti nel confronto.
        | '\u{200b}'..='\u{200d}'
        | '\u{00ad}'
        | '\u{feff}'
    )
}

/// Verifica la lunghezza di un testo multilinea, ammettendo i ritorni a capo.
///
/// Il corpo di un messaggio è l'unico campo in cui le interruzioni di riga sono
/// significative e vanno conservate fedelmente. Gli altri caratteri di controllo
/// restano vietati.
pub(crate) fn validate_multiline_text(
    field: &'static str,
    raw: &str,
    max: usize,
) -> DomainResult<String> {
    let actual = raw.chars().count();
    if actual > max {
        return Err(DomainError::TooLong { field, max, actual });
    }
    if raw
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\r')
    {
        return Err(DomainError::ControlCharacters { field });
    }
    if raw.chars().any(alters_reading_order) {
        return Err(DomainError::BidirectionalOverride { field });
    }
    Ok(raw.to_owned())
}

/// Formatta l'elenco delle varianti ammesse, per i messaggi di errore.
pub fn unknown_variant(kind: &'static str, value: &str) -> DomainError {
    DomainError::UnknownVariant {
        kind,
        value: value.chars().take(64).collect(),
    }
}

/// Reso disponibile per i test e per la diagnostica leggibile.
impl DomainError {
    /// Nome breve e stabile della classe di errore, utile per l'audit.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Empty { .. } => "campo_vuoto",
            Self::TooLong { .. } => "campo_troppo_lungo",
            Self::ControlCharacters { .. } => "caratteri_di_controllo",
            Self::BidirectionalOverride { .. } => "ordine_di_lettura_alterato",
            Self::InvalidAnalysisLevel(_) => "livello_non_valido",
            Self::AlertLevelWithoutAlarm => "alert_senza_allarme",
            Self::InvalidUrl { .. } => "url_non_valido",
            Self::UnknownVariant { .. } => "variante_sconosciuta",
            Self::ClockBeforeEpoch => "orologio_prima_epoca",
            Self::TimestampOutOfRange => "timestamp_fuori_intervallo",
            Self::InconsistentPlannedDuration { .. } => "durata_incoerente",
            Self::EndBeforeStart => "fine_prima_inizio",
            Self::InvalidDigest => "impronta_non_valida",
            Self::InvalidMatchRange { .. } => "intervallo_match_non_valido",
            Self::InvalidAccountUuid => "uuid_account_non_valido",
            Self::InvalidMaskedPhone => "numero_mascherato_non_valido",
            Self::InvalidStatus => "stato_non_valido",
            Self::InvalidImage { .. } => "immagine_non_valida",
            Self::InvalidDestination { .. } => "cartella_non_valida",
            Self::InvalidDeviceId { .. } => "dispositivo_non_valido",
            Self::InvalidEnrollmentCode { .. } => "codice_arruolamento_non_valido",
            Self::InvalidPersonId { .. } => "persona_non_valida",
            Self::InvalidPassphrase { .. } => "frase_non_valida",
            Self::InvalidCommandId { .. } => "identificativo_comando_non_valido",
            Self::InvalidHubEvent { .. } => "evento_hub_non_valido",
            Self::InvalidHubRole { .. } => "ruolo_hub_non_valido",
            Self::InvalidHubFingerprint { .. } => "impronta_hub_non_valida",
            Self::InvalidHubAddress { .. } => "indirizzo_hub_non_valido",
            Self::InvalidOfficeNetwork { .. } => "rete_ufficio_non_valida",
            Self::DeviceStateTransition { .. } => "passaggio_dispositivo_non_ammesso",
            Self::InvalidWatchedOrganisation { .. } => "organizzazione_non_valida",
            Self::InvalidAttackElement { .. } => "elemento_attack_non_valido",
            Self::InvalidNumericCode { .. } => "codice_numerico_non_valido",
            Self::InvalidExpression { .. } => "espressione_non_valida",
        }
    }
}

/// Rende l'errore utilizzabile dove è atteso un identificatore leggibile.
pub struct DomainErrorKind<'a>(pub &'a DomainError);

impl fmt::Display for DomainErrorKind<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.kind())
    }
}

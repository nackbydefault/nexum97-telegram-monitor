//! Runtime di acquisizione: inbox, versioni e cancellazioni.
//!
//! È il modello dei fatti che stanno **fra** un evento del connettore e una riga
//! nello storico. La progettazione è in `docs/adr/ADR-0017-ACQUISITION-RUNTIME.md`.
//!
//! Tre principi vivono qui, dove un test li può fissare:
//!
//! - **l'idempotenza è una chiave, non un ottimismo.** Lo stesso evento produce
//!   la stessa [`IdempotencyKey`], e il vincolo di unicità dell'inbox rifiuta il
//!   secondo inserimento. Un controllo applicativo «se non esiste, inserisci»
//!   avrebbe una finestra di corsa che una ripresa dopo crash può centrare;
//! - **le modifiche non si sovrascrivono, si aggiungono.** Una modifica osservata
//!   è una nuova [`ContentVersion`], immutabile; il corpo originale resta;
//! - **la cancellazione è un fatto osservato, non un'intenzione attribuita.** Una
//!   [`ContentDeletion`] registra che un messaggio non è più disponibile presso
//!   la fonte, non che l'autore lo abbia cancellato: non lo sappiamo.

use crate::digest::Sha256Digest;
use crate::id::{ContentDeletionId, ContentId, ContentVersionId, InboxId, SessionId, SourceId};
use crate::text::{ContentBody, RemoteMessageId};
use crate::time::Timestamp;

string_enum!(
    /// Stato di una voce dell'inbox nel suo ciclo di elaborazione.
    InboxState {
        /// Ricevuta e scritta, non ancora validata.
        Received => "received",
        /// Validata, in attesa di elaborazione.
        Validated => "validated",
        /// In elaborazione: se l'applicazione cade qui, va ripresa.
        Processing => "processing",
        /// Elaborata con successo. Non si rielabora.
        Completed => "completed",
        /// Da ritentare dopo un errore transitorio.
        Retry => "retry",
        /// Fallita in modo permanente. Resta in archivio con la sua ragione.
        Failed => "failed",
        /// Scartata alla validazione (quarantena), con un motivo.
        Discarded => "discarded",
    }
);

impl InboxState {
    /// Se lo stato è conclusivo e non richiede altra elaborazione.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Discarded)
    }

    /// Se lo stato attende un'elaborazione (compresa la ripresa dopo crash).
    ///
    /// `Processing` è compreso: una voce rimasta in elaborazione al momento di
    /// un crash è **in sospeso**, e va ripresa. Ignorarla la perderebbe.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Received | Self::Validated | Self::Retry | Self::Processing
        )
    }
}

string_enum!(
    /// Tipo di evento registrato nell'inbox.
    ///
    /// Elenco chiuso, esteso solo con una migrazione: i valori finiscono in un
    /// `CHECK` dello schema.
    InboxEventKind {
        /// Nuovo messaggio da una fonte.
        NewMessage => "new_message",
        /// Modifica di un messaggio già osservabile.
        EditedMessage => "edited_message",
        /// Cancellazione osservata presso la fonte.
        DeletedMessage => "deleted_message",
        /// Una fonte è tornata raggiungibile.
        SourceAvailable => "source_available",
        /// Una fonte non è più raggiungibile.
        SourceUnavailable => "source_unavailable",
        /// Il connettore ha stabilito la sessione.
        ConnectionEstablished => "connection_established",
        /// La connessione è caduta.
        ConnectionLost => "connection_lost",
        /// La connessione è stata ristabilita.
        Reconnected => "reconnected",
        /// Errore transitorio, con backoff.
        TemporaryError => "temporary_error",
        /// Errore non recuperabile senza intervento.
        PermanentError => "permanent_error",
        /// Arresto ordinato richiesto.
        OrderedShutdown => "ordered_shutdown",
        /// Marcatore di avanzamento sicuro.
        Checkpoint => "checkpoint",
        /// Evento ricevuto e non interpretabile da questa versione.
        UnsupportedEvent => "unsupported_event",
    }
);

impl InboxEventKind {
    /// Se l'evento produce o modifica un contenuto nello storico.
    ///
    /// La cancellazione **non** è compresa: riguarda un contenuto ma non ne
    /// crea né ne modifica il corpo, e si registra a parte.
    #[must_use]
    pub const fn creates_or_edits_content(self) -> bool {
        matches!(self, Self::NewMessage | Self::EditedMessage)
    }

    /// Se l'evento riguarda un messaggio specifico (nuovo, modifica o cancellazione).
    #[must_use]
    pub const fn is_about_a_message(self) -> bool {
        matches!(
            self,
            Self::NewMessage | Self::EditedMessage | Self::DeletedMessage
        )
    }
}

/// Chiave di idempotenza di un evento dell'inbox.
///
/// È l'impronta dei **fatti** dell'evento: la stessa combinazione produce la
/// stessa chiave, e il vincolo di unicità dell'inbox rende impossibile
/// applicarla due volte. Eventi diversi producono chiavi diverse — una modifica
/// non collide con l'originale, e due modifiche successive non collidono fra
/// loro grazie al discriminante.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Deriva la chiave dai fatti dell'evento.
    ///
    /// - `discriminator` distingue eventi che condividono gli altri fatti ma
    ///   sono comunque distinti: per una modifica è l'istante o l'impronta del
    ///   nuovo corpo, così che due modifiche dello stesso messaggio siano due
    ///   eventi. Per un nuovo messaggio è vuoto: la riconsegna dello stesso
    ///   messaggio **è** lo stesso evento, e deve collidere.
    ///
    /// Il separatore è un carattere di controllo che i tipi validati del
    /// dominio non ammettono: due combinazioni diverse non possono così
    /// produrre lo stesso testo da cui si calcola l'impronta.
    #[must_use]
    pub fn derive(
        session_id: SessionId,
        source_id: Option<SourceId>,
        kind: InboxEventKind,
        remote_event_id: Option<&str>,
        discriminator: Option<&str>,
    ) -> Self {
        let source = source_id.map_or_else(String::new, |id| id.get().to_string());
        let canonical = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            session_id.get(),
            source,
            kind.as_str(),
            remote_event_id.unwrap_or_default(),
            discriminator.unwrap_or_default(),
        );
        Self(Sha256Digest::of_text(&canonical).as_str().to_owned())
    }

    /// Ricostruisce una chiave già calcolata, letta dal database.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il valore non è un'impronta esadecimale valida.
    pub fn from_stored(raw: &str) -> crate::error::DomainResult<Self> {
        Ok(Self(Sha256Digest::from_hex(raw)?.as_str().to_owned()))
    }

    /// Rappresentazione testuale, per la persistenza.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Voce dell'inbox che si intende scrivere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInboxEntry {
    /// Sessione durante la quale l'evento è stato ricevuto.
    pub session_id: SessionId,
    /// Fonte interessata, quando l'evento ne riguarda una.
    pub source_id: Option<SourceId>,
    /// Tipo di evento.
    pub event_kind: InboxEventKind,
    /// Identificativo del messaggio presso la fonte, quando l'evento ne ha uno.
    pub remote_event_id: Option<RemoteMessageId>,
    /// Chiave di idempotenza.
    pub idempotency_key: IdempotencyKey,
    /// Istante dichiarato dalla fonte, quando disponibile.
    pub remote_timestamp: Option<Timestamp>,
    /// Istante di ricezione da parte del prodotto.
    pub received_at: Timestamp,
    /// Dati normalizzati dell'evento, opachi al dominio e alla persistenza.
    ///
    /// Il formato è definito dal livello dei servizi: qui è una stringa, così
    /// che il dominio non conosca la serializzazione. Deve bastare a rieseguire
    /// l'applicazione dell'evento dopo un riavvio.
    pub payload_json: Option<String>,
    /// Versione del formato del payload.
    pub format_version: u32,
}

/// Voce dell'inbox registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEntry {
    /// Identificatore assegnato dalla persistenza.
    pub id: InboxId,
    /// Sessione durante la quale l'evento è stato ricevuto.
    pub session_id: SessionId,
    /// Fonte interessata, quando l'evento ne riguarda una.
    pub source_id: Option<SourceId>,
    /// Tipo di evento.
    pub event_kind: InboxEventKind,
    /// Identificativo del messaggio presso la fonte, quando presente.
    pub remote_event_id: Option<RemoteMessageId>,
    /// Istante dichiarato dalla fonte, quando disponibile.
    pub remote_timestamp: Option<Timestamp>,
    /// Istante di ricezione.
    pub received_at: Timestamp,
    /// Stato corrente.
    pub state: InboxState,
    /// Tentativi di elaborazione compiuti.
    pub attempts: u32,
    /// Classe dell'ultimo errore, se ce n'è stato uno. Mai testo remoto.
    pub last_error_kind: Option<String>,
    /// Istante del prossimo tentativo, per gli eventi da ritentare.
    pub next_attempt_at: Option<Timestamp>,
    /// Istante di completamento, per gli eventi conclusi.
    pub completed_at: Option<Timestamp>,
    /// Dati normalizzati, per la rielaborazione dopo un riavvio.
    pub payload_json: Option<String>,
    /// Contenuto prodotto o toccato dall'evento, quando ne esiste uno.
    pub correlated_content_id: Option<ContentId>,
}

/// Esito dell'accodamento di un evento nell'inbox.
///
/// Il ritentativo di accodare lo stesso evento è un evento normale, non un
/// errore: è precisamente ciò che la chiave di idempotenza deve rendere
/// innocuo. Il chiamante deve poterlo distinguere da un accodamento nuovo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxOutcome {
    /// L'evento è stato accodato ora.
    Enqueued(InboxId),
    /// L'evento era già presente: stessa chiave di idempotenza.
    AlreadyQueued(InboxId),
}

impl InboxOutcome {
    /// Identificatore della voce, in entrambi i casi.
    #[must_use]
    pub const fn id(self) -> InboxId {
        match self {
            Self::Enqueued(id) | Self::AlreadyQueued(id) => id,
        }
    }

    /// Se l'accodamento ha prodotto una nuova voce.
    #[must_use]
    pub const fn is_new(self) -> bool {
        matches!(self, Self::Enqueued(_))
    }
}

/// Versione di un contenuto che si intende registrare.
///
/// L'impronta del corpo e il numero di versione non sono campi di questo tipo:
/// li calcola la persistenza, così che nessun chiamante possa fornirne uno
/// incoerente con il corpo o fuori sequenza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContentVersion {
    /// Contenuto a cui la versione appartiene.
    pub content_id: ContentId,
    /// Nuovo corpo.
    pub body: ContentBody,
    /// Istante della modifica dichiarato dalla fonte, quando disponibile.
    pub remote_edit_timestamp: Option<Timestamp>,
    /// Istante in cui la modifica è stata osservata.
    pub observed_at: Timestamp,
}

impl NewContentVersion {
    /// Impronta del corpo di questa versione.
    #[must_use]
    pub fn body_digest(&self) -> Sha256Digest {
        Sha256Digest::of_text(self.body.as_str())
    }
}

/// Versione registrata di un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentVersion {
    /// Identificatore assegnato dalla persistenza.
    pub id: ContentVersionId,
    /// Contenuto a cui la versione appartiene.
    pub content_id: ContentId,
    /// Numero progressivo: la versione 1 è il corpo originale.
    pub version_number: u32,
    /// Corpo di questa versione.
    pub body: ContentBody,
    /// Impronta del corpo.
    pub body_sha256: Sha256Digest,
    /// Istante della modifica dichiarato dalla fonte, quando disponibile.
    pub remote_edit_timestamp: Option<Timestamp>,
    /// Istante in cui la versione è stata osservata.
    pub observed_at: Timestamp,
    /// Versione precedente, quando ne esiste una.
    pub previous_version_id: Option<ContentVersionId>,
}

impl ContentVersion {
    /// Se è il corpo originale con cui il contenuto è stato acquisito.
    #[must_use]
    pub const fn is_original(&self) -> bool {
        self.version_number == 1
    }
}

/// Cancellazione osservata che si intende registrare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContentDeletion {
    /// Contenuto cancellato, se era stato acquisito. `None` se mai visto.
    pub content_id: Option<ContentId>,
    /// Sessione durante la quale la cancellazione è stata osservata.
    pub session_id: SessionId,
    /// Fonte presso cui è stata osservata, quando nota.
    pub source_id: Option<SourceId>,
    /// Identificativo del messaggio presso la fonte, quando presente.
    pub remote_event_id: Option<RemoteMessageId>,
    /// Istante in cui la cancellazione è stata osservata.
    pub observed_at: Timestamp,
}

/// Cancellazione registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDeletion {
    /// Identificatore assegnato dalla persistenza.
    pub id: ContentDeletionId,
    /// Contenuto cancellato, se era stato acquisito.
    pub content_id: Option<ContentId>,
    /// Sessione durante la quale è stata osservata.
    pub session_id: SessionId,
    /// Fonte presso cui è stata osservata, quando nota.
    pub source_id: Option<SourceId>,
    /// Identificativo del messaggio presso la fonte, quando presente.
    pub remote_event_id: Option<RemoteMessageId>,
    /// Istante in cui è stata osservata.
    pub observed_at: Timestamp,
}

impl ContentDeletion {
    /// Se la cancellazione riguarda un contenuto mai acquisito.
    ///
    /// È un'informazione, non un errore: la fonte ha cancellato qualcosa che
    /// non abbiamo fatto in tempo a vedere.
    #[must_use]
    pub const fn is_of_an_unseen_message(&self) -> bool {
        self.content_id.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::{IdempotencyKey, InboxEventKind, InboxOutcome, InboxState};
    use crate::id::{InboxId, SessionId, SourceId};

    fn session() -> SessionId {
        SessionId::new(7)
    }

    fn source() -> SourceId {
        SourceId::new(3)
    }

    #[test]
    fn the_same_event_derives_the_same_key() {
        let first = IdempotencyKey::derive(
            session(),
            Some(source()),
            InboxEventKind::NewMessage,
            Some("m1"),
            None,
        );
        let second = IdempotencyKey::derive(
            session(),
            Some(source()),
            InboxEventKind::NewMessage,
            Some("m1"),
            None,
        );
        assert_eq!(first, second);
    }

    #[test]
    fn an_edit_does_not_collide_with_the_original() {
        let original = IdempotencyKey::derive(
            session(),
            Some(source()),
            InboxEventKind::NewMessage,
            Some("m1"),
            None,
        );
        let edit = IdempotencyKey::derive(
            session(),
            Some(source()),
            InboxEventKind::EditedMessage,
            Some("m1"),
            Some("1700000001000"),
        );
        assert_ne!(original, edit);
    }

    #[test]
    fn two_edits_of_the_same_message_are_distinct_events() {
        let first = IdempotencyKey::derive(
            session(),
            Some(source()),
            InboxEventKind::EditedMessage,
            Some("m1"),
            Some("1700000001000"),
        );
        let second = IdempotencyKey::derive(
            session(),
            Some(source()),
            InboxEventKind::EditedMessage,
            Some("m1"),
            Some("1700000002000"),
        );
        assert_ne!(
            first, second,
            "due modifiche successive sono due fatti, non uno"
        );
    }

    #[test]
    fn the_same_message_from_two_sources_is_two_events() {
        let a = IdempotencyKey::derive(
            session(),
            Some(SourceId::new(1)),
            InboxEventKind::NewMessage,
            Some("m1"),
            None,
        );
        let b = IdempotencyKey::derive(
            session(),
            Some(SourceId::new(2)),
            InboxEventKind::NewMessage,
            Some("m1"),
            None,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn a_derived_key_is_a_valid_stored_digest() {
        let key = IdempotencyKey::derive(session(), None, InboxEventKind::Checkpoint, None, None);
        let Ok(restored) = IdempotencyKey::from_stored(key.as_str()) else {
            panic!("la chiave appena derivata deve essere rileggibile");
        };
        assert_eq!(key, restored);
    }

    #[test]
    fn processing_is_pending_so_a_crash_does_not_lose_it() {
        assert!(InboxState::Processing.is_pending());
        assert!(!InboxState::Processing.is_terminal());
        assert!(InboxState::Completed.is_terminal());
        assert!(!InboxState::Completed.is_pending());
    }

    #[test]
    fn only_new_and_edited_events_create_or_change_content() {
        assert!(InboxEventKind::NewMessage.creates_or_edits_content());
        assert!(InboxEventKind::EditedMessage.creates_or_edits_content());
        assert!(!InboxEventKind::DeletedMessage.creates_or_edits_content());
        assert!(InboxEventKind::DeletedMessage.is_about_a_message());
        assert!(!InboxEventKind::Checkpoint.is_about_a_message());
    }

    #[test]
    fn the_outcome_carries_the_id_and_says_whether_it_is_new() {
        let fresh = InboxOutcome::Enqueued(InboxId::new(5));
        assert!(fresh.is_new());
        assert_eq!(fresh.id(), InboxId::new(5));

        let repeat = InboxOutcome::AlreadyQueued(InboxId::new(5));
        assert!(!repeat.is_new());
        assert_eq!(repeat.id(), InboxId::new(5));
    }
}

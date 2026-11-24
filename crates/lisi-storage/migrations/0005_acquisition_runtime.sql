-- Migrazione 0005 - runtime di acquisizione.
--
-- Aggiunge cio' che sta fra un evento del connettore e una riga nello storico:
-- un'inbox durevole, le versioni di un contenuto modificato, le cancellazioni
-- osservate, e un checkpoint di ripresa per sessione.
--
-- La progettazione e' in docs/adr/ADR-0017-ACQUISITION-RUNTIME.md.

-- Inbox durevole. L'evento normalizzato si scrive qui PRIMA di essere
-- elaborato: un crash fra ricezione ed elaborazione lo lascia in archivio, e
-- la ripresa lo recupera.
CREATE TABLE inbox (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id            INTEGER NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    -- Nullable: gli eventi di connessione e gli errori globali non riguardano
    -- una fonte in particolare.
    source_id             INTEGER REFERENCES sources (id) ON DELETE RESTRICT,
    event_kind            TEXT NOT NULL CHECK (event_kind IN (
        'new_message', 'edited_message', 'deleted_message',
        'source_available', 'source_unavailable',
        'connection_established', 'connection_lost', 'reconnected',
        'temporary_error', 'permanent_error',
        'ordered_shutdown', 'checkpoint', 'unsupported_event')),
    remote_event_id       TEXT,
    -- L'idempotenza e' un vincolo di schema, non un controllo applicativo: lo
    -- stesso evento produce la stessa chiave, e il secondo inserimento e'
    -- rifiutato qui, dove nessuna corsa lo aggira.
    idempotency_key       TEXT NOT NULL,
    remote_timestamp      INTEGER,
    received_at           INTEGER NOT NULL,
    -- Evento normalizzato, opaco allo schema: deve bastare a rieseguire
    -- l'applicazione dopo un riavvio. Il formato lo definisce il livello dei
    -- servizi.
    payload_json          TEXT,
    payload_sha256        TEXT CHECK (payload_sha256 IS NULL OR length(payload_sha256) = 64),
    state                 TEXT NOT NULL DEFAULT 'received' CHECK (state IN (
        'received', 'validated', 'processing', 'completed', 'retry', 'failed', 'discarded')),
    attempts              INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- Classe dell'errore, costante del prodotto: mai il testo di un evento remoto.
    last_error_kind       TEXT,
    next_attempt_at       INTEGER,
    completed_at          INTEGER,
    discard_reason        TEXT,
    format_version        INTEGER NOT NULL,
    correlated_content_id INTEGER REFERENCES contents (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX inbox_idempotency ON inbox (idempotency_key);
CREATE INDEX inbox_by_session_state ON inbox (session_id, state, id);

-- Versioni di un contenuto. Una modifica osservata non sovrascrive il corpo
-- originale: aggiunge una versione. La versione 1 e' il corpo con cui il
-- contenuto e' stato acquisito e analizzato.
CREATE TABLE content_versions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id            INTEGER NOT NULL REFERENCES contents (id) ON DELETE RESTRICT,
    version_number        INTEGER NOT NULL CHECK (version_number >= 1),
    body                  TEXT NOT NULL,
    body_sha256           TEXT NOT NULL CHECK (length(body_sha256) = 64),
    remote_edit_timestamp INTEGER,
    observed_at           INTEGER NOT NULL,
    previous_version_id   INTEGER REFERENCES content_versions (id),
    UNIQUE (content_id, version_number)
);

CREATE INDEX content_versions_by_content ON content_versions (content_id, version_number);

-- Le versioni sono immutabili: si aggiungono, non si cambiano. In un archivio
-- probatorio il fatto che un messaggio sia stato cambiato dopo essere stato
-- visto e' spesso l'informazione piu' utile, e non deve poter sparire.
CREATE TRIGGER content_versions_are_immutable
    BEFORE UPDATE ON content_versions
BEGIN
    SELECT RAISE(ABORT, 'una versione di contenuto e'' immutabile');
END;

CREATE TRIGGER content_versions_are_not_deleted
    BEFORE DELETE ON content_versions
BEGIN
    SELECT RAISE(ABORT, 'una versione di contenuto non si cancella');
END;

-- Cancellazioni osservate. Registrano che un messaggio non e' piu' disponibile
-- presso la fonte, senza toccare il contenuto e senza attribuire la
-- cancellazione all'autore: che la fonte non lo esponga piu' non prova che sia
-- stato cancellato da chi lo aveva scritto.
CREATE TABLE content_deletions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Nullable: una cancellazione puo' riguardare un messaggio mai acquisito.
    content_id      INTEGER REFERENCES contents (id) ON DELETE RESTRICT,
    session_id      INTEGER NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    source_id       INTEGER REFERENCES sources (id) ON DELETE RESTRICT,
    remote_event_id TEXT,
    observed_at     INTEGER NOT NULL
);

CREATE INDEX content_deletions_by_content ON content_deletions (content_id);
CREATE INDEX content_deletions_by_session ON content_deletions (session_id);

-- Checkpoint di ripresa per sessione: l'ultima voce dell'inbox completata.
--
-- E' un puntatore SOFT (nessuna foreign key): la retention potra' potare le
-- voci completate dell'inbox, e una chiave esterna rigida lo impedirebbe. Il
-- valore e' un riferimento informativo, non un vincolo.
ALTER TABLE sessions ADD COLUMN last_completed_inbox_id INTEGER;
ALTER TABLE sessions ADD COLUMN checkpoint_at INTEGER;

-- Migrazione 0001 — schema iniziale di LISI Telegram Monitor.
--
-- Le scelte sono motivate in docs/adr/ADR-0006-SQLITE-STORAGE.md.
-- Questo file non va mai modificato una volta applicato: ogni evoluzione dello
-- schema richiede una nuova migrazione numerata.
--
-- AUTOINCREMENT e' usato ovunque perche' impedisce il riuso degli identificatori
-- di righe cancellate. In un archivio con valore probatorio un identificatore
-- riusato renderebbe ambiguo ogni riferimento esterno gia' emesso.

-- Fonti autorizzate al monitoraggio.
CREATE TABLE sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('channel', 'group')),
    identifier TEXT NOT NULL,
    display_name TEXT NOT NULL,
    -- Il monitoraggio avviene solo su fonti autorizzate: l'autorizzazione deve
    -- essere riconducibile a una persona, quindi la colonna non ammette NULL.
    authorized_by TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (kind, identifier)
);

-- Sessioni di monitoraggio.
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    started_by TEXT NOT NULL,
    duration_mode TEXT NOT NULL CHECK (duration_mode IN ('preset', 'custom', 'manual')),
    planned_seconds INTEGER,
    state TEXT NOT NULL CHECK (
        state IN ('planned', 'running', 'paused', 'completed', 'stopped')
    ),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    ended_at INTEGER,
    -- La modalita' manuale non ha durata pianificata; le altre due la esigono
    -- e la vogliono positiva.
    CHECK (
        (duration_mode = 'manual' AND planned_seconds IS NULL)
        OR (duration_mode IN ('preset', 'custom') AND planned_seconds > 0)
    ),
    -- Una sessione non puo' essere conclusa senza essere stata avviata.
    CHECK (ended_at IS NULL OR started_at IS NOT NULL),
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);

-- Fonti selezionate per una sessione.
--
-- La chiave primaria composta e' anche la chiave verso cui punta la foreign key
-- composta di `contents`: e' quel vincolo a rendere strutturalmente impossibile
-- collegare un contenuto a una fonte non selezionata per la sessione.
CREATE TABLE session_sources (
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES sources (id) ON DELETE RESTRICT,
    selected_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, source_id)
);

-- Contenuti acquisiti.
--
-- Vi rientra ogni contenuto effettivamente acquisito e analizzato, compreso
-- quello di livello 0 che non genera alcun alert.
CREATE TABLE contents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    remote_message_id TEXT NOT NULL,
    author TEXT,
    body TEXT NOT NULL,
    url TEXT,
    published_at INTEGER NOT NULL,
    acquired_at INTEGER NOT NULL,
    analysis_level INTEGER NOT NULL CHECK (analysis_level BETWEEN 0 AND 4),
    body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64),
    -- Prima occorrenza dello stesso corpo osservata in un'altra sessione.
    -- La duplicazione fra sessioni e' annotata, non impedita.
    duplicate_of_id INTEGER REFERENCES contents (id) ON DELETE SET NULL,
    -- Deduplicazione per sessione: il ritentativo di acquisizione dello stesso
    -- messaggio non crea righe doppie.
    UNIQUE (session_id, source_id, remote_message_id),
    FOREIGN KEY (session_id, source_id)
    REFERENCES session_sources (session_id, source_id) ON DELETE RESTRICT
);

CREATE INDEX contents_by_session ON contents (session_id, acquired_at);
CREATE INDEX contents_by_body_digest ON contents (body_sha256);
CREATE INDEX contents_by_level ON contents (analysis_level);

-- Riscontri del dizionario su un contenuto.
CREATE TABLE matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id INTEGER NOT NULL REFERENCES contents (id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_category TEXT NOT NULL,
    matched_text TEXT NOT NULL,
    start_offset INTEGER NOT NULL CHECK (start_offset >= 0),
    end_offset INTEGER NOT NULL,
    level INTEGER NOT NULL CHECK (level BETWEEN 0 AND 4),
    created_at INTEGER NOT NULL,
    CHECK (end_offset > start_offset)
);

CREATE INDEX matches_by_content ON matches (content_id);

-- Alert generati dall'analisi.
--
-- Il livello ammesso parte da 1: il livello 0 significa contenuto analizzato e
-- non rilevante, che resta in `contents` senza riga qui.
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id INTEGER NOT NULL UNIQUE REFERENCES contents (id) ON DELETE CASCADE,
    level INTEGER NOT NULL CHECK (level BETWEEN 1 AND 4),
    reason TEXT NOT NULL,
    raised_at INTEGER NOT NULL
);

CREATE INDEX alerts_by_time ON alerts (raised_at);

-- Revisioni umane. Ogni decisione e' conservata: la tabella e' uno storico,
-- non lo stato corrente, cosi' che il percorso di valutazione resti leggibile.
CREATE TABLE reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id INTEGER NOT NULL REFERENCES contents (id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (
        state IN (
            'new', 'in_review', 'relevant', 'not_relevant',
            'duplicate', 'archived', 'reported'
        )
    ),
    reviewer TEXT NOT NULL,
    note TEXT,
    decided_at INTEGER NOT NULL
);

CREATE INDEX reviews_by_content ON reviews (content_id, decided_at);

-- Errori operativi.
CREATE TABLE faults (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES sessions (id) ON DELETE SET NULL,
    source_id INTEGER REFERENCES sources (id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (
        kind IN ('network', 'storage', 'analysis', 'export', 'internal')
    ),
    message TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);

CREATE INDEX faults_by_time ON faults (occurred_at);

-- Export prodotti, con l'impronta del file consegnato.
CREATE TABLE exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    format TEXT NOT NULL CHECK (format IN ('pdf', 'txt', 'xlsx')),
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    requested_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX exports_by_session ON exports (session_id, created_at);

-- Registro di audit.
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    -- Intero grezzo e non foreign key: l'audit attraversa tutte le entita' e
    -- deve sopravvivere alla cancellazione di cio' che descrive.
    entity_id INTEGER,
    detail TEXT,
    recorded_at INTEGER NOT NULL
);

CREATE INDEX audit_by_time ON audit (recorded_at);

-- Append-only realizzato dal motore.
--
-- La garanzia vale contro l'applicazione, non contro chi abbia accesso diretto
-- al file con strumenti esterni: quel rischio residuo e' dichiarato nell'ADR.
CREATE TRIGGER audit_refuses_update
BEFORE UPDATE ON audit
BEGIN
SELECT RAISE(ABORT, 'audit append-only: la modifica non e'' ammessa');
END;

CREATE TRIGGER audit_refuses_delete
BEFORE DELETE ON audit
BEGIN
SELECT RAISE(ABORT, 'audit append-only: la cancellazione non e'' ammessa');
END;

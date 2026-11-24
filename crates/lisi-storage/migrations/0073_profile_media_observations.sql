-- 0073 — Foto, biografia e stato di un autore, osservati su richiesta
-- (PERSON-MEDIA-01, ADR-0174, DEC-443).
--
-- # Che cosa registra
--
-- Una riga per richiesta: chi l'ha fatta, quando e perche', per quale autore
-- di quale monitoraggio, con quale account d'ufficio, e che cosa Telegram ha
-- restituito in quell'istante. Anche un rifiuto, o una richiesta che non e'
-- arrivata a una risposta, ha la sua riga: una richiesta fatta non sparisce.
--
-- # Un'osservazione datata, mai un'identita'
--
-- Una seconda richiesta e' una seconda riga: la prima resta com'era. Lo stato
-- e' il valore di quell'istante, non un attributo della persona. Nessuna
-- colonna collega la riga a un soggetto (resta manuale, PERS-06).
--
-- # La foto
--
-- I byte dell'immagine piccola del profilo, non decodificati, con la loro
-- impronta SHA-256 e un tetto di 512 KiB. Lo schema li vuole insieme: una foto
-- senza impronta, o un'impronta senza foto, non si scrivono.
--
-- # Che cosa non si puo' fare
--
-- Le righe non cambiano e non si cancellano.
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE profile_media_observations (
    id                INTEGER PRIMARY KEY,
    session_id        INTEGER NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    author_identifier TEXT NOT NULL
                          CHECK (length(author_identifier) BETWEEN 1 AND 20
                                 AND author_identifier NOT GLOB '*[^0-9]*'),
    account_uuid      TEXT
                          CHECK (account_uuid IS NULL
                                 OR (length(account_uuid) = 32
                                     AND account_uuid NOT GLOB '*[^0-9a-f]*')),
    requested_by      TEXT NOT NULL CHECK (length(trim(requested_by)) > 0),
    reason            TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    requested_at      INTEGER NOT NULL,
    outcome           TEXT NOT NULL
                          CHECK (outcome IN ('osservato', 'rifiutato', 'non_riuscito')),
    outcome_detail    TEXT,
    bio               TEXT CHECK (bio IS NULL OR length(bio) <= 1000),
    status            TEXT
                          CHECK (status IS NULL OR status IN ('in_linea', 'non_in_linea',
                                 'di_recente', 'ultima_settimana', 'ultimo_mese',
                                 'non_mostrato')),
    status_was_online INTEGER,
    photo             BLOB CHECK (photo IS NULL OR length(photo) BETWEEN 1 AND 524288),
    photo_sha256      TEXT
                          CHECK (photo_sha256 IS NULL
                                 OR (length(photo_sha256) = 64
                                     AND photo_sha256 NOT GLOB '*[^0-9a-f]*')),
    photo_not_read    TEXT,
    CHECK ((photo IS NULL) = (photo_sha256 IS NULL)),
    CHECK (outcome = 'osservato' OR (bio IS NULL AND status IS NULL AND photo IS NULL))
);

CREATE INDEX profile_media_by_author
    ON profile_media_observations (session_id, author_identifier, requested_at);

CREATE TRIGGER profile_media_observations_are_immutable
    BEFORE UPDATE ON profile_media_observations
BEGIN
    SELECT RAISE(ABORT, 'un''osservazione del profilo non cambia');
END;

CREATE TRIGGER profile_media_observations_are_not_deleted
    BEFORE DELETE ON profile_media_observations
BEGIN
    SELECT RAISE(ABORT, 'un''osservazione del profilo non si cancella');
END;

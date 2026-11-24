-- PR-09, ADR-0125: il registro delle ricerche puntuali.
--
-- IN SOLA AGGIUNTA. Una riga per ricerca: chi, perche', quale ingresso, quando,
-- e l'esito fra i cinque, tenuti distinti. I campi del profilo esistono
-- SOLTANTO per un esito «trovato», e contengono soltanto cio' che Telegram ha
-- restituito: mai un'ipotesi, mai cio' che non e' stato ottenuto. Le righe non
-- si modificano e non si cancellano.
--
-- `executed` dice se la richiesta e' partita verso Telegram: un ingresso non
-- ammissibile si registra, ma non conta nel tetto delle ricerche.
CREATE TABLE identity_resolutions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    requested_by      TEXT NOT NULL CHECK (length(trim(requested_by)) > 0),
    reason            TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    input_kind        TEXT NOT NULL CHECK (input_kind IN (
        'nome_utente', 'numero', 'identificativo', 'collegamento')),
    input_value       TEXT NOT NULL,
    requested_at      INTEGER NOT NULL,
    executed          INTEGER NOT NULL CHECK (executed IN (0, 1)),
    outcome           TEXT NOT NULL CHECK (outcome IN (
        'trovato', 'dato_non_disponibile', 'richiesta_non_valida',
        'errore_temporaneo', 'errore_operativo')),
    outcome_reason    TEXT NOT NULL,
    wait_seconds      INTEGER CHECK (wait_seconds IS NULL OR wait_seconds >= 0),
    technical_detail  TEXT,
    found_kind        TEXT,
    found_telegram_id INTEGER,
    found_name        TEXT,
    found_username    TEXT,
    table_version     INTEGER NOT NULL CHECK (table_version >= 1),
    -- Il profilo c'e' tutto e soltanto per un «trovato».
    CHECK ((outcome = 'trovato') = (found_kind IS NOT NULL AND found_telegram_id IS NOT NULL)),
    CHECK (outcome = 'trovato' OR (found_name IS NULL AND found_username IS NULL)),
    -- Un'attesa la indica soltanto un errore temporaneo.
    CHECK (wait_seconds IS NULL OR outcome = 'errore_temporaneo')
);

CREATE INDEX identity_resolutions_by_time ON identity_resolutions (requested_at);

CREATE TRIGGER identity_resolutions_are_immutable
    BEFORE UPDATE ON identity_resolutions
BEGIN
    SELECT RAISE(ABORT, 'una ricerca puntuale registrata e'' immutabile');
END;

CREATE TRIGGER identity_resolutions_are_not_deleted
    BEFORE DELETE ON identity_resolutions
BEGIN
    SELECT RAISE(ABORT, 'una ricerca puntuale non si cancella');
END;

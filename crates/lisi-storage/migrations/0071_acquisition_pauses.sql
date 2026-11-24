-- 0071 — La pausa vera dell'acquisizione (PAUSE-01, ADR-0172, DEC-437).
--
-- # Che cosa registra
--
-- Una riga per pausa: da quando, chi, perche', e quando e chi l'ha ripresa. Il
-- periodo fra la pausa e la ripresa e' non coperto, per decisione
-- dell'operatore, e la copertura lo dice.
--
-- # Che cosa non si puo' fare
--
-- Una sola pausa aperta per monitoraggio. Una riga si completa una volta, con
-- la ripresa, e poi non cambia piu'; non si cancella.
--
-- # Additiva
--
-- Una tabella nuova; lo stato delle sessioni non cambia, e la storia delle
-- sessioni gia' registrate resta com'era.

CREATE TABLE acquisition_pauses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    paused_at   INTEGER NOT NULL,
    paused_by   TEXT NOT NULL CHECK (length(trim(paused_by)) > 0),
    reason      TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 20 AND 500),
    resumed_at  INTEGER,
    resumed_by  TEXT CHECK (resumed_by IS NULL OR length(trim(resumed_by)) > 0),
    CHECK ((resumed_at IS NULL) = (resumed_by IS NULL)),
    CHECK (resumed_at IS NULL OR resumed_at >= paused_at)
);

CREATE UNIQUE INDEX acquisition_pauses_one_open
    ON acquisition_pauses (session_id) WHERE resumed_at IS NULL;

CREATE INDEX acquisition_pauses_by_session
    ON acquisition_pauses (session_id, paused_at);

CREATE TRIGGER acquisition_pauses_complete_once
    BEFORE UPDATE ON acquisition_pauses
    WHEN OLD.resumed_at IS NOT NULL
        OR NEW.session_id IS NOT OLD.session_id
        OR NEW.paused_at IS NOT OLD.paused_at
        OR NEW.paused_by IS NOT OLD.paused_by
        OR NEW.reason IS NOT OLD.reason
BEGIN
    SELECT RAISE(ABORT, 'una pausa registrata si completa una volta sola');
END;

CREATE TRIGGER acquisition_pauses_are_not_deleted
    BEFORE DELETE ON acquisition_pauses
BEGIN
    SELECT RAISE(ABORT, 'una pausa registrata non si cancella');
END;

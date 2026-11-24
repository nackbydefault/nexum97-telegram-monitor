-- 0070 — L'inizio programmato di un monitoraggio (SCHEDULE-01, ADR-0171,
-- DEC-436).
--
-- # Che cosa registra
--
-- Per un monitoraggio programmato, una riga: l'istante in cui deve partire,
-- chi lo ha programmato e quando, e — se e' successo — l'avvio mancato con la
-- sua ragione. Il monitoraggio stesso e' una sessione nello stato
-- pianificato, con la configurazione gia' fissata.
--
-- # Che cosa non si puo' fare
--
-- L'inizio, chi e quando non si riscrivono: per cambiare l'inizio si annulla
-- il monitoraggio e se ne programma un altro. L'avvio mancato si scrive una
-- volta sola, e la riga non si cancella.
--
-- # Additiva
--
-- Una tabella nuova; nessuna tabella esistente cambia.

CREATE TABLE session_schedules (
    session_id    INTEGER PRIMARY KEY REFERENCES sessions (id) ON DELETE CASCADE,
    start_at      INTEGER NOT NULL,
    scheduled_by  TEXT NOT NULL CHECK (length(trim(scheduled_by)) > 0),
    scheduled_at  INTEGER NOT NULL,
    missed_at     INTEGER,
    missed_reason TEXT CHECK (
        missed_reason IN ('programma_chiuso', 'account_non_collegato')
    ),
    CHECK (start_at > scheduled_at),
    CHECK ((missed_at IS NULL) = (missed_reason IS NULL))
);

CREATE INDEX session_schedules_by_start ON session_schedules (start_at);

CREATE TRIGGER session_schedules_are_written_once
    BEFORE UPDATE ON session_schedules
    WHEN NEW.start_at IS NOT OLD.start_at
        OR NEW.scheduled_by IS NOT OLD.scheduled_by
        OR NEW.scheduled_at IS NOT OLD.scheduled_at
        OR NEW.session_id IS NOT OLD.session_id
        OR OLD.missed_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'un inizio programmato non si riscrive');
END;

CREATE TRIGGER session_schedules_are_not_deleted
    BEFORE DELETE ON session_schedules
BEGIN
    SELECT RAISE(ABORT, 'un inizio programmato non si cancella');
END;

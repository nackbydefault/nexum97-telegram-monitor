-- 0086 — La pianificazione delle copie di sicurezza, e il registro dei suoi
-- tentativi (BACKUP-SCHEDULE-01, ADR-0191, DEC-476).
--
-- # Che cosa registra
--
-- `backup_schedule`: una riga sola, la pianificazione della postazione. Spenta
-- di fabbrica: nessuna cartella, nessun intervallo (ADR-0191, decisione 1).
--
-- `scheduled_backups`: ogni tentativo pianificato, riuscito o no, con il
-- motivo; il nome della copia (mai la cartella) e se la conservazione l'ha
-- tolta. Un tentativo non cambia, se non per dire che la sua copia è stata
-- tolta (decisioni 4 e 6).
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE backup_schedule (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    -- NULL vuol dire «spenta», ed e' il valore di fabbrica.
    destination     TEXT CHECK (destination IS NULL
                                OR (length(destination) BETWEEN 1 AND 1024
                                    AND instr(destination, char(10)) = 0
                                    AND instr(destination, char(13)) = 0)),
    interval_days   INTEGER CHECK (interval_days IS NULL OR interval_days BETWEEN 1 AND 30),
    keep            INTEGER CHECK (keep IS NULL OR keep BETWEEN 1 AND 30),
    updated_at      INTEGER NOT NULL,
    updated_by      TEXT    NOT NULL,
    CHECK ((destination IS NULL) = (interval_days IS NULL)),
    CHECK ((destination IS NULL) = (keep IS NULL))
);

INSERT INTO backup_schedule (id, destination, interval_days, keep, updated_at, updated_by)
VALUES (1, NULL, NULL, NULL, 0, 'sistema');

CREATE TRIGGER backup_schedule_non_si_cancella
BEFORE DELETE ON backup_schedule
BEGIN
    SELECT RAISE(ABORT, 'la pianificazione delle copie non si cancella: si spegne');
END;

CREATE TABLE scheduled_backups (
    id            INTEGER PRIMARY KEY,
    attempted_at  INTEGER NOT NULL,
    outcome       TEXT    NOT NULL CHECK (outcome IN ('riuscita', 'fallita')),
    -- Il nome della copia, non il percorso.
    file_name     TEXT CHECK (file_name IS NULL
                              OR (length(file_name) BETWEEN 1 AND 255
                                  AND instr(file_name, '/') = 0
                                  AND instr(file_name, '\') = 0
                                  AND instr(file_name, ':') = 0)),
    detail        TEXT,
    removed_at    INTEGER,
    -- Una copia riuscita ha un nome; un fallimento dice perche' e non ha
    -- niente da togliere.
    CHECK ((outcome = 'riuscita') = (file_name IS NOT NULL)),
    CHECK (outcome = 'riuscita' OR (detail IS NOT NULL AND length(trim(detail)) > 0)),
    CHECK (outcome = 'riuscita' OR removed_at IS NULL)
);

CREATE INDEX scheduled_backups_by_time ON scheduled_backups (attempted_at, id);

-- Un tentativo non cambia: soltanto `removed_at`, una volta, da vuoto.
CREATE TRIGGER scheduled_backups_change_only_removal
    BEFORE UPDATE ON scheduled_backups
    WHEN NEW.id IS NOT OLD.id
      OR NEW.attempted_at IS NOT OLD.attempted_at
      OR NEW.outcome IS NOT OLD.outcome
      OR NEW.file_name IS NOT OLD.file_name
      OR NEW.detail IS NOT OLD.detail
      OR OLD.removed_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'un tentativo registrato non cambia');
END;

CREATE TRIGGER scheduled_backups_are_not_deleted
    BEFORE DELETE ON scheduled_backups
BEGIN
    SELECT RAISE(ABORT, 'un tentativo registrato non si cancella');
END;

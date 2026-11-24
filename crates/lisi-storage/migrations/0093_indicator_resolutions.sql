-- 0093 — La risoluzione degli indicatori dal PC (IOC-RESOLVE-01, ADR-0202).
--
-- # Che cosa registra
--
-- `indicator_resolution_settings`: una riga sola, se la risoluzione è
-- abilitata. Zero è il valore di fabbrica (ADR-0202, decisione 3).
--
-- `indicator_resolutions`: ogni richiesta, con chi, quando, quale indicatore,
-- quale nome si è chiesto davvero al risolutore, com'è andata e che cosa ha
-- risposto (decisione 5). Una richiesta non cambia e non si toglie.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE indicator_resolution_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    enabled     INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL
);

INSERT INTO indicator_resolution_settings (id, enabled, updated_at, updated_by)
VALUES (1, 0, 0, 'sistema');

CREATE TRIGGER indicator_resolution_settings_non_si_cancella
BEFORE DELETE ON indicator_resolution_settings
BEGIN
    SELECT RAISE(ABORT, 'la scelta sulla risoluzione degli indicatori non si cancella: si spegne');
END;

CREATE TABLE indicator_resolutions (
    id              INTEGER PRIMARY KEY,
    indicator_kind  TEXT    NOT NULL CHECK (indicator_kind IN ('ipv4', 'ipv6', 'dominio', 'url')),
    indicator_value TEXT    NOT NULL CHECK (length(indicator_value) BETWEEN 1 AND 2048),
    queried_name    TEXT    NOT NULL CHECK (length(queried_name) BETWEEN 1 AND 255),
    requested_by    TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    requested_at    INTEGER NOT NULL,
    outcome         TEXT    NOT NULL
                            CHECK (outcome IN ('trovato', 'nessun_record', 'inesistente', 'non_riuscito')),
    error_code      INTEGER,
    answers         TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX indicator_resolutions_by_indicator
    ON indicator_resolutions (indicator_kind, indicator_value, requested_at);

CREATE TRIGGER indicator_resolutions_are_immutable
    BEFORE UPDATE ON indicator_resolutions
BEGIN
    SELECT RAISE(ABORT, 'una risoluzione registrata non cambia');
END;

CREATE TRIGGER indicator_resolutions_are_kept
    BEFORE DELETE ON indicator_resolutions
BEGIN
    SELECT RAISE(ABORT, 'una risoluzione registrata non si toglie');
END;

-- 0094 — Il monitoraggio in background e il passaggio di mano (SERVICE-01,
-- ADR-0203).
--
-- # Che cosa registra
--
-- `background_keeper`: una riga sola, l'ultimo segno di vita di chi tiene
-- l'acquisizione — la finestra o il servizio —, quando, e quali account la
-- persona aveva collegato. Si riscrive a ogni segno: è uno stato, non un fatto.
--
-- `background_handovers`: ogni passaggio di mano fra i due custodi, con
-- l'ultimo segno di vita di chi l'ha lasciata e l'istante in cui l'altro l'ha
-- presa. Un passaggio non cambia e non si toglie: il tempo fra i due istanti
-- resta scritto.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE background_keeper (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    keeper          TEXT CHECK (keeper IS NULL OR keeper IN ('finestra', 'servizio')),
    alive_at        INTEGER,
    linked_accounts TEXT NOT NULL DEFAULT ''
);

INSERT INTO background_keeper (id, keeper, alive_at, linked_accounts)
VALUES (1, NULL, NULL, '');

CREATE TRIGGER background_keeper_non_si_cancella
BEFORE DELETE ON background_keeper
BEGIN
    SELECT RAISE(ABORT, 'il segno di vita del custode non si cancella');
END;

CREATE TABLE background_handovers (
    id           INTEGER PRIMARY KEY,
    released_by  TEXT    NOT NULL CHECK (released_by IN ('finestra', 'servizio')),
    released_at  INTEGER NOT NULL,
    taken_by     TEXT    NOT NULL CHECK (taken_by IN ('finestra', 'servizio')),
    taken_at     INTEGER NOT NULL,
    accounts     TEXT    NOT NULL,
    CHECK (released_by <> taken_by),
    CHECK (taken_at >= released_at)
);

CREATE INDEX background_handovers_taken_at ON background_handovers (taken_at);

CREATE TRIGGER background_handovers_sono_immutabili
BEFORE UPDATE ON background_handovers
BEGIN
    SELECT RAISE(ABORT, 'un passaggio di mano registrato non cambia');
END;

CREATE TRIGGER background_handovers_restano
BEFORE DELETE ON background_handovers
BEGIN
    SELECT RAISE(ABORT, 'un passaggio di mano registrato non si cancella');
END;

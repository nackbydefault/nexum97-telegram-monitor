-- 0087 — Il registro dei rapporti complessivi su più monitoraggi
-- (REPORT-MULTI-01, ADR-0192, DEC-478).
--
-- # Che cosa registra
--
-- Ogni rapporto complessivo prodotto: l'identificativo `RC-<anno>-<progressivo>`,
-- chi l'ha chiesto e quando, il responsabile del documento (nome e
-- qualifica), quali monitoraggi, l'impronta dell'elenco delle impronte
-- (ADR-0192, decisione 6).
--
-- # Immutabile
--
-- Risponde a «che cosa è uscito da qui, e a nome di chi»: una riga non cambia
-- e non si cancella. L'audit sta nella stessa transazione.
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE overview_reports (
    id                 INTEGER PRIMARY KEY,
    year               INTEGER NOT NULL CHECK (year BETWEEN 2000 AND 9999),
    sequence           INTEGER NOT NULL CHECK (sequence >= 1),
    requested_by       TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    requested_at       INTEGER NOT NULL,
    responsible_name   TEXT    NOT NULL
                           CHECK (length(trim(responsible_name)) BETWEEN 1 AND 200
                                  AND instr(responsible_name, char(10)) = 0
                                  AND instr(responsible_name, char(13)) = 0),
    responsible_role   TEXT    NOT NULL
                           CHECK (length(trim(responsible_role)) BETWEEN 1 AND 200
                                  AND instr(responsible_role, char(10)) = 0
                                  AND instr(responsible_role, char(13)) = 0),
    -- Gli identificativi dei monitoraggi, separati da una virgola, in ordine.
    session_ids        TEXT    NOT NULL
                           CHECK (length(session_ids) >= 3
                                  AND session_ids NOT GLOB '*[^0-9,]*'
                                  AND instr(session_ids, ',') > 0),
    manifest_sha256    TEXT    NOT NULL
                           CHECK (length(manifest_sha256) = 64
                                  AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    UNIQUE (year, sequence)
);

CREATE TRIGGER overview_reports_are_immutable
    BEFORE UPDATE ON overview_reports
BEGIN
    SELECT RAISE(ABORT, 'un rapporto complessivo registrato non cambia');
END;

CREATE TRIGGER overview_reports_are_not_deleted
    BEFORE DELETE ON overview_reports
BEGIN
    SELECT RAISE(ABORT, 'un rapporto complessivo registrato non si cancella');
END;

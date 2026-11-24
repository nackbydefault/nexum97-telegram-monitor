-- 0088 — Il registro delle consultazioni (AUDIT-VIEW-01, ADR-0193, DEC-480).
--
-- # Che cosa registra
--
-- `consultation_settings`: una riga sola, la conservazione in giorni. NULL vuol
-- dire spento, ed è il valore di fabbrica (ADR-0193, decisione 2).
--
-- `consultations`: chi ha aperto che cosa e quando. Nessun testo, nessun
-- motivo (decisione 1). Una riga non cambia; si toglie soltanto per la
-- conservazione o allo spegnimento (decisione 5).
--
-- # Separato dall'audit
--
-- L'audit documenta le azioni (ADR-0051, decisione 5): le letture stanno qui.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE consultation_settings (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    retention_days  INTEGER CHECK (retention_days IS NULL
                                   OR retention_days BETWEEN 30 AND 365),
    updated_at      INTEGER NOT NULL,
    updated_by      TEXT    NOT NULL
);

INSERT INTO consultation_settings (id, retention_days, updated_at, updated_by)
VALUES (1, NULL, 0, 'sistema');

CREATE TRIGGER consultation_settings_non_si_cancella
BEFORE DELETE ON consultation_settings
BEGIN
    SELECT RAISE(ABORT, 'la scelta del registro delle consultazioni non si cancella: si spegne');
END;

CREATE TABLE consultations (
    id          INTEGER PRIMARY KEY,
    actor       TEXT    NOT NULL CHECK (length(trim(actor)) > 0),
    kind        TEXT    NOT NULL CHECK (kind IN ('contenuto', 'soggetto')),
    entity_id   INTEGER NOT NULL CHECK (entity_id > 0),
    viewed_at   INTEGER NOT NULL
);

CREATE INDEX consultations_by_time ON consultations (viewed_at, id);

CREATE TRIGGER consultations_are_immutable
    BEFORE UPDATE ON consultations
BEGIN
    SELECT RAISE(ABORT, 'una consultazione registrata non cambia');
END;

-- 0091 — I comandi a distanza dei monitoraggi dell'Hub (HUB-REMOTE-01,
-- ADR-0200, DEC-492).
--
-- # Che cosa registra
--
-- `remote_command_settings`: una riga sola, se l'Hub accetta comandi a
-- distanza. Zero è il valore di fabbrica (ADR-0200, decisione 3).
--
-- `remote_commands`: ogni comando ricevuto, eseguito o rifiutato. Chi, da quale
-- postazione, che cosa, su quale monitoraggio, con quale motivo, e com'è
-- andata (decisione 5). Una riga non cambia e non si toglie.
--
-- L'identificativo del comando è unico: ripetere non raddoppia (decisione 7).
-- Il monitoraggio non è una chiave esterna: un comando rifiutato perché il
-- monitoraggio non esiste resta comunque scritto.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE remote_command_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    accepted    INTEGER NOT NULL CHECK (accepted IN (0, 1)),
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL
);

INSERT INTO remote_command_settings (id, accepted, updated_at, updated_by)
VALUES (1, 0, 0, 'sistema');

CREATE TRIGGER remote_command_settings_non_si_cancella
BEFORE DELETE ON remote_command_settings
BEGIN
    SELECT RAISE(ABORT, 'la scelta dei comandi a distanza non si cancella: si spegne');
END;

CREATE TABLE remote_commands (
    id           INTEGER PRIMARY KEY,
    command_id   TEXT    NOT NULL UNIQUE
                         CHECK (length(command_id) BETWEEN 8 AND 64),
    device       TEXT    NOT NULL CHECK (length(trim(device)) > 0),
    person       TEXT    NOT NULL CHECK (length(trim(person)) > 0),
    session_id   INTEGER NOT NULL CHECK (session_id > 0),
    action       TEXT    NOT NULL CHECK (action IN ('pausa', 'ripresa', 'arresto')),
    reason       TEXT    NOT NULL,
    outcome      TEXT    NOT NULL CHECK (outcome IN ('eseguito', 'rifiutato')),
    detail       TEXT    NOT NULL,
    received_at  INTEGER NOT NULL
);

CREATE INDEX remote_commands_by_time ON remote_commands (received_at, id);

CREATE TRIGGER remote_commands_are_immutable
    BEFORE UPDATE ON remote_commands
BEGIN
    SELECT RAISE(ABORT, 'un comando a distanza registrato non cambia');
END;

CREATE TRIGGER remote_commands_are_kept
    BEFORE DELETE ON remote_commands
BEGIN
    SELECT RAISE(ABORT, 'un comando a distanza registrato non si toglie');
END;

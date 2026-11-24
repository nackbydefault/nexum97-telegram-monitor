-- PR-07, ADR-0123: il registro delle operazioni di recupero.
--
-- IN SOLA AGGIUNTA. Fino a qui un contenuto diceva di essere recuperato, ma non
-- chi lo aveva chiesto ne' per quale intervallo. Questa migrazione non
-- riscrive nulla: la colonna `acquisition_origin` della 0012 resta com'era, e
-- nessuna riga riceve un modo per valore predefinito. Il modo che si dichiara
-- si ricava dai fatti (`lisi_services::acquisition_mode`).
--
-- Un'operazione: quale monitoraggio, quale fonte, quale intervallo — vuoto per
-- il recupero fino all'inizio del monitoraggio, che ha un intervallo implicito
-- e lo dice — chi l'ha chiesta, quando, quanti messaggi trovati e quanti
-- archiviati. Non si modifica e non si cancella.
CREATE TABLE recovery_operations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    source_id     INTEGER NOT NULL,
    interval_from INTEGER,
    interval_to   INTEGER,
    requested_by  TEXT NOT NULL CHECK (length(trim(requested_by)) > 0),
    performed_at  INTEGER NOT NULL,
    found         INTEGER NOT NULL CHECK (found >= 0),
    archived      INTEGER NOT NULL CHECK (archived >= 0 AND archived <= found),
    -- Un intervallo o c'e' tutto, o non c'e'.
    CHECK ((interval_from IS NULL) = (interval_to IS NULL)),
    CHECK (interval_to IS NULL OR interval_to > interval_from)
);

CREATE INDEX recovery_operations_by_session ON recovery_operations (session_id, performed_at);

CREATE TRIGGER recovery_operations_are_immutable
    BEFORE UPDATE ON recovery_operations
BEGIN
    SELECT RAISE(ABORT, 'un''operazione di recupero registrata e'' immutabile');
END;

CREATE TRIGGER recovery_operations_are_not_deleted
    BEFORE DELETE ON recovery_operations
BEGIN
    SELECT RAISE(ABORT, 'un''operazione di recupero non si cancella');
END;

-- Il legame fra un contenuto e l'operazione che lo ha portato in archivio.
--
-- Non si modifica. Segue il contenuto: se la conservazione toglie il
-- contenuto, il legame se ne va con lui, e l'operazione resta.
CREATE TABLE content_recoveries (
    content_id   INTEGER PRIMARY KEY REFERENCES contents (id) ON DELETE CASCADE,
    operation_id INTEGER NOT NULL REFERENCES recovery_operations (id) ON DELETE RESTRICT
);

CREATE INDEX content_recoveries_by_operation ON content_recoveries (operation_id);

CREATE TRIGGER content_recoveries_are_immutable
    BEFORE UPDATE ON content_recoveries
BEGIN
    SELECT RAISE(ABORT, 'il legame fra un contenuto e il suo recupero e'' immutabile');
END;

-- 0074 — Le osservazioni di profilo scelte per i documenti (PERSON-MEDIA-01
-- parte 3, ADR-0174, DEC-445).
--
-- # Che cosa registra
--
-- Ogni volta che l'operatore sceglie un'osservazione di foto, biografia e
-- stato «da riportare nei documenti», o la toglie, una riga: quale
-- osservazione, se scelta o tolta, chi e quando. La scelta in vigore e'
-- l'ultima riga di quell'osservazione; nessuna riga vuol dire non scelta.
--
-- # Perche' un registro e non una colonna
--
-- Le osservazioni non cambiano (0073). Una colonna «scelta» si dovrebbe
-- riscrivere, e chi ha scelto e quando andrebbero persi: qui restano tutti.
--
-- # Che cosa non si puo' fare
--
-- Le righe non cambiano e non si cancellano.
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE profile_media_report_marks (
    id             INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL
                       REFERENCES profile_media_observations (id) ON DELETE RESTRICT,
    chosen         INTEGER NOT NULL CHECK (chosen IN (0, 1)),
    marked_by      TEXT NOT NULL CHECK (length(trim(marked_by)) > 0),
    marked_at      INTEGER NOT NULL
);

CREATE INDEX profile_media_report_marks_by_observation
    ON profile_media_report_marks (observation_id, id);

CREATE TRIGGER profile_media_report_marks_are_immutable
    BEFORE UPDATE ON profile_media_report_marks
BEGIN
    SELECT RAISE(ABORT, 'una scelta per i documenti non cambia: se ne registra un''altra');
END;

CREATE TRIGGER profile_media_report_marks_are_not_deleted
    BEFORE DELETE ON profile_media_report_marks
BEGIN
    SELECT RAISE(ABORT, 'una scelta per i documenti non si cancella');
END;

-- 0085 — Il registro delle copie cifrate per il destinatario
-- (ENCRYPT-02, ADR-0190, DEC-474).
--
-- # Che cosa registra
--
-- Ogni copia cifrata di un pacchetto per il certificato di chi lo riceve, e
-- ogni tentativo non riuscito: quale pacchetto (il nome, mai la cartella),
-- l'impronta del suo manifest, per quale certificato (titolare e impronta),
-- quando, da chi, e l'impronta della copia (ADR-0190, decisione 5).
--
-- # Immutabile
--
-- Risponde a «che cosa è uscito da qui, per chi, e quando»: una riga non
-- cambia e non si cancella. L'audit sta nella stessa transazione.
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE recipient_copies (
    id                 INTEGER PRIMARY KEY,
    requested_by       TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    requested_at       INTEGER NOT NULL,
    -- Il nome della cartella del pacchetto, non il percorso.
    package_name       TEXT    NOT NULL
                           CHECK (length(package_name) BETWEEN 1 AND 255
                                  AND instr(package_name, '/') = 0
                                  AND instr(package_name, '\') = 0
                                  AND instr(package_name, ':') = 0),
    manifest_sha256    TEXT    NOT NULL
                           CHECK (length(manifest_sha256) = 64
                                  AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    recipient_subject  TEXT    NOT NULL
                           CHECK (length(recipient_subject) BETWEEN 1 AND 512
                                  AND instr(recipient_subject, char(10)) = 0
                                  AND instr(recipient_subject, char(13)) = 0),
    recipient_sha256   TEXT    NOT NULL
                           CHECK (length(recipient_sha256) = 64
                                  AND recipient_sha256 NOT GLOB '*[^0-9a-f]*'),
    copy_name          TEXT
                           CHECK (copy_name IS NULL
                                  OR (length(copy_name) BETWEEN 1 AND 255
                                      AND instr(copy_name, '/') = 0
                                      AND instr(copy_name, '\') = 0
                                      AND instr(copy_name, ':') = 0)),
    copy_sha256        TEXT
                           CHECK (copy_sha256 IS NULL
                                  OR (length(copy_sha256) = 64
                                      AND copy_sha256 NOT GLOB '*[^0-9a-f]*')),
    outcome            TEXT    NOT NULL CHECK (outcome IN ('cifrata', 'non_cifrata')),
    outcome_detail     TEXT,
    -- Una copia scritta ha nome e impronta; un rifiuto non li ha.
    CHECK ((outcome = 'cifrata') = (copy_name IS NOT NULL AND copy_sha256 IS NOT NULL)),
    CHECK (outcome = 'cifrata' OR (copy_name IS NULL AND copy_sha256 IS NULL)),
    -- Un rifiuto dice perche'.
    CHECK (outcome = 'cifrata'
           OR (outcome_detail IS NOT NULL AND length(trim(outcome_detail)) > 0))
);

CREATE TRIGGER recipient_copies_are_immutable
    BEFORE UPDATE ON recipient_copies
BEGIN
    SELECT RAISE(ABORT, 'una copia registrata non cambia');
END;

CREATE TRIGGER recipient_copies_are_not_deleted
    BEFORE DELETE ON recipient_copies
BEGIN
    SELECT RAISE(ABORT, 'una copia registrata non si cancella');
END;

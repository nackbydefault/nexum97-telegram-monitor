-- 0079 — La firma dell'ufficio (SIGN-01 parte 2, ADR-0181, DEC-463).
--
-- # Che cosa registra
--
-- Due cose, ciascuna con la sua tabella.
--
-- 1. **Il certificato scelto**: l'impronta SHA-256 del certificato con cui
--    firma l'ufficio, e il nome del titolare come Windows lo mostrava quando
--    e' stato scelto. Una riga sola, vuota di fabbrica, come la destinazione
--    TAXII (0078). Il certificato e la sua chiave **non stanno qui**: stanno
--    nell'archivio personale dell'utente di Windows (ADR-0181, decisione 3).
-- 2. **Le firme**: una riga per tentativo, anche quando Windows ha rifiutato
--    o la firma non si e' verificata, con chi, quando, che cosa, il solo nome
--    del file e la sua impronta, l'impronta del certificato, che cosa si sa
--    della revoca e l'esito (decisione 9).
--
-- # Che cosa non si puo' fare
--
-- La riga del certificato non si cancella: si svuota. Impronta e titolare si
-- scrivono insieme o mancano insieme. Le firme non cambiano e non si
-- cancellano. Un nome di file non e' un percorso: niente barre, niente due
-- punti.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia. Il genere `pdf` e' per la copia
-- firmata della relazione (parte 3): ammesso da subito, perche' un vincolo
-- non si allarga senza ricostruire la tabella.

CREATE TABLE signing_certificate (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    -- NULL vuol dire «nessun certificato scelto», ed e' il valore di fabbrica.
    sha256      TEXT CHECK (sha256 IS NULL
                            OR (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*')),
    subject     TEXT CHECK (subject IS NULL
                            OR (length(subject) BETWEEN 1 AND 512
                                AND instr(subject, char(10)) = 0
                                AND instr(subject, char(13)) = 0)),
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL,
    CHECK ((sha256 IS NULL) = (subject IS NULL))
);

INSERT INTO signing_certificate (id, sha256, subject, updated_at, updated_by)
VALUES (1, NULL, NULL, 0, 'sistema');

CREATE TRIGGER signing_certificate_non_si_cancella
BEFORE DELETE ON signing_certificate
BEGIN
    SELECT RAISE(ABORT, 'il certificato di firma non si cancella: si svuota');
END;

CREATE TABLE document_signatures (
    id                 INTEGER PRIMARY KEY,
    requested_by       TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    requested_at       INTEGER NOT NULL,
    kind               TEXT    NOT NULL CHECK (kind IN ('manifest', 'dizionario', 'pdf')),
    -- Il nome, non il percorso: il registro non dice dove stanno i file.
    file_name          TEXT    NOT NULL
                           CHECK (length(file_name) BETWEEN 1 AND 255
                                  AND instr(file_name, '/') = 0
                                  AND instr(file_name, '\') = 0
                                  AND instr(file_name, ':') = 0),
    file_sha256        TEXT    NOT NULL
                           CHECK (length(file_sha256) = 64
                                  AND file_sha256 NOT GLOB '*[^0-9a-f]*'),
    certificate_sha256 TEXT    NOT NULL
                           CHECK (length(certificate_sha256) = 64
                                  AND certificate_sha256 NOT GLOB '*[^0-9a-f]*'),
    -- Che cosa la postazione sapeva della revoca: soltanto per una firma fatta.
    revocation         TEXT CHECK (revocation IS NULL
                                   OR revocation IN ('non_revocato', 'non_saputo')),
    outcome            TEXT    NOT NULL CHECK (outcome IN ('firmato', 'non_firmato')),
    outcome_detail     TEXT,
    CHECK ((outcome = 'firmato') = (revocation IS NOT NULL)),
    -- Un rifiuto dice perche'.
    CHECK (outcome = 'firmato'
           OR (outcome_detail IS NOT NULL AND length(trim(outcome_detail)) > 0))
);

CREATE TRIGGER document_signatures_are_immutable
    BEFORE UPDATE ON document_signatures
BEGIN
    SELECT RAISE(ABORT, 'una firma registrata non cambia');
END;

CREATE TRIGGER document_signatures_are_not_deleted
    BEFORE DELETE ON document_signatures
BEGIN
    SELECT RAISE(ABORT, 'una firma registrata non si cancella');
END;

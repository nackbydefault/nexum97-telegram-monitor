-- 0081 — Il punteggio CVSS delle CVE (CVSS-01, ADR-0184, DEC-467).
--
-- # Che cosa registra
--
-- Per ogni CVE di una fotografia importata da qui in avanti, il punteggio
-- primario della versione di CVSS piu' recente presente nel file NVD: la
-- versione, il vettore, il punteggio di base in decimi, la severita' come NVD
-- la scrive, la fonte che l'ha assegnato (ADR-0184, decisione 2).
--
-- # Perche' una tabella a parte
--
-- `cve_records` non porta punteggi, e il dominio della CVE nemmeno: il
-- punteggio vive accanto, e si legge soltanto nella scheda della CVE
-- (decisioni 1 e 3). Le fotografie importate prima restano senza.
--
-- # Che cosa non si puo' fare
--
-- Come le fotografie: non cambia e non si cancella.
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE cve_scores (
    snapshot_id INTEGER NOT NULL REFERENCES cve_snapshots (id) ON DELETE RESTRICT,
    cve_id      TEXT    NOT NULL CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*'),
    version     TEXT    NOT NULL CHECK (version IN ('2.0', '3.0', '3.1', '4.0')),
    vector      TEXT    NOT NULL CHECK (length(vector) BETWEEN 1 AND 255
                                        AND vector NOT GLOB '*[^A-Za-z0-9:/.()]*'),
    base_tenths INTEGER NOT NULL CHECK (base_tenths BETWEEN 0 AND 100),
    severity    TEXT    NOT NULL CHECK (length(trim(severity)) BETWEEN 1 AND 20
                                        AND severity NOT GLOB '*[' || char(10) || char(13) || ']*'),
    source      TEXT    NOT NULL CHECK (length(trim(source)) BETWEEN 1 AND 120
                                        AND source NOT GLOB '*[' || char(10) || char(13) || ']*'),
    PRIMARY KEY (snapshot_id, cve_id)
);

CREATE TRIGGER cve_scores_non_cambiano
BEFORE UPDATE ON cve_scores
BEGIN
    SELECT RAISE(ABORT, 'un punteggio di una fotografia non cambia');
END;

CREATE TRIGGER cve_scores_non_si_cancellano
BEFORE DELETE ON cve_scores
BEGIN
    SELECT RAISE(ABORT, 'un punteggio di una fotografia non si cancella');
END;

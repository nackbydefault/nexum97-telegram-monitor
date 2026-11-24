-- 0082 — Mitigazioni e rilevazioni di ATT&CK (ATTACK-03, ADR-0185, DEC-468).
--
-- # Che cosa registra
--
-- Per ogni fotografia ATT&CK importata da qui in avanti, le contromisure
-- (identificativo M) e le strategie di rilevamento (identificativo DET), con
-- nome e descrizione, e le tecniche a cui MITRE le lega (ADR-0185, decisione
-- 4). Nessun attore: gli oggetti che nominano attori si scartano come prima
-- (decisione 5).
--
-- # Che cosa non si puo' fare
--
-- Come le fotografie: non cambia e non si cancella.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE attack_guidance (
    snapshot_id INTEGER NOT NULL REFERENCES attack_snapshots (id) ON DELETE RESTRICT,
    guidance_id TEXT    NOT NULL CHECK (guidance_id GLOB 'M[0-9][0-9][0-9][0-9]'
                                        OR guidance_id GLOB 'DET[0-9][0-9][0-9][0-9]'),
    kind        TEXT    NOT NULL CHECK (kind IN ('mitigazione', 'rilevazione')),
    name        TEXT    NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    description TEXT    NOT NULL CHECK (length(description) <= 20000),
    CHECK ((kind = 'mitigazione') = (guidance_id GLOB 'M*')),
    PRIMARY KEY (snapshot_id, guidance_id)
);

CREATE TABLE attack_guidance_techniques (
    snapshot_id  INTEGER NOT NULL,
    guidance_id  TEXT    NOT NULL,
    technique_id TEXT    NOT NULL CHECK (technique_id GLOB 'T[0-9][0-9][0-9][0-9]*'),
    PRIMARY KEY (snapshot_id, guidance_id, technique_id),
    FOREIGN KEY (snapshot_id, guidance_id)
        REFERENCES attack_guidance (snapshot_id, guidance_id) ON DELETE RESTRICT
);

-- La domanda della scheda: «che cosa suggerisce ATT&CK per questa tecnica».
CREATE INDEX attack_guidance_by_technique
    ON attack_guidance_techniques (snapshot_id, technique_id);

CREATE TRIGGER attack_guidance_non_cambia
BEFORE UPDATE ON attack_guidance
BEGIN
    SELECT RAISE(ABORT, 'una mitigazione o una rilevazione di una fotografia non cambia');
END;

CREATE TRIGGER attack_guidance_non_si_cancella
BEFORE DELETE ON attack_guidance
BEGIN
    SELECT RAISE(ABORT, 'una mitigazione o una rilevazione di una fotografia non si cancella');
END;

CREATE TRIGGER attack_guidance_techniques_non_cambiano
BEFORE UPDATE ON attack_guidance_techniques
BEGIN
    SELECT RAISE(ABORT, 'un legame di una fotografia non cambia');
END;

CREATE TRIGGER attack_guidance_techniques_non_si_cancellano
BEFORE DELETE ON attack_guidance_techniques
BEGIN
    SELECT RAISE(ABORT, 'un legame di una fotografia non si cancella');
END;

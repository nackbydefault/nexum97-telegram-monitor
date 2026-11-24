-- 0069 — Il codice numerico, un quarto modo di riscontro (DICT-CODES-01,
-- ADR-0170, DEC-435).
--
-- # Perche' si ricostruisce
--
-- SQLite non consente di cambiare un vincolo CHECK: le due tabelle della 0003
-- che conservano il modo di un termine vanno ricostruite, con la procedura
-- della 0002 e della 0063. Le righe si copiano con il loro numero, e la 0003
-- non si modifica: gli archivi installati non la rieseguirebbero.
--
-- # Che cosa cambia
--
-- Il modo ammette 'numeric_code', e un vincolo nuovo lo restringe: un codice
-- numerico ha da due a dodici cifre e il livello 1. Le parole aggiunte a una
-- sola sessione (`session_custom_terms`) non cambiano: li' un codice non e'
-- ammesso, perche' un codice entra soltanto da un dizionario rivisto e
-- pubblicato.
--
-- # Che cosa resta com'era
--
-- Le colonne, l'unicita', gli indici e i divieti della 0003: i termini di una
-- versione pubblicata non si aggiungono, non si modificano e non si
-- cancellano; la fotografia di una sessione non si riscrive.

-- ------------------------------------------------------- termini dei dizionari

CREATE TABLE dictionary_terms_ricostruita (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES dictionary_versions (id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    normalised TEXT NOT NULL,
    category TEXT NOT NULL,
    language TEXT NOT NULL,
    match_mode TEXT NOT NULL CHECK (
        match_mode IN ('exact_word', 'phrase', 'normalized_word', 'numeric_code')
    ),
    suggested_level INTEGER NOT NULL CHECK (suggested_level BETWEEN -4 AND 4),
    note TEXT NOT NULL,
    -- Un codice numerico: da due a dodici cifre, livello 1.
    CHECK (
        match_mode <> 'numeric_code'
        OR (
            length(normalised) BETWEEN 2 AND 12
            AND normalised NOT GLOB '*[^0-9]*'
            AND suggested_level = 1
        )
    ),
    UNIQUE (version_id, normalised, match_mode)
);

INSERT INTO dictionary_terms_ricostruita (
    id, version_id, text, normalised, category, language, match_mode,
    suggested_level, note
)
SELECT id, version_id, text, normalised, category, language, match_mode,
    suggested_level, note
FROM dictionary_terms;

DROP TRIGGER dictionary_terms_of_published_versions_are_not_insertable;
DROP TRIGGER dictionary_terms_of_published_versions_are_immutable;
DROP TRIGGER dictionary_terms_of_published_versions_are_not_deletable;
DROP INDEX dictionary_terms_by_version;
DROP INDEX dictionary_terms_by_category;
DROP TABLE dictionary_terms;

ALTER TABLE dictionary_terms_ricostruita RENAME TO dictionary_terms;

CREATE INDEX dictionary_terms_by_version ON dictionary_terms (version_id);
CREATE INDEX dictionary_terms_by_category ON dictionary_terms (category);

CREATE TRIGGER dictionary_terms_of_published_versions_are_not_insertable
BEFORE INSERT ON dictionary_terms
WHEN (
    SELECT published_at FROM dictionary_versions WHERE id = NEW.version_id
) IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'non si aggiungono termini a una versione pubblicata');
END;

CREATE TRIGGER dictionary_terms_of_published_versions_are_immutable
BEFORE UPDATE ON dictionary_terms
WHEN (
    SELECT published_at FROM dictionary_versions WHERE id = OLD.version_id
) IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'non si modificano i termini di una versione pubblicata');
END;

CREATE TRIGGER dictionary_terms_of_published_versions_are_not_deletable
BEFORE DELETE ON dictionary_terms
WHEN (
    SELECT published_at FROM dictionary_versions WHERE id = OLD.version_id
) IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'non si cancellano i termini di una versione pubblicata');
END;

-- ---------------------------------------- fotografia dei termini di sessione

CREATE TABLE session_resolved_terms_ricostruita (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    normalised TEXT NOT NULL,
    original TEXT NOT NULL,
    category TEXT NOT NULL,
    language TEXT NOT NULL,
    match_mode TEXT NOT NULL CHECK (
        match_mode IN ('exact_word', 'phrase', 'normalized_word', 'numeric_code')
    ),
    suggested_level INTEGER NOT NULL CHECK (suggested_level BETWEEN -4 AND 4),
    provenances TEXT NOT NULL,
    CHECK (
        match_mode <> 'numeric_code'
        OR (
            length(normalised) BETWEEN 2 AND 12
            AND normalised NOT GLOB '*[^0-9]*'
            AND suggested_level = 1
        )
    ),
    UNIQUE (session_id, normalised, match_mode)
);

INSERT INTO session_resolved_terms_ricostruita (
    id, session_id, normalised, original, category, language, match_mode,
    suggested_level, provenances
)
SELECT id, session_id, normalised, original, category, language, match_mode,
    suggested_level, provenances
FROM session_resolved_terms;

DROP TRIGGER session_resolved_terms_are_immutable;
DROP TRIGGER session_resolved_terms_are_not_deletable;
DROP INDEX session_resolved_terms_by_session;
DROP TABLE session_resolved_terms;

ALTER TABLE session_resolved_terms_ricostruita RENAME TO session_resolved_terms;

CREATE INDEX session_resolved_terms_by_session ON session_resolved_terms (session_id);

CREATE TRIGGER session_resolved_terms_are_immutable
BEFORE UPDATE ON session_resolved_terms
BEGIN
SELECT RAISE(ABORT, 'la configurazione risolta di una sessione non si modifica');
END;

CREATE TRIGGER session_resolved_terms_are_not_deletable
BEFORE DELETE ON session_resolved_terms
BEGIN
SELECT RAISE(ABORT, 'la configurazione risolta di una sessione non si cancella');
END;

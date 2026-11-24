-- 0063 — Il registro delle ricerche ammette il ramo D, nei post pubblici
-- (CYBER-SEARCH-02, ADR-0161, DEC-425).
--
-- # Perche' si ricostruisce
--
-- SQLite non consente di cambiare un vincolo CHECK: la tabella della 0061 va
-- ricostruita, con la procedura della 0002. Le ricerche gia' registrate si
-- copiano con il loro numero, e la 0061 non si modifica: gli archivi
-- installati non la rieseguirebbero.
--
-- # Che cosa cambia
--
-- Soltanto il ramo: 'B', 'C' e ora 'D'. La D non indica una chat, come la B.
-- Tutto il resto e' come nella 0061, con l'indice e i due divieti: una ricerca
-- registrata non si riscrive e non si cancella.

CREATE TABLE cyber_searches_ricostruita (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    searched_by    TEXT NOT NULL CHECK (length(trim(searched_by)) > 0),
    searched_at    INTEGER NOT NULL,
    -- 'B' nelle chat dell'account, 'C' dentro una chat indicata, 'D' nei post
    -- dei canali pubblici.
    branch         TEXT NOT NULL CHECK (branch IN ('B', 'C', 'D')),
    query          TEXT NOT NULL CHECK (length(trim(query)) BETWEEN 2 AND 64),
    scope          TEXT NOT NULL CHECK (length(trim(scope)) > 0),
    -- La chat, soltanto per la C.
    chat_id        INTEGER,
    -- Quale pagina della stessa ricerca: 1 per la prima.
    page           INTEGER NOT NULL CHECK (page >= 1),
    outcome        TEXT NOT NULL CHECK (outcome IN (
        'trovati', 'nessun_risultato', 'rifiutata', 'non_riuscita')),
    results        INTEGER NOT NULL CHECK (results >= 0),
    outcome_reason TEXT NOT NULL CHECK (length(trim(outcome_reason)) > 0),
    CHECK ((branch = 'C') = (chat_id IS NOT NULL)),
    -- Risultati soltanto per «trovati».
    CHECK ((outcome = 'trovati') = (results > 0))
);

INSERT INTO cyber_searches_ricostruita (
    id, searched_by, searched_at, branch, query, scope, chat_id, page, outcome,
    results, outcome_reason
)
SELECT id, searched_by, searched_at, branch, query, scope, chat_id, page, outcome,
    results, outcome_reason
FROM cyber_searches;

DROP TRIGGER cyber_searches_are_immutable;
DROP TRIGGER cyber_searches_are_not_deleted;
DROP INDEX cyber_searches_by_time;
DROP TABLE cyber_searches;

ALTER TABLE cyber_searches_ricostruita RENAME TO cyber_searches;

CREATE INDEX cyber_searches_by_time ON cyber_searches (searched_at);

CREATE TRIGGER cyber_searches_are_immutable
    BEFORE UPDATE ON cyber_searches
BEGIN
    SELECT RAISE(ABORT, 'una ricerca registrata e'' immutabile');
END;

CREATE TRIGGER cyber_searches_are_not_deleted
    BEFORE DELETE ON cyber_searches
BEGIN
    SELECT RAISE(ABORT, 'una ricerca registrata non si cancella');
END;

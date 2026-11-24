-- 0064 — Le ricerche ricorrenti E e le loro esecuzioni (CYBER-WATCH-02,
-- ADR-0162, DEC-426).
--
-- # Che cosa registra
--
-- La DOMANDA che si ripete — parole, ramo, la chat per la C, l'intervallo — e,
-- per ogni esecuzione fatta o saltata, l'esito, quante novita', se la pagina
-- era piena, la data del messaggio piu' recente visto e la ragione. Nessun
-- testo di messaggio: le novita' si mostrano e non si conservano (ADR-0162,
-- decisione 4).
--
-- # Additiva
--
-- Due tabelle nuove; nessuna tabella esistente cambia.

CREATE TABLE recurring_searches (
    id               INTEGER PRIMARY KEY,
    -- 'B' nelle chat dell'account, 'C' dentro una chat, 'D' nei post pubblici.
    branch           TEXT NOT NULL CHECK (branch IN ('B', 'C', 'D')),
    query            TEXT NOT NULL CHECK (length(trim(query)) BETWEEN 2 AND 64),
    -- La chat, soltanto per la C.
    chat_id          INTEGER,
    -- Da un'ora a un giorno (ADR-0162, decisione 3).
    interval_minutes INTEGER NOT NULL CHECK (interval_minutes BETWEEN 60 AND 1440),
    created_by       TEXT NOT NULL CHECK (length(trim(created_by)) > 0),
    created_at       INTEGER NOT NULL,
    suspended        INTEGER NOT NULL DEFAULT 0 CHECK (suspended IN (0, 1)),
    withdrawn_by     TEXT,
    withdrawn_at     INTEGER,
    CHECK ((branch = 'C') = (chat_id IS NOT NULL)),
    -- Il ritiro: chi e quando, tutti e due o nessuno. `IS NOT NULL` esplicito:
    -- un confronto con NULL vale NULL, e un CHECK che vale NULL passa.
    CHECK ((withdrawn_by IS NULL AND withdrawn_at IS NULL)
        OR (withdrawn_by IS NOT NULL AND withdrawn_at IS NOT NULL
            AND length(trim(withdrawn_by)) > 0))
);

CREATE TRIGGER recurring_searches_definition_is_fixed
    BEFORE UPDATE OF branch, query, chat_id, interval_minutes, created_by, created_at
    ON recurring_searches
BEGIN
    SELECT RAISE(ABORT, 'una ricerca ricorrente non si riscrive: se ne salva un''altra');
END;

CREATE TRIGGER recurring_searches_withdrawal_is_final
    BEFORE UPDATE ON recurring_searches
    WHEN OLD.withdrawn_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'una ricerca ricorrente ritirata resta ritirata');
END;

CREATE TRIGGER recurring_searches_are_not_deleted
    BEFORE DELETE ON recurring_searches
BEGIN
    SELECT RAISE(ABORT, 'una ricerca ricorrente non si cancella: si ritira');
END;

CREATE TABLE recurring_search_runs (
    id                  INTEGER PRIMARY KEY,
    recurring_id        INTEGER NOT NULL
        REFERENCES recurring_searches (id) ON DELETE RESTRICT,
    ran_at              INTEGER NOT NULL,
    -- La pagina registrata fra le ricerche, se una richiesta c'e' stata.
    search_id           INTEGER REFERENCES cyber_searches (id) ON DELETE RESTRICT,
    outcome             TEXT NOT NULL CHECK (outcome IN (
        'novita', 'nessuna_novita', 'rifiutata', 'non_riuscita', 'saltata')),
    new_results         INTEGER NOT NULL CHECK (new_results >= 0),
    page_full           INTEGER NOT NULL CHECK (page_full IN (0, 1)),
    -- La data del messaggio piu' recente letto in questa esecuzione: serve a
    -- riconoscere le novita' della successiva. Non il messaggio.
    newest_published_at INTEGER,
    reason              TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    -- Saltata se e solo se nessuna richiesta e' partita.
    CHECK ((outcome = 'saltata') = (search_id IS NULL)),
    -- Novita' soltanto per «novita».
    CHECK ((outcome = 'novita') = (new_results > 0))
);

CREATE INDEX recurring_search_runs_by_recurring ON recurring_search_runs (recurring_id, ran_at);
CREATE INDEX recurring_search_runs_by_search ON recurring_search_runs (search_id);
CREATE INDEX recurring_search_runs_by_time ON recurring_search_runs (ran_at);

CREATE TRIGGER recurring_search_runs_are_immutable
    BEFORE UPDATE ON recurring_search_runs
BEGIN
    SELECT RAISE(ABORT, 'un''esecuzione registrata e'' immutabile');
END;

CREATE TRIGGER recurring_search_runs_are_not_deleted
    BEFORE DELETE ON recurring_search_runs
BEGIN
    SELECT RAISE(ABORT, 'un''esecuzione registrata non si cancella');
END;

-- 0061 — Il registro delle ricerche cyber B e C (NEXUM97-CYBER-SEARCH-01, ADR-0154).
--
-- # Che cosa registra
--
-- La RICERCA, non i suoi risultati: chi, quando, quale ramo, quali parole, su
-- quale perimetro, quanti risultati, com'e' andata. I messaggi trovati non si
-- conservano: non sono acquisizioni (ADR-0154, decisione 4), e il loro testo
-- non entra qui.
--
-- # Additiva
--
-- Una tabella nuova, in sola aggiunta; nessuna tabella esistente cambia.

CREATE TABLE cyber_searches (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    searched_by    TEXT NOT NULL CHECK (length(trim(searched_by)) > 0),
    searched_at    INTEGER NOT NULL,
    -- 'B' nelle chat dell'account, 'C' dentro una chat indicata.
    branch         TEXT NOT NULL CHECK (branch IN ('B', 'C')),
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

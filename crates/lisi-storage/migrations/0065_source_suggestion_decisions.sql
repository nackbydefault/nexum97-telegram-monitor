-- 0065 — Le decisioni sui suggerimenti di fonti (SOURCE-SUGGEST-01,
-- ADR-0164, DEC-428).
--
-- # Che cosa registra
--
-- Che cosa una persona ha deciso di un suggerimento: ignorarlo, con il motivo,
-- o aggiungerlo come fonte. Il suggerimento in se' non si conserva: si
-- ricalcola ogni volta dai contenuti acquisiti (ADR-0164, decisione 6).
--
-- # Perche' la fonte non e' una chiave esterna
--
-- Una fonte si puo' togliere dalla pagina Fonti. Una chiave esterna con
-- RESTRICT impedirebbe di toglierla; con CASCADE cancellerebbe la decisione,
-- che deve restare. Il numero resta come fatto: «quel giorno e' nata la fonte
-- con questo numero».
--
-- # Additiva
--
-- Una tabella nuova; nessuna tabella esistente cambia.

CREATE TABLE source_suggestion_decisions (
    id         INTEGER PRIMARY KEY,
    -- L'indirizzo pubblico, in minuscolo: Telegram non distingue le maiuscole.
    address    TEXT NOT NULL CHECK (length(address) BETWEEN 5 AND 32
        AND address = lower(address)),
    decision   TEXT NOT NULL CHECK (decision IN ('ignorato', 'aggiunto')),
    actor      TEXT NOT NULL CHECK (length(trim(actor)) > 0),
    reason     TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    decided_at INTEGER NOT NULL,
    -- La fonte nata dall'aggiunta.
    source_id  INTEGER,
    CHECK ((decision = 'aggiunto') = (source_id IS NOT NULL))
);

CREATE INDEX source_suggestion_decisions_by_address
    ON source_suggestion_decisions (address);

CREATE TRIGGER source_suggestion_decisions_are_immutable
    BEFORE UPDATE ON source_suggestion_decisions
BEGIN
    SELECT RAISE(ABORT, 'una decisione registrata e'' immutabile');
END;

CREATE TRIGGER source_suggestion_decisions_are_not_deleted
    BEFORE DELETE ON source_suggestion_decisions
BEGIN
    SELECT RAISE(ABORT, 'una decisione registrata non si cancella');
END;

-- 0067 — L'affidabilita' di una fonte, valutata a mano (SOURCE-RELIABILITY-01,
-- ADR-0167, DEC-432).
--
-- # Che cosa registra
--
-- Ogni atto di una persona sull'affidabilita' di una fonte: valutarla con una
-- parola, oppure ritirare la valutazione; con il motivo, chi e quando. La
-- valutazione in vigore e' l'atto piu' recente: si ricava, non si conserva.
--
-- # Perche' la fonte non e' una chiave esterna
--
-- Una fonte si puo' togliere dalla pagina Fonti, e il giudizio che l'ufficio
-- ne aveva dato deve restare: il numero resta come fatto.
--
-- # Additiva
--
-- Una tabella nuova; nessuna tabella esistente cambia.

CREATE TABLE source_reliability_entries (
    id        INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL CHECK (source_id > 0),
    -- Parole, non numeri.
    act       TEXT NOT NULL CHECK (act IN (
        'affidabile', 'da_verificare', 'poco_affidabile', 'ritirata')),
    reason    TEXT NOT NULL CHECK (length(trim(reason)) >= 20),
    actor     TEXT NOT NULL CHECK (length(trim(actor)) > 0),
    acted_at  INTEGER NOT NULL
);

CREATE INDEX source_reliability_entries_by_source
    ON source_reliability_entries (source_id, acted_at);

CREATE TRIGGER source_reliability_entries_are_immutable
    BEFORE UPDATE ON source_reliability_entries
BEGIN
    SELECT RAISE(ABORT, 'un atto sull''affidabilita'' di una fonte e'' immutabile');
END;

CREATE TRIGGER source_reliability_entries_are_not_deleted
    BEFORE DELETE ON source_reliability_entries
BEGIN
    SELECT RAISE(ABORT, 'un atto sull''affidabilita'' di una fonte non si cancella');
END;

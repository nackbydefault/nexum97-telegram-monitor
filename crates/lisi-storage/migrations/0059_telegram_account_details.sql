-- 0059 — Ciò che Telegram dice di un account (NEXUM97-IDENTITY-02, ADR-0153, DG-07).
--
-- # Che cosa aggiunge
--
-- Alla Ricerca puntuale: nome e cognome separati, TUTTI gli username attivi e
-- il telefono MASCHERATO, quando Telegram lo restituisce. Una tabella nuova per
-- le letture dell'account d'ufficio (`getMe`).
--
-- # Che cosa NON fa
--
-- Non riscrive nessuna riga. `identity_resolutions` e' in sola aggiunta, e le
-- colonne nuove valgono NULL per le ricerche gia' registrate: NULL si legge
-- «non registrato allora», mai «Telegram non l'ha dato».
--
-- # Il telefono pieno non entra
--
-- Il vincolo sulla colonna rifiuta una forma con piu' di due cifre in chiaro:
-- e' la stessa regola di `MaskedPhoneNumber`, ripetuta nello schema perche'
-- un errore nel codice non diventi un numero conservato.

ALTER TABLE identity_resolutions ADD COLUMN found_first_name TEXT;
ALTER TABLE identity_resolutions ADD COLUMN found_last_name TEXT;
-- Gli username attivi, separati da uno spazio: uno username non ne contiene.
ALTER TABLE identity_resolutions ADD COLUMN found_usernames TEXT;
ALTER TABLE identity_resolutions ADD COLUMN found_phone_masked TEXT CHECK (
    found_phone_masked IS NULL
    OR length(found_phone_masked) - length(
        replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
            found_phone_masked, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''),
            '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
    ) <= 2
);

CREATE TABLE office_account_reads (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Chi l'ha chiesta, e quando. Si chiede soltanto su comando.
    read_by          TEXT NOT NULL CHECK (length(trim(read_by)) > 0),
    read_at          INTEGER NOT NULL,
    -- 'letto': Telegram ha risposto con l'account; 'non_letto': la richiesta
    -- non e' arrivata a una risposta, e `outcome_reason` dice perche'.
    outcome          TEXT NOT NULL CHECK (outcome IN ('letto', 'non_letto')),
    outcome_reason   TEXT NOT NULL CHECK (length(trim(outcome_reason)) > 0),
    telegram_id      INTEGER,
    first_name       TEXT,
    last_name        TEXT,
    usernames        TEXT,
    phone_masked     TEXT CHECK (
        phone_masked IS NULL
        OR length(phone_masked) - length(
            replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
                phone_masked, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''),
                '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
        ) <= 2
    ),
    -- I dati ci sono tutti e soltanto per una lettura riuscita.
    CHECK ((outcome = 'letto') = (telegram_id IS NOT NULL)),
    CHECK (outcome = 'letto' OR (first_name IS NULL AND last_name IS NULL
        AND usernames IS NULL AND phone_masked IS NULL))
);

CREATE INDEX office_account_reads_by_time ON office_account_reads (read_at);

CREATE TRIGGER office_account_reads_are_immutable
    BEFORE UPDATE ON office_account_reads
BEGIN
    SELECT RAISE(ABORT, 'una lettura dell''account d''ufficio registrata e'' immutabile');
END;

CREATE TRIGGER office_account_reads_are_not_deleted
    BEFORE DELETE ON office_account_reads
BEGIN
    SELECT RAISE(ABORT, 'una lettura dell''account d''ufficio non si cancella');
END;

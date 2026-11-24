-- 0060 — Note e riferimenti del soggetto (NEXUM97-IDENTITY-02, ADR-0153, DG-08).
--
-- # Perche' una tabella propria
--
-- Le note di NOTE-01 non ammettono il genere «soggetto», e cambiarne il vincolo
-- in SQLite vuol dire ricostruire `notes`, copiando ogni nota di ogni archivio
-- installato. Il rischio non vale il guadagno: le note di un soggetto stanno
-- sulla sua scheda. Questa migrazione AGGIUNGE e non tocca nulla di esistente.
--
-- # Una riga e' una nota o un riferimento
--
-- Una nota: parole non vuote. Un riferimento: a un contenuto, una fonte o un
-- rapporto dell'archivio, per numero, oppure a un documento esterno, per la sua
-- indicazione; con la ragione, almeno venti caratteri.
--
-- # Sola aggiunta
--
-- Nessuna riga si cancella, il testo non si riscrive, il ritiro porta chi,
-- quando e perche', e non si annulla.

CREATE TABLE person_entries (
    id             INTEGER PRIMARY KEY,
    person_id      INTEGER NOT NULL REFERENCES persons (id) ON DELETE RESTRICT,
    entry_kind     TEXT NOT NULL CHECK (entry_kind IN ('nota', 'riferimento')),
    -- La nota, o per un riferimento la sua ragione.
    body           TEXT NOT NULL CHECK (length(trim(body)) > 0),
    ref_kind       TEXT CHECK (ref_kind IS NULL
        OR ref_kind IN ('contenuto', 'fonte', 'rapporto', 'documento')),
    ref_target_id  INTEGER CHECK (ref_target_id IS NULL OR ref_target_id > 0),
    ref_document   TEXT CHECK (ref_document IS NULL OR length(trim(ref_document)) > 0),
    written_by     TEXT NOT NULL CHECK (length(trim(written_by)) > 0),
    written_at     INTEGER NOT NULL,
    withdrawn_by   TEXT,
    withdrawn_at   INTEGER,
    withdrawal_reason TEXT,
    -- Una nota non riferisce nulla.
    CHECK (entry_kind = 'riferimento' OR (ref_kind IS NULL AND ref_target_id IS NULL
        AND ref_document IS NULL)),
    -- Un riferimento ha un genere, e una ragione di almeno venti caratteri.
    CHECK (entry_kind = 'nota' OR (ref_kind IS NOT NULL AND length(trim(body)) >= 20)),
    -- Un documento esterno si indica a parole; il resto con un numero.
    CHECK (ref_kind IS NULL
        OR (ref_kind = 'documento' AND ref_document IS NOT NULL AND ref_target_id IS NULL)
        OR (ref_kind <> 'documento' AND ref_target_id IS NOT NULL AND ref_document IS NULL)),
    -- Il ritiro: tutto o niente, con una ragione di almeno venti caratteri.
    -- `IS NOT NULL` esplicito: un confronto con NULL vale NULL, e un CHECK che
    -- vale NULL passa. Trovato da una prova negativa.
    CHECK ((withdrawn_by IS NULL AND withdrawn_at IS NULL AND withdrawal_reason IS NULL)
        OR (withdrawn_by IS NOT NULL AND withdrawn_at IS NOT NULL
            AND withdrawal_reason IS NOT NULL
            AND length(trim(withdrawal_reason)) >= 20))
);

CREATE INDEX person_entries_by_person ON person_entries (person_id, written_at);

CREATE TRIGGER person_entries_are_written_once
    BEFORE UPDATE OF person_id, entry_kind, body, ref_kind, ref_target_id, ref_document,
        written_by, written_at ON person_entries
BEGIN
    SELECT RAISE(ABORT, 'una voce del soggetto non si riscrive: si ritira e se ne scrive un''altra');
END;

CREATE TRIGGER person_entries_withdrawal_stays
    BEFORE UPDATE ON person_entries
    WHEN OLD.withdrawn_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'un ritiro non si annulla e non si ripete');
END;

CREATE TRIGGER person_entries_are_never_deleted
    BEFORE DELETE ON person_entries
BEGIN
    SELECT RAISE(ABORT, 'una voce del soggetto non si cancella: si ritira, e resta visibile');
END;

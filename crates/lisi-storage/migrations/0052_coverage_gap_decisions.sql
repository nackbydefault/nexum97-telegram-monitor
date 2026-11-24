-- PR-06, ADR-0122: le decisioni sui periodi non coperti prioritari.
--
-- IN SOLA AGGIUNTA. Una riga registra il periodo come e' stato riconosciuto —
-- la fonte, l'inizio, la fine, la priorita' e la versione del criterio che
-- l'ha data — e la decisione di una persona, con il motivo, chi e quando.
--
-- La fonte e' un intero grezzo e non una chiave esterna, come nell'audit: la
-- decisione deve sopravvivere alla rimozione della fonte, e una chiave esterna
-- la impedirebbe o la cancellerebbe.
--
-- La priorita' e' TECNICA: dice dove guardare per primo quando si valuta un
-- recupero, e non dice che nel periodo la fonte abbia pubblicato qualcosa.
CREATE TABLE coverage_gap_decisions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id         INTEGER NOT NULL,
    gap_from          INTEGER NOT NULL,
    gap_to            INTEGER NOT NULL CHECK (gap_to > gap_from),
    priority          TEXT NOT NULL CHECK (priority IN ('alta', 'media', 'bassa')),
    criterion_version INTEGER NOT NULL CHECK (criterion_version >= 1),
    decision          TEXT NOT NULL CHECK (decision IN (
        'da_valutare_per_recupero', 'dichiarato_non_coperto')),
    reason            TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    decided_by        TEXT NOT NULL,
    decided_at        INTEGER NOT NULL
);

CREATE INDEX coverage_gap_decisions_by_period
    ON coverage_gap_decisions (source_id, gap_from, gap_to);

CREATE TRIGGER coverage_gap_decisions_are_immutable
    BEFORE UPDATE ON coverage_gap_decisions
BEGIN
    SELECT RAISE(ABORT, 'una decisione su un periodo non coperto e'' immutabile');
END;

CREATE TRIGGER coverage_gap_decisions_are_not_deleted
    BEFORE DELETE ON coverage_gap_decisions
BEGIN
    SELECT RAISE(ABORT, 'una decisione su un periodo non coperto non si cancella');
END;

-- Migrazione 0002 - ammette il tipo di fonte "supergroup".
--
-- La piattaforma tratta il supergruppo come entita' distinta dal gruppo, con
-- un proprio intervallo di identificativi. Fonderli perderebbe informazione
-- utile a ricondurre un contenuto alla sua origine.
--
-- SQLite non consente di modificare un vincolo CHECK: la tabella va
-- ricostruita. La procedura seguita e' quella raccomandata dalla
-- documentazione di SQLite per una modifica di schema in presenza di foreign
-- key. Il runner disattiva l'applicazione delle foreign key per la durata
-- delle migrazioni e la riattiva dopo, verificando con PRAGMA
-- foreign_key_check che nessun riferimento sia rimasto pendente.
--
-- La migrazione 0001 NON e' stata modificata: i database esistenti non la
-- rieseguirebbero e divergerebbero in silenzio da quelli nuovi.

CREATE TABLE sources_ricostruita (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('channel', 'group', 'supergroup')),
    identifier TEXT NOT NULL,
    display_name TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (kind, identifier)
);

-- Gli identificatori sono conservati: le righe di session_sources, contents e
-- faults che vi fanno riferimento restano valide.
INSERT INTO sources_ricostruita (
    id, kind, identifier, display_name, authorized_by, active, created_at, updated_at
)
SELECT id, kind, identifier, display_name, authorized_by, active, created_at, updated_at
FROM sources;

DROP TABLE sources;

ALTER TABLE sources_ricostruita RENAME TO sources;

-- Cio' che l'ufficio scrive insieme, sull'Hub.
--
-- Motivata in ADR-0099 e DEC-338 (TEAM-WS-01).
--
-- ===========================================================================
-- NON E' LA COPIA DI `notes` E `workspaces`.
--
-- Quelle sono di una postazione sola (NOTE-01, WS-01) e restano sue. Queste
-- sono dell'ufficio, e vivono dove vive l'autorita': sincronizzare due
-- archivi che scrivono entrambi vorrebbe dire decidere chi vince, e «vince
-- chi ha scritto per ultimo» e' cio' che questo prodotto rifiuta da ADR-0089.
--
-- ===========================================================================
-- UNA NOTA SI SCRIVE E SI RITIRA. NON SI RISCRIVE E NON SI CANCELLA.
--
-- E' la stessa regola della nota locale, moltiplicata: una nota riscritta
-- cancella cio' che qualcun altro aveva gia' letto, e su un Hub quel qualcun
-- altro esiste davvero. Il trigger vale anche per chi scrivesse un secondo
-- servizio domani.
--
-- ===========================================================================
-- L'AUTORE E' UNA PERSONA.
--
-- Non una postazione: una nota e' PAROLE DI QUALCUNO, e senza un autore
-- verificato e' un foglietto anonimo lasciato sulla scrivania di tutti
-- (ADR-0099, decisione 3). La colonna porta `persona.<id>` gia' composto,
-- perche' e' cosi' che l'atto si legge.
--
-- ===========================================================================
-- QUI NON C'E' IL TESTO DI UN CONTENUTO.
--
-- `body` sono le parole di chi annota. Il riferimento e' polimorfico e senza
-- chiave esterna, come in `notes`: un riferimento puo' restare appeso, e chi
-- legge riceve la dichiarazione invece del silenzio.

CREATE TABLE hub_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Su che cosa. 'segnalibro' NON e' ammesso: un segnalibro e' esso stesso
    -- un riferimento, e una nota su di lui sarebbe una nota sul dito.
    kind        TEXT NOT NULL CHECK (
        kind IN ('fonte', 'contenuto', 'rapporto', 'workspace')
    ),
    target_id   INTEGER NOT NULL,
    -- Le parole di chi annota. Mai vuote.
    body        TEXT NOT NULL CHECK (length(trim(body)) > 0),
    -- L'identificativo della persona che l'ha scritta.
    author      TEXT NOT NULL,
    written_at  INTEGER NOT NULL,
    -- Il ritiro: chi e quando, insieme o nessuno dei due.
    withdrawn_by TEXT,
    withdrawn_at INTEGER,

    CHECK (
        (withdrawn_by IS NULL AND withdrawn_at IS NULL)
        OR (withdrawn_by IS NOT NULL AND withdrawn_at IS NOT NULL)
    )
);

CREATE INDEX hub_notes_by_target ON hub_notes (kind, target_id, id);

-- IL TESTO DI UNA NOTA CONDIVISA NON SI RISCRIVE.
--
-- Il vincolo non e' contro la malafede: e' contro la cosa normale, cioe'
-- qualcuno che «corregge un refuso» e senza volerlo fa dire all'autore e
-- all'istante una cosa falsa a chi l'aveva gia' letta.
CREATE TRIGGER hub_notes_text_is_written_once
    BEFORE UPDATE OF body, kind, target_id, author, written_at ON hub_notes
BEGIN
    SELECT RAISE(ABORT, 'una nota condivisa non si riscrive: si ritira e se ne scrive un''altra');
END;

-- UNA NOTA CONDIVISA NON SI CANCELLA.
--
-- Ritirare e' un atto che lascia una traccia; cancellare non lascia niente, e
-- una riga sparita si legge come una riga mai esistita.
CREATE TRIGGER hub_notes_are_never_deleted
    BEFORE DELETE ON hub_notes
BEGIN
    SELECT RAISE(ABORT, 'una nota condivisa non si cancella: si ritira');
END;

-- UN RITIRO NON SI ANNULLA.
CREATE TRIGGER hub_notes_withdrawal_is_final
    BEFORE UPDATE OF withdrawn_by, withdrawn_at ON hub_notes
    WHEN OLD.withdrawn_by IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'una nota condivisa gia'' ritirata non torna indietro');
END;

-- ===========================================================================
-- I RACCOGLITORI DELL'UFFICIO.
--
-- Chiudere NON cancella: smette di accettare elementi. Un raccoglitore che si
-- svuotasse chiudendosi perderebbe il lavoro di chi l'ha riempito.

CREATE TABLE hub_workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    state       TEXT NOT NULL CHECK (state IN ('aperto', 'chiuso')),
    opened_by   TEXT NOT NULL,
    opened_at   INTEGER NOT NULL,
    closed_by   TEXT,
    closed_at   INTEGER,

    CHECK (length(trim(name)) > 0),
    CHECK (
        (state = 'aperto' AND closed_by IS NULL AND closed_at IS NULL)
        OR (state = 'chiuso' AND closed_by IS NOT NULL AND closed_at IS NOT NULL)
    )
);

-- Due raccoglitori APERTI non possono avere lo stesso nome: chi ne cerca uno
-- non deve doverne scegliere uno fra due. Chiusi si', perche' il nome di un
-- lavoro finito puo' tornare.
CREATE UNIQUE INDEX hub_workspaces_open_name
    ON hub_workspaces (name) WHERE state = 'aperto';

CREATE TABLE hub_workspace_items (
    workspace_id INTEGER NOT NULL REFERENCES hub_workspaces (id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (
        kind IN ('fonte', 'contenuto', 'rapporto', 'segnalibro')
    ),
    target_id    INTEGER NOT NULL,
    added_by     TEXT NOT NULL,
    added_at     INTEGER NOT NULL,

    PRIMARY KEY (workspace_id, kind, target_id)
);

CREATE INDEX hub_workspace_items_by_workspace
    ON hub_workspace_items (workspace_id, added_at);

-- UN RACCOGLITORE CHIUSO NON ACCETTA PIU' ELEMENTI.
--
-- Il rifiuto sta qui e non solo nel servizio: vale anche per chi scrivesse un
-- secondo servizio domani.
CREATE TRIGGER hub_workspace_items_need_an_open_workspace
    BEFORE INSERT ON hub_workspace_items
    WHEN (SELECT state FROM hub_workspaces WHERE id = NEW.workspace_id) <> 'aperto'
BEGIN
    SELECT RAISE(ABORT, 'un raccoglitore chiuso non accetta piu'' elementi');
END;

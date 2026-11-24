-- Workspace operativi (WS-01).
--
-- # Che cos'e' un workspace, e che cosa NON e'
--
-- E' un contenitore logico di lavoro: un posto dove una persona raccoglie cio'
-- di cui si sta occupando. NON e' il «fascicolo» condivisibile di TM-01, che e'
-- una configurazione; e NON e' un archivio.
--
-- # La regola che governa tutto: RIFERISCE SENZA COPIARE
--
-- Il congelamento lo scrive due volte, per il workspace e per i segnalibri:
-- «riferisce senza copiare», «riferimenti a materiale esistente, mai copie
-- della prova».
--
-- Il modo di rispettarla non e' ricordarsene: e' che in `workspace_items` NON
-- ESISTA UNA COLONNA in cui una copia possa stare. Non c'e' un `body`, non c'e'
-- un `testo`, non c'e' un `titolo`, non c'e' un'anteprima. C'e' che cosa e
-- quale, e nient'altro.
--
-- Ne segue la proprieta' che serve davvero: cio' che un workspace mostra e'
-- sempre cio' che l'archivio dice ADESSO. Non puo' divergere, perche' non ha
-- una seconda copia da cui divergere.
--
-- # Perche' il riferimento e' polimorfico e quindi SENZA chiave esterna
--
-- Il congelamento elenca otto generi di cosa referenziabile: fonti, contenuti,
-- persone, CyberEvent, segnalibri, note, ricerche salvate, rapporti. Cinque di
-- essi NON ESISTONO ancora — arrivano con PERS-01, BOOK-01, NOTE-01 e
-- SEARCH-01.
--
-- Una tabella di collegamento per genere avrebbe una chiave esterna vera, ma
-- richiederebbe di creare tabelle che puntano a tabelle inesistenti. Un
-- riferimento polimorfico — genere piu' identificativo — non puo' avere una
-- chiave esterna.
--
-- IL COSTO E' DICHIARATO, NON NASCOSTO: un riferimento puo' restare appeso, se
-- cio' a cui punta viene cancellato. Chi legge un workspace riceve, per ogni
-- riferimento, o la cosa risolta o la dichiarazione che non e' piu'
-- nell'archivio. Mai il silenzio.
--
-- # Perche' un workspace chiuso rifiuta nuovi elementi
--
-- Perche' altrimenti lo stato del ciclo di vita sarebbe una decorazione. Il
-- rifiuto e' dell'archivio, con un trigger: non e' una regola che un servizio
-- deve ricordarsi di applicare.

CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY,
    -- Il nome con cui le persone lo chiamano.
    name TEXT NOT NULL,
    -- A che cosa serve. Facoltativa: un contenitore appena aperto puo' non
    -- avere ancora una descrizione, e obbligarla produrrebbe descrizioni finte.
    description TEXT,
    -- 'aperto' oppure 'chiuso'.
    state TEXT NOT NULL CHECK (state IN ('aperto', 'chiuso')),
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    -- Chi lo ha chiuso e quando. NULL insieme o valorizzati insieme: un
    -- workspace chiuso da nessuno, o chiuso in nessun istante, sarebbe un
    -- ciclo di vita a meta'.
    closed_by TEXT,
    closed_at INTEGER,
    CHECK (
        (state = 'aperto' AND closed_by IS NULL AND closed_at IS NULL)
        OR (state = 'chiuso' AND closed_by IS NOT NULL AND closed_at IS NOT NULL)
    )
);

-- DUE WORKSPACE APERTI NON POSSONO CHIAMARSI ALLO STESSO MODO.
--
-- Chi lavora li chiama per nome, e due contenitori aperti con lo stesso nome
-- sono una trappola: si mette una cosa nell'uno credendo di metterla
-- nell'altro.
--
-- Il vincolo vale SOLO fra quelli aperti: un nome tornato libero dopo la
-- chiusura puo' essere riusato, ed e' giusto — «Indagine marzo» chiusa non
-- impedisce «Indagine marzo» dell'anno dopo.
CREATE UNIQUE INDEX workspaces_open_names_are_unique
    ON workspaces (name)
    WHERE state = 'aperto';

-- I riferimenti raccolti in un workspace.
--
-- # Che cosa questa tabella NON ha
--
-- Nessuna colonna di testo per il materiale referenziato. Vedere sopra.
CREATE TABLE workspace_items (
    workspace_id INTEGER NOT NULL REFERENCES workspaces (id) ON DELETE RESTRICT,
    -- Che genere di cosa. I generi ammessi sono quelli che ESISTONO: aggiungere
    -- qui un genere che nulla puo' produrre sarebbe una capacita' costruita e
    -- mai raggiungibile, ed e' il debito che questo progetto ha gia' pagato una
    -- volta.
    kind TEXT NOT NULL CHECK (kind IN ('fonte', 'contenuto', 'rapporto')),
    -- Quale. Senza chiave esterna: il riferimento e' polimorfico, e il costo e'
    -- dichiarato sopra.
    target_id INTEGER NOT NULL,
    added_by TEXT NOT NULL,
    added_at INTEGER NOT NULL,
    -- La stessa cosa non si raccoglie due volte nello stesso workspace: due
    -- righe identiche non direbbero nulla di piu', e chi legge conterebbe due
    -- volte lo stesso oggetto.
    PRIMARY KEY (workspace_id, kind, target_id)
);

CREATE INDEX workspace_items_by_target ON workspace_items (kind, target_id);

-- UN WORKSPACE CHIUSO NON ACCETTA NUOVI ELEMENTI.
--
-- E' l'archivio a rifiutare, non un servizio che deve ricordarsene: uno stato
-- del ciclo di vita che non impedisce nulla e' una decorazione.
CREATE TRIGGER workspace_items_refuse_a_closed_workspace
    BEFORE INSERT ON workspace_items
    WHEN (SELECT state FROM workspaces WHERE id = NEW.workspace_id) = 'chiuso'
BEGIN
    SELECT RAISE(ABORT, 'un workspace chiuso non accetta nuovi elementi');
END;

-- E NON NE PERDE.
--
-- Togliere qualcosa da un contenitore chiuso cambierebbe che cosa quel lavoro
-- conteneva, dopo che lo si e' dichiarato concluso.
CREATE TRIGGER workspace_items_of_a_closed_workspace_stay
    BEFORE DELETE ON workspace_items
    WHEN (SELECT state FROM workspaces WHERE id = OLD.workspace_id) = 'chiuso'
BEGIN
    SELECT RAISE(ABORT, 'un workspace chiuso non perde elementi');
END;

-- UN WORKSPACE CHIUSO NON SI RIAPRE.
--
-- Riaprirlo renderebbe la chiusura una parentesi invece di un fatto, e cio' che
-- si e' scritto «concluso il ...» tornerebbe in lavorazione senza che nulla lo
-- dica. Se serve continuare, se ne apre un altro: due contenitori raccontano
-- due periodi, uno solo riscritto non racconta niente.
CREATE TRIGGER workspaces_do_not_reopen
    BEFORE UPDATE OF state ON workspaces
    WHEN OLD.state = 'chiuso' AND NEW.state = 'aperto'
BEGIN
    SELECT RAISE(ABORT, 'un workspace chiuso non si riapre');
END;

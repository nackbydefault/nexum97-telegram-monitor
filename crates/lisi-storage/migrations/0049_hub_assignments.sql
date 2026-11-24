-- A chi e' il lavoro, sull'Hub.
--
-- Motivata in ADR-0098 e DEC-336 (TEAM-ASSIGN-01).
--
-- ===========================================================================
-- UN FATTO PER CONTENUTO, E LA SUA STORIA ACCANTO.
--
-- `hub_assignments` dice a chi e' un contenuto ADESSO: una riga per
-- contenuto, che si sovrascrive. `hub_assignment_log` dice come ci si e'
-- arrivati, e non si tocca piu'.
--
-- Servono tutte e due. Senza la prima, sapere a chi e' un contenuto
-- vorrebbe dire rileggere tutta la storia a ogni riga della coda. Senza la
-- seconda, una riassegnazione cancellerebbe chi ce l'aveva prima, e
-- «assegnato a nessuno» non si distinguerebbe da «mai assegnato».
--
-- ===========================================================================
-- LA VERSIONE E' QUANTI CAMBI SONO STATI FATTI.
--
-- E' la stessa forma della revisione (ADR-0094): chi scrive dichiara la
-- versione che si aspetta, e se nel frattempo qualcun altro ha assegnato, il
-- comando riceve un CONFLITTO invece di sovrascrivere (ADR-0089, ADR-0098
-- decisione 3). La versione si legge contando le righe del registro.
--
-- ===========================================================================
-- ASSEGNARE A NESSUNO E' UN FATTO.
--
-- `assigned_to` e' NULL quando il lavoro e' stato revocato. La riga resta,
-- perche' «revocato» e «mai assegnato» sono due cose diverse e la coda deve
-- poterle distinguere.

CREATE TABLE hub_assignments (
    content_id  INTEGER PRIMARY KEY REFERENCES contents (id) ON DELETE CASCADE,
    -- L'identificativo della persona, o NULL se il lavoro e' di nessuno.
    assigned_to TEXT,
    -- Chi ha deciso: `persona.<id>` o `postazione.<id>`.
    decided_by  TEXT NOT NULL,
    decided_at  INTEGER NOT NULL
);

-- «Che cosa e' mio» e' la lettura che una persona fa piu' spesso.
CREATE INDEX hub_assignments_by_person ON hub_assignments (assigned_to);

-- Come ci si e' arrivati. Append-only: nessun UPDATE, nessun DELETE.
CREATE TABLE hub_assignment_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id  INTEGER NOT NULL REFERENCES contents (id) ON DELETE CASCADE,
    -- A chi e' passato, o NULL per una revoca.
    assigned_to TEXT,
    decided_by  TEXT NOT NULL,
    decided_at  INTEGER NOT NULL
);

-- La versione di un contenuto si conta di qui.
CREATE INDEX hub_assignment_log_by_content ON hub_assignment_log (content_id, id);

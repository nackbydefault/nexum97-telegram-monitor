-- I comandi che l'Hub ha gia' visto, e come sono finiti.
--
-- Motivata in ADR-0089 e DEC-327 (HUB-CMD-01), attua ADR-0042 decisione 8.
--
-- ===========================================================================
-- LA CHIAVE E' (DISPOSITIVO, IDENTIFICATIVO), NON L'IDENTIFICATIVO.
--
-- Il proof of concept lo ha MISURATO (ADR-0044, misura 2): con identificativi
-- scelti liberamente dai client, due che ne scelgono uno uguale si vedono
-- restituire l'esito dell'altro, e il proprio comando NON viene eseguito.
--
-- La decisione 8 di ADR-0042 dipende quindi dalla decisione 2 - l'identita' del
-- dispositivo - e le due non si possono realizzare in ordine inverso. Qui la
-- dipendenza e' scritta come vincolo: UNIQUE sulla COPPIA.
--
-- ===========================================================================
-- L'ESITO SI CONSERVA PERCHE' UNA RIPETIZIONE LO RICEVE.
--
-- Un comando gia' visto non si riesegue: si restituisce l'esito di allora. Per
-- farlo bisogna averlo conservato, e conservarlo nella STESSA transazione
-- dell'effetto - altrimenti esisterebbe un istante in cui l'effetto c'e' e la
-- memoria no, e una ripetizione in quell'istante raddoppierebbe.
--
-- ===========================================================================
-- APPEND-ONLY.
--
-- Un esito riscritto e' una risposta diversa alla stessa domanda: il client che
-- ripete riceverebbe qualcosa che non e' mai successo.

CREATE TABLE hub_commands (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      TEXT NOT NULL,
    command_id     TEXT NOT NULL,
    -- 'eseguito' oppure 'rifiutato'.
    outcome_kind   TEXT NOT NULL,
    outcome_detail TEXT,
    recorded_at    INTEGER NOT NULL,

    UNIQUE (device_id, command_id),
    CHECK (outcome_kind IN ('eseguito', 'rifiutato')),
    -- Un rifiuto senza ragione manderebbe a indovinare.
    CHECK (outcome_kind = 'eseguito' OR outcome_detail IS NOT NULL)
);

CREATE INDEX hub_commands_by_time ON hub_commands (recorded_at);

CREATE TRIGGER hub_commands_refuses_update
BEFORE UPDATE ON hub_commands
BEGIN
SELECT RAISE(ABORT, 'esiti dei comandi append-only: la modifica non e'' ammessa');
END;

CREATE TRIGGER hub_commands_refuses_delete
BEFORE DELETE ON hub_commands
BEGIN
SELECT RAISE(ABORT, 'esiti dei comandi append-only: la cancellazione non e'' ammessa');
END;

-- Un monitoraggio interrotto, e cio' che NON e'.
--
-- Motivata in ADR-0064 e DEC-299.
--
-- ===========================================================================
-- PERCHE' UNA TABELLA E NON UNA VARIANTE DI STATO.
--
-- `sessions.state` racconta CIO' CHE LE PERSONE HANNO DECISO: pianificata, in
-- corso, sospesa, conclusa per durata, ARRESTATA DALL'OPERATORE. Sono tutti
-- atti, o conseguenze dichiarate di un atto.
--
-- Un arresto anomalo non e' un atto di nessuno: e' qualcosa che e' successo al
-- programma. Metterlo in quell'enumerazione farebbe raccontare alla storia
-- delle decisioni una cosa che non e' una decisione, e da quel momento nessuno
-- potrebbe piu' distinguere le due specie di riga.
--
-- E portare la sessione ad 'arrestata' all'avvio sarebbe peggio: scriverebbe
-- «arrestata DALL'OPERATORE» su un atto che l'operatore non ha compiuto.
--
-- LO STATO DELLA SESSIONE NON SI TOCCA. Resta 'in corso', che e' vero — nessuno
-- l'ha fermata — e accanto c'e' scritto che il processo che la osservava non
-- c'e' piu'.

-- ---------------------------------------------------------------------------
-- Il fatto.
--
-- UNA RIGA PER SESSIONE INTERROTTA, e non una per riapertura: riaprire dieci
-- volte non produce dieci righe, perche' il fatto e' uno solo. Lo garantisce la
-- chiave primaria, non il codice che scrive.
CREATE TABLE session_interruptions (
    -- La sessione che risultava in corso.
    session_id INTEGER PRIMARY KEY REFERENCES sessions (id) ON DELETE RESTRICT,
    -- Quando questa postazione se n'e' accorta: l'avvio del processo che ha
    -- trovato la riga. E' un istante MISURATO da questa macchina.
    noticed_at INTEGER NOT NULL,
    -- Da quando non si stava piu' guardando.
    gap_start_at INTEGER NOT NULL,
    -- Da dove viene quell'istante: 'ultimo_contenuto' oppure 'avvio'.
    --
    -- QUALE DEI DUE CAMBIA CIO' CHE SI PUO' DIRE, e un istante solo li
    -- confonderebbe: la frase che ne uscirebbe sarebbe piu' precisa di quanto
    -- il prodotto sappia. Se la sessione non aveva acquisito nulla non si
    -- inventa un istante, si dichiara da dove viene quello che si ha.
    gap_start_origin TEXT NOT NULL CHECK (gap_start_origin IN ('ultimo_contenuto', 'avvio')),
    -- Quando l'operatore l'ha presa in carico, se l'ha fatto.
    --
    -- CIO' CHE E' STATO VISTO RESTA IN ARCHIVIO: sparisce l'avviso, non il
    -- fatto. Un avviso che riappare a ogni avvio e' un avviso che si impara a
    -- chiudere senza leggerlo.
    acknowledged_at INTEGER
);

-- La domanda per cui la tabella esiste: «c'e' un'interruzione da mostrare?».
CREATE INDEX session_interruptions_open
    ON session_interruptions (acknowledged_at)
    WHERE acknowledged_at IS NULL;

-- ---------------------------------------------------------------------------
-- Il fatto non si riscrive, e non si cancella.
--
-- UN SOLO CAMPO PUO' CAMBIARE, ed e' la presa in carico. Tutto il resto
-- documenta un momento, e cio' che documenta un momento non deve poter cambiare
-- dopo: sarebbe il modo in cui un buco nell'archivio smette di risultare.
CREATE TRIGGER session_interruptions_are_immutable
    BEFORE UPDATE OF session_id, noticed_at, gap_start_at, gap_start_origin
    ON session_interruptions
BEGIN
    SELECT RAISE(ABORT, 'un''interruzione registrata e'' immutabile');
END;

CREATE TRIGGER session_interruptions_are_not_deleted
    BEFORE DELETE ON session_interruptions
BEGIN
    SELECT RAISE(ABORT, 'un''interruzione registrata non si cancella');
END;

-- La presa in carico avviene UNA VOLTA SOLA: riprenderla toglierebbe alla riga
-- l'istante in cui qualcuno l'ha davvero letta.
CREATE TRIGGER session_interruptions_are_acknowledged_once
    BEFORE UPDATE OF acknowledged_at ON session_interruptions
    WHEN OLD.acknowledged_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'un''interruzione gia'' presa in carico non si riprende');
END;

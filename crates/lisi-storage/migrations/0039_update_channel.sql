-- Il canale degli aggiornamenti di QUESTA postazione.
--
-- Motivata in ADR-0066 e DEC-302.
--
-- ===========================================================================
-- PERCHE' IL CANALE STA IN ARCHIVIO E NON IN UNA COSTANTE.
--
-- Fino a UPDATE-01 il canale era scritto nel sorgente: `Channel::Stable`. La
-- ragione era buona — finche' manca il certificato di firma non c'e' nulla di
-- pubblicato su alcun canale, e un selettore fra due canali vuoti sarebbe un
-- comando decorativo.
--
-- Ma il canale NON e' una preferenza: e' la dichiarazione che questa postazione
-- RICEVE PRIMA, ed e' la risposta a una domanda che un giorno qualcuno fara' —
-- «perche' questa macchina aveva una versione che le altre non avevano?».
--
-- Una costante non risponde. Una riga con chi l'ha scritta e quando, si'.
--
-- ===========================================================================
-- IL CANALE NON E' UN LIVELLO DI FIDUCIA.
--
-- Il pilota e' LO STESSO artefatto, firmato allo stesso modo, pubblicato prima
-- (ADR-0040). Nessuna verifica cambia con il canale, e nessuna query di questa
-- tabella deve comparire nella catena di verifica: un canale che allentasse i
-- controlli sarebbe una porta di servizio, e basterebbe convincere UNA
-- postazione a mettersi su pilota.

CREATE TABLE update_channel (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    -- 'stable' | 'pilot'.
    --
    -- LE ETICHETTE SONO QUELLE DEL MANIFESTO, non una seconda ortografia
    -- italiana: il canale viaggia gia' con questi nomi dentro il manifesto, e
    -- due vocabolari per la stessa cosa sono due vocabolari che divergono.
    --
    -- Il vincolo sta qui e non solo nel codice: un valore inventato a mano non
    -- deve poter entrare, perche' verrebbe letto come 'stable' dal dominio e
    -- la postazione crederebbe di essere dove non e'.
    choice     TEXT    NOT NULL CHECK (choice IN ('stable', 'pilot')),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL
);

-- La riga predefinita esiste da subito, cosi' chi legge non gestisce l'assenza.
--
-- Il predefinito e' STABILE (ADR-0040): una postazione nuova non riceve prima
-- perche' nessuno l'ha deciso.
INSERT INTO update_channel (id, choice, updated_at, updated_by)
VALUES (1, 'stable', 0, 'sistema');

-- ---------------------------------------------------------------------------
-- La riga non si cancella.
--
-- Non e' immutabilita': il canale SI CAMBIA, ed e' il suo scopo. Ma cancellarla
-- lascerebbe la postazione senza canale, e chi legge dovrebbe indovinare quale
-- fosse — dove «indovinare» significa, in pratica, «stabile», cioe' il
-- contrario di cio' che qualcuno aveva scelto.
CREATE TRIGGER update_channel_non_si_cancella
BEFORE DELETE ON update_channel
BEGIN
    SELECT RAISE(ABORT, 'il canale degli aggiornamenti non si cancella: si cambia');
END;

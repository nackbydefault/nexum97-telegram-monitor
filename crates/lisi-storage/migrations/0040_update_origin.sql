-- L'origine del manifesto degli aggiornamenti.
--
-- Motivata in ADR-0067 e DEC-303.
--
-- ===========================================================================
-- PERCHE' L'ORIGINE STA IN ARCHIVIO E NON NEL SORGENTE.
--
-- Da UPDATE-02 il prodotto ha una porta verso la rete. La destinazione di
-- quella porta e' UNA SOLA, e questa riga e' quella destinazione.
--
-- Scriverla nel sorgente avrebbe voluto dire inventare un indirizzo: non esiste
-- ancora nulla di pubblicato, perche' manca il certificato di firma (HVQ-07).
-- Un indirizzo inventato sarebbe un indirizzo che un giorno qualcuno contatta.
--
-- ===========================================================================
-- E PERCHE' NON PUO' VENIRE DA CONTENUTO MONITORATO.
--
-- E' la proprieta' che sostituisce la guardia forte di ADR-0048, caduta oggi.
-- Un messaggio Telegram, un profilo, un allegato, un dizionario importato o un
-- fascicolo condiviso NON devono poter diventare un indirizzo che il prodotto
-- contatta: se potessero, un canale monitorato diventerebbe il modo per far
-- parlare la postazione con chi vuole chi scrive nel canale.
--
-- L'origine si scrive qui, e qui ci arriva solo chi amministra la postazione.

CREATE TABLE update_origin (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    -- NULL significa «non configurata», ed e' il valore di fabbrica: con
    -- l'origine vuota il prodotto non ha dove andare, e lo dice invece di
    -- fingere un'origine che non risponde.
    --
    -- Il vincolo sullo schema sta qui e non solo nel codice: in chiaro, chi
    -- controlla la rete sostituisce il documento, e un'origine scritta a mano
    -- in archivio non deve poter aggirare il controllo che il codice fa.
    origin     TEXT    CHECK (origin IS NULL OR origin LIKE 'https://%'),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL
);

-- La riga predefinita esiste da subito, cosi' chi legge non gestisce l'assenza
-- della RIGA: l'unica assenza da gestire e' quella dell'ORIGINE, che e' un
-- fatto vero e non un caso limite.
INSERT INTO update_origin (id, origin, updated_at, updated_by)
VALUES (1, NULL, 0, 'sistema');

-- ---------------------------------------------------------------------------
-- La riga non si cancella.
--
-- Non e' immutabilita': l'origine SI CAMBIA. Ma cancellare la riga lascerebbe
-- il prodotto senza sapere se l'origine sia assente perche' nessuno l'ha messa
-- o perche' qualcosa e' andato storto, e sono due cose diverse.
CREATE TRIGGER update_origin_non_si_cancella
BEFORE DELETE ON update_origin
BEGIN
    SELECT RAISE(ABORT, 'l''origine degli aggiornamenti non si cancella: si svuota');
END;

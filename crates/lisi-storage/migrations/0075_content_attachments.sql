-- 0075 — La descrizione dell'allegato di un contenuto (ATTACH-01, ADR-0177,
-- DEC-451).
--
-- # Che cosa registra
--
-- Una riga per contenuto che porta un allegato: il genere, e cio' che il
-- mittente dichiara (nome, dimensione, tipo). Nessun byte: l'allegato non si
-- scarica all'acquisizione.
--
-- # Cio' che il mittente dichiara non e' un fatto sul file
--
-- Il nome e il tipo arrivano gia' ripuliti dal connettore (niente caratteri di
-- controllo, niente caratteri che invertono la scrittura). Lo schema ne
-- controlla la lunghezza. Il nome non diventa mai il nome di un file.
--
-- # Che cosa non si puo' fare
--
-- Le righe non cambiano. Se ne vanno soltanto con il loro contenuto, quando la
-- conservazione lo toglie.
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE content_attachments (
    id            INTEGER PRIMARY KEY,
    content_id    INTEGER NOT NULL UNIQUE REFERENCES contents (id) ON DELETE CASCADE,
    kind          TEXT NOT NULL
                      CHECK (kind IN ('documento', 'foto', 'video', 'audio', 'nota_vocale',
                             'videomessaggio', 'animazione', 'adesivo')),
    declared_name TEXT CHECK (declared_name IS NULL
                              OR length(trim(declared_name)) BETWEEN 1 AND 255),
    declared_size INTEGER CHECK (declared_size IS NULL OR declared_size > 0),
    declared_mime TEXT CHECK (declared_mime IS NULL
                              OR (length(declared_mime) BETWEEN 3 AND 100
                                  AND declared_mime GLOB '*/*'))
);

CREATE TRIGGER content_attachments_are_immutable
    BEFORE UPDATE ON content_attachments
BEGIN
    SELECT RAISE(ABORT, 'la descrizione di un allegato non cambia');
END;

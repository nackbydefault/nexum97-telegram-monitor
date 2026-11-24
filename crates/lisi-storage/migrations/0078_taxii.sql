-- 0078 — Lo scambio TAXII (TAXII-01 parte 2, ADR-0179, DEC-459).
--
-- # Che cosa registra
--
-- Due cose, ciascuna con la sua tabella.
--
-- 1. **La destinazione**: la radice dell'API `https://`, l'identificativo della
--    collezione e il nome utente. Una riga sola, vuota di fabbrica, come la
--    fonte dei dizionari (0077). La parola d'ordine **non sta qui**: sta in un
--    file protetto con DPAPI, fuori dall'archivio e dalle sue copie
--    (ADR-0179, decisione 5).
-- 2. **Gli invii**: una riga per invio arrivato alla rete, anche quando il
--    server non l'ha preso, con chi, quando, l'indirizzo, il monitoraggio,
--    quanti oggetti, l'impronta del corpo, lo stato HTTP e, se c'era, lo
--    stato TAXII (decisione 9).
--
-- # Che cosa non si puo' fare
--
-- La riga della destinazione non si cancella: si svuota. Radice e collezione
-- si scrivono insieme o mancano insieme. Gli invii non cambiano e non si
-- cancellano. Il corpo non si tiene: si rifa' dal piano, e l'impronta dice se
-- e' lo stesso.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE taxii_destination (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    -- NULL vuol dire «non configurata», ed e' il valore di fabbrica.
    api_root      TEXT CHECK (api_root IS NULL
                              OR (api_root LIKE 'https://%' AND length(api_root) <= 1900)),
    -- Diventa un pezzo di percorso: soltanto lettere, cifre e trattini.
    collection_id TEXT CHECK (collection_id IS NULL
                              OR (length(collection_id) BETWEEN 1 AND 64
                                  AND collection_id NOT GLOB '*[^0-9A-Za-z-]*')),
    -- Il nome utente di HTTP Basic: niente due punti, niente a capo.
    username      TEXT CHECK (username IS NULL
                              OR (length(username) BETWEEN 1 AND 256
                                  AND instr(username, ':') = 0
                                  AND instr(username, char(10)) = 0
                                  AND instr(username, char(13)) = 0)),
    updated_at    INTEGER NOT NULL,
    updated_by    TEXT    NOT NULL,
    CHECK ((api_root IS NULL) = (collection_id IS NULL))
);

INSERT INTO taxii_destination (id, api_root, collection_id, username, updated_at, updated_by)
VALUES (1, NULL, NULL, NULL, 0, 'sistema');

CREATE TRIGGER taxii_destination_non_si_cancella
BEFORE DELETE ON taxii_destination
BEGIN
    SELECT RAISE(ABORT, 'la destinazione TAXII non si cancella: si svuota');
END;

CREATE TABLE taxii_submissions (
    id             INTEGER PRIMARY KEY,
    requested_by   TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    requested_at   INTEGER NOT NULL,
    url            TEXT    NOT NULL CHECK (url LIKE 'https://%'),
    -- Un numero e non un riferimento: il registro resta com'era anche se il
    -- monitoraggio un giorno non c'e' piu'.
    session_id     INTEGER NOT NULL,
    objects        INTEGER NOT NULL CHECK (objects > 0),
    body_sha256    TEXT    NOT NULL
                       CHECK (length(body_sha256) = 64
                              AND body_sha256 NOT GLOB '*[^0-9a-f]*'),
    http_status    INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    outcome        TEXT    NOT NULL CHECK (outcome IN ('consegnato', 'non_consegnato')),
    outcome_detail TEXT,
    -- Lo stato TAXII: dato non fidato, di cui si tengono un identificativo e
    -- tre numeri, e nient'altro.
    status_id      TEXT CHECK (status_id IS NULL
                               OR (length(status_id) BETWEEN 1 AND 64
                                   AND status_id NOT GLOB '*[^0-9A-Za-z-]*')),
    success_count  INTEGER CHECK (success_count IS NULL OR success_count >= 0),
    failure_count  INTEGER CHECK (failure_count IS NULL OR failure_count >= 0),
    pending_count  INTEGER CHECK (pending_count IS NULL OR pending_count >= 0),
    -- Consegnato vuol dire che il server ha risposto 202, e soltanto quello.
    CHECK ((outcome = 'consegnato') = (http_status IS NOT NULL AND http_status = 202)),
    -- Lo stato TAXII c'e' soltanto in una consegna.
    CHECK (outcome = 'consegnato'
           OR (status_id IS NULL AND success_count IS NULL
               AND failure_count IS NULL AND pending_count IS NULL))
);

CREATE INDEX taxii_submissions_by_session ON taxii_submissions (session_id);

CREATE TRIGGER taxii_submissions_are_immutable
    BEFORE UPDATE ON taxii_submissions
BEGIN
    SELECT RAISE(ABORT, 'un invio TAXII non cambia');
END;

CREATE TRIGGER taxii_submissions_are_not_deleted
    BEFORE DELETE ON taxii_submissions
BEGIN
    SELECT RAISE(ABORT, 'un invio TAXII non si cancella');
END;

-- 0077 — I dizionari dalla rete (DICT-NET-01 parte 2, ADR-0178, DEC-455).
--
-- # Che cosa registra
--
-- Tre cose, ciascuna con la sua tabella.
--
-- 1. **La fonte**: l'indirizzo `https://` del dizionario, una riga sola, vuota
--    di fabbrica, come l'origine degli aggiornamenti (0040). La firma sta
--    allo stesso indirizzo con `.p7s` in fondo, e non si scrive a parte: due
--    indirizzi sarebbero due destinazioni (ADR-0178, decisione 5).
-- 2. **I firmatari ammessi**: le impronte SHA-256 dei certificati che
--    l'amministratore ammette, al piu' otto, nessuna di fabbrica (decisione 4).
-- 3. **Gli scaricamenti**: una riga per tentativo, anche per i rifiuti, con
--    chi, quando, l'indirizzo, l'impronta dei byte, il firmatario, il nome e
--    il numero dichiarati e l'esito (decisione 10).
--
-- # Che cosa non si puo' fare
--
-- La riga della fonte non si cancella: si svuota. Gli scaricamenti non
-- cambiano e non si cancellano. I byte non stanno qui: un dizionario che passa
-- entra fra i dizionari, uno che non passa non si tiene (decisione 11).
--
-- Il dizionario e la versione scritti sono numeri e non riferimenti: un
-- dizionario in bozza si puo' togliere, e il registro deve restare com'era.
--
-- # Additiva
--
-- Tre tabelle nuove; nient'altro cambia.

CREATE TABLE dictionary_network_source (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    -- NULL vuol dire «non configurata», ed e' il valore di fabbrica.
    url        TEXT CHECK (url IS NULL
                           OR (url LIKE 'https://%' AND length(url) <= 2044)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL
);

INSERT INTO dictionary_network_source (id, url, updated_at, updated_by)
VALUES (1, NULL, 0, 'sistema');

CREATE TRIGGER dictionary_network_source_non_si_cancella
BEFORE DELETE ON dictionary_network_source
BEGIN
    SELECT RAISE(ABORT, 'la fonte dei dizionari non si cancella: si svuota');
END;

CREATE TABLE dictionary_signers (
    fingerprint TEXT PRIMARY KEY
                    CHECK (length(fingerprint) = 64
                           AND fingerprint NOT GLOB '*[^0-9a-f]*'),
    added_at    INTEGER NOT NULL,
    added_by    TEXT    NOT NULL CHECK (length(trim(added_by)) > 0)
);

CREATE TRIGGER dictionary_signers_al_piu_otto
BEFORE INSERT ON dictionary_signers
WHEN (SELECT count(*) FROM dictionary_signers) >= 8
BEGIN
    SELECT RAISE(ABORT, 'i firmatari ammessi dei dizionari sono al piu'' otto');
END;

CREATE TABLE dictionary_downloads (
    id               INTEGER PRIMARY KEY,
    requested_by     TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    requested_at     INTEGER NOT NULL,
    url              TEXT    NOT NULL CHECK (url LIKE 'https://%'),
    -- L'impronta dei byte arrivati: manca soltanto se non e' arrivato niente.
    content_sha256   TEXT
                         CHECK (content_sha256 IS NULL
                                OR (length(content_sha256) = 64
                                    AND content_sha256 NOT GLOB '*[^0-9a-f]*')),
    -- L'impronta del certificato di chi ha firmato, se la firma l'ha detta.
    signer_sha256    TEXT
                         CHECK (signer_sha256 IS NULL
                                OR (length(signer_sha256) = 64
                                    AND signer_sha256 NOT GLOB '*[^0-9a-f]*')),
    declared_name    TEXT,
    declared_version INTEGER CHECK (declared_version IS NULL OR declared_version > 0),
    outcome          TEXT    NOT NULL
                         CHECK (outcome IN ('importato', 'rifiutato', 'non_riuscito')),
    outcome_detail   TEXT,
    dictionary_id    INTEGER,
    version_id       INTEGER,
    -- Un dizionario entra soltanto con tutto cio' che lo ha fatto entrare.
    CHECK ((outcome = 'importato') = (version_id IS NOT NULL)),
    CHECK (outcome <> 'importato'
           OR (dictionary_id IS NOT NULL AND content_sha256 IS NOT NULL
               AND signer_sha256 IS NOT NULL AND declared_name IS NOT NULL
               AND declared_version IS NOT NULL))
);

CREATE INDEX dictionary_downloads_by_name
    ON dictionary_downloads (declared_name, outcome);

CREATE TRIGGER dictionary_downloads_are_immutable
    BEFORE UPDATE ON dictionary_downloads
BEGIN
    SELECT RAISE(ABORT, 'uno scaricamento di un dizionario non cambia');
END;

CREATE TRIGGER dictionary_downloads_are_not_deleted
    BEFORE DELETE ON dictionary_downloads
BEGIN
    SELECT RAISE(ABORT, 'uno scaricamento di un dizionario non si cancella');
END;

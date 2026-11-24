-- 0076 — Gli allegati conservati su richiesta (ATTACH-01 parte 2, ADR-0177,
-- DEC-452).
--
-- # Che cosa registra
--
-- Una riga per richiesta di conservare l'allegato di un contenuto: chi l'ha
-- fatta, quando e perche', con quale account d'ufficio, e com'e' andata.
-- Anche una richiesta che un tetto ha fermato, che Telegram ha rifiutato o
-- che non e' arrivata a una risposta ha la sua riga: una richiesta fatta non
-- sparisce (ADR-0177, decisione 3).
--
-- # I byte
--
-- Soltanto una richiesta riuscita porta i byte, non aperti, con la loro
-- impronta SHA-256: lo schema li vuole insieme, e li vuole soltanto per
-- l'esito «conservato». Un allegato oltre 25 MiB non si scrive; l'archivio
-- non ne tiene oltre 1 GiB in tutto, e il trigger lo ricontrolla anche se il
-- servizio sbagliasse il conto (ADR-0177, decisione 5).
--
-- # Una volta
--
-- Un allegato conservato non si conserva una seconda volta: l'indice unico
-- parziale lo impedisce (ADR-0177, decisione 8). Le richieste non riuscite
-- possono ripetersi, una riga ciascuna.
--
-- # Che cosa non si puo' fare
--
-- Le righe non cambiano e non si cancellano. Il contenuto a cui si
-- riferiscono non si toglie: `ON DELETE RESTRICT`, e la conservazione
-- dell'archivio lo lascia stare (DEC-452).
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE attachment_keepings (
    id             INTEGER PRIMARY KEY,
    content_id     INTEGER NOT NULL REFERENCES contents (id) ON DELETE RESTRICT,
    account_uuid   TEXT
                       CHECK (account_uuid IS NULL
                              OR (length(account_uuid) = 32
                                  AND account_uuid NOT GLOB '*[^0-9a-f]*')),
    requested_by   TEXT NOT NULL CHECK (length(trim(requested_by)) > 0),
    reason         TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    requested_at   INTEGER NOT NULL,
    outcome        TEXT NOT NULL
                       CHECK (outcome IN ('conservato', 'fermato', 'rifiutato',
                                          'non_riuscito')),
    outcome_detail TEXT,
    bytes          BLOB CHECK (bytes IS NULL OR length(bytes) BETWEEN 1 AND 26214400),
    sha256         TEXT
                       CHECK (sha256 IS NULL
                              OR (length(sha256) = 64
                                  AND sha256 NOT GLOB '*[^0-9a-f]*')),
    CHECK ((bytes IS NULL) = (sha256 IS NULL)),
    CHECK ((outcome = 'conservato') = (bytes IS NOT NULL))
);

CREATE UNIQUE INDEX attachment_kept_once
    ON attachment_keepings (content_id) WHERE outcome = 'conservato';

CREATE INDEX attachment_keepings_by_content
    ON attachment_keepings (content_id, requested_at);

CREATE TRIGGER attachment_keepings_stay_under_the_total
    BEFORE INSERT ON attachment_keepings
    WHEN NEW.bytes IS NOT NULL
     AND (SELECT coalesce(sum(length(bytes)), 0) FROM attachment_keepings)
         + length(NEW.bytes) > 1073741824
BEGIN
    SELECT RAISE(ABORT, 'gli allegati conservati supererebbero 1 GiB');
END;

CREATE TRIGGER attachment_keepings_are_immutable
    BEFORE UPDATE ON attachment_keepings
BEGIN
    SELECT RAISE(ABORT, 'una conservazione di un allegato non cambia');
END;

CREATE TRIGGER attachment_keepings_are_not_deleted
    BEFORE DELETE ON attachment_keepings
BEGIN
    SELECT RAISE(ABORT, 'una conservazione di un allegato non si cancella');
END;

-- 0095 — Chi ha registrato un nome o un indirizzo, chiesto dal PC (WHOIS-01,
-- ADR-0205).
--
-- # Che cosa registra
--
-- `registration_lookup_settings`: una riga sola, se il WHOIS è abilitato.
-- Zero è il valore di fabbrica (ADR-0205, decisione 5).
--
-- `registration_lookups`: ogni richiesta, con chi, quando, quale indicatore,
-- quale nome o indirizzo si è chiesto davvero, a quale servizio e a quale
-- registro, com'è andata e il riassunto della risposta (decisione 8). Una
-- richiesta non cambia e non si toglie.
--
-- # Additiva
--
-- Due tabelle nuove; nient'altro cambia.

CREATE TABLE registration_lookup_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    enabled     INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL
);

INSERT INTO registration_lookup_settings (id, enabled, updated_at, updated_by)
VALUES (1, 0, 0, 'sistema');

CREATE TRIGGER registration_lookup_settings_non_si_cancella
BEFORE DELETE ON registration_lookup_settings
BEGIN
    SELECT RAISE(ABORT, 'la scelta sul WHOIS non si cancella: si spegne');
END;

CREATE TABLE registration_lookups (
    id              INTEGER PRIMARY KEY,
    indicator_kind  TEXT    NOT NULL CHECK (indicator_kind IN ('ipv4', 'ipv6', 'dominio', 'url')),
    indicator_value TEXT    NOT NULL CHECK (length(indicator_value) BETWEEN 1 AND 2048),
    queried_name    TEXT    NOT NULL CHECK (length(queried_name) BETWEEN 1 AND 255),
    service         TEXT    NOT NULL CHECK (service IN ('rdap', 'whois', 'nessuno')),
    server          TEXT    NOT NULL DEFAULT '' CHECK (length(server) <= 2048),
    requested_by    TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    requested_at    INTEGER NOT NULL,
    outcome         TEXT    NOT NULL
                            CHECK (outcome IN ('trovato', 'inesistente', 'nessun_servizio', 'non_riuscito')),
    detail          TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 1024),
    summary         TEXT    NOT NULL DEFAULT '' CHECK (length(summary) <= 16384)
);

CREATE INDEX registration_lookups_by_indicator
    ON registration_lookups (indicator_kind, indicator_value, requested_at);

CREATE TRIGGER registration_lookups_are_immutable
    BEFORE UPDATE ON registration_lookups
BEGIN
    SELECT RAISE(ABORT, 'una richiesta WHOIS registrata non cambia');
END;

CREATE TRIGGER registration_lookups_are_kept
    BEFORE DELETE ON registration_lookups
BEGIN
    SELECT RAISE(ABORT, 'una richiesta WHOIS registrata non si toglie');
END;

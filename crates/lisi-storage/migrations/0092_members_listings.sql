-- 0092 — Gli elenchi degli iscritti delle fonti (MEMBERS-01, ADR-0201).
--
-- # Che cosa registra
--
-- `members_listing_settings`: una riga sola, se l'elenco degli iscritti è
-- abilitato. Zero è il valore di fabbrica (ADR-0201, decisione 4).
--
-- `members_listings`: ogni richiesta, con chi, quando, per quale fonte, con
-- quale motivo e com'è andata, e quanti iscritti Telegram dichiarava e quanti
-- ne sono arrivati (decisioni 2 e 5).
--
-- `members_listing_rows`: gli iscritti arrivati. Il telefono c'è soltanto
-- mascherato: lo schema rifiuta tre cifre di fila (decisione 6).
--
-- Una richiesta e le sue righe non cambiano e non si tolgono (decisione 7).
--
-- # Additiva
--
-- Tre tabelle nuove; nient'altro cambia.

CREATE TABLE members_listing_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    enabled     INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL
);

INSERT INTO members_listing_settings (id, enabled, updated_at, updated_by)
VALUES (1, 0, 0, 'sistema');

CREATE TRIGGER members_listing_settings_non_si_cancella
BEFORE DELETE ON members_listing_settings
BEGIN
    SELECT RAISE(ABORT, 'la scelta sull''elenco degli iscritti non si cancella: si spegne');
END;

CREATE TABLE members_listings (
    id              INTEGER PRIMARY KEY,
    source_id       INTEGER NOT NULL REFERENCES sources (id),
    chat_id         INTEGER NOT NULL,
    account_uuid    TEXT,
    requested_by    TEXT    NOT NULL CHECK (length(trim(requested_by)) > 0),
    reason          TEXT    NOT NULL CHECK (length(trim(reason)) > 0),
    requested_at    INTEGER NOT NULL,
    outcome         TEXT    NOT NULL
                            CHECK (outcome IN ('ottenuto', 'rifiutato', 'non_riuscito', 'non_gruppo')),
    outcome_detail  TEXT,
    declared_total  INTEGER CHECK (declared_total IS NULL OR declared_total >= 0),
    received        INTEGER NOT NULL CHECK (received >= 0),
    stopped_at_cap  INTEGER NOT NULL CHECK (stopped_at_cap IN (0, 1))
);

CREATE INDEX members_listings_by_time ON members_listings (requested_at, id);

CREATE TRIGGER members_listings_are_immutable
    BEFORE UPDATE ON members_listings
BEGIN
    SELECT RAISE(ABORT, 'una richiesta di elenco registrata non cambia');
END;

CREATE TRIGGER members_listings_are_kept
    BEFORE DELETE ON members_listings
BEGIN
    SELECT RAISE(ABORT, 'una richiesta di elenco registrata non si toglie');
END;

CREATE TABLE members_listing_rows (
    listing_id    INTEGER NOT NULL REFERENCES members_listings (id),
    position      INTEGER NOT NULL CHECK (position >= 0),
    user_id       INTEGER NOT NULL CHECK (user_id > 0),
    display_name  TEXT,
    username      TEXT,
    masked_phone  TEXT CHECK (masked_phone IS NULL OR masked_phone NOT GLOB '*[0-9][0-9][0-9]*'),
    status        TEXT    NOT NULL
                          CHECK (status IN ('creatore', 'amministratore', 'iscritto', 'limitato',
                                            'uscito', 'escluso')),
    joined_at     INTEGER,
    PRIMARY KEY (listing_id, position)
);

CREATE TRIGGER members_listing_rows_are_immutable
    BEFORE UPDATE ON members_listing_rows
BEGIN
    SELECT RAISE(ABORT, 'un iscritto registrato non cambia');
END;

CREATE TRIGGER members_listing_rows_are_kept
    BEFORE DELETE ON members_listing_rows
BEGIN
    SELECT RAISE(ABORT, 'un iscritto registrato non si toglie');
END;

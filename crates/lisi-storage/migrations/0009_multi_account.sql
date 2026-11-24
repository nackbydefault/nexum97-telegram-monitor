-- Migrazione 0009 - profili di credenziali API e account Telegram (M3B.1).
--
-- Modello multi-account (ADR-0019): un profilo API serve N account. Qui stanno
-- solo i METADATI NON SEGRETI. L'API hash, il numero pieno, i codici e le chiavi
-- NON compaiono in questo database in chiaro: l'API hash e la chiave del
-- database TDLib per-account stanno in file protetti DPAPI; il numero e'
-- conservato solo mascherato; codici e password non sono mai persistiti.
--
-- L'identita' stabile di un account e' il suo UUID (32 cifre esadecimali), da
-- cui si derivano a runtime la directory TDLib, la directory file e il nome del
-- file della chiave. Il numero, l'username o il nome della persona NON sono mai
-- usati per nominare directory o file.

CREATE TABLE api_credential_profiles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label      TEXT NOT NULL,
    -- Se l'API id/hash e' stato salvato nel file protetto. Il segreto non e' qui.
    configured INTEGER NOT NULL CHECK (configured IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE telegram_accounts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    -- UUID locale: 32 cifre esadecimali minuscole. Unico per postazione.
    uuid              TEXT NOT NULL UNIQUE
                          CHECK (length(uuid) = 32 AND uuid GLOB '[0-9a-f]*'),
    label             TEXT NOT NULL,
    -- Numero MASCHERATO (solo le ultime cifre). Mai il numero pieno.
    masked_phone      TEXT,
    profile_id        INTEGER NOT NULL REFERENCES api_credential_profiles (id)
                          ON DELETE RESTRICT,
    auth_status       TEXT NOT NULL
                          CHECK (auth_status IN
                              ('fresh', 'authorizing', 'authorized', 'logged_out', 'failed')),
    connection_status TEXT NOT NULL
                          CHECK (connection_status IN
                              ('offline', 'connecting', 'connected', 'unknown')),
    last_connected_at INTEGER,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE INDEX telegram_accounts_by_profile ON telegram_accounts (profile_id);

-- Una fonte puo' appartenere a un account. Nullable: le fonti gia' configurate
-- (mock) restano valide senza account. Un account non si cancella finche' ha
-- fonti associate.
ALTER TABLE sources ADD COLUMN account_id INTEGER
    REFERENCES telegram_accounts (id) ON DELETE RESTRICT;

CREATE INDEX sources_by_account ON sources (account_id);

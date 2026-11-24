-- 0072 — L'account d'ufficio di un monitoraggio (MULTI-ACCOUNT-02 parte 2,
-- ADR-0173, DEC-439).
--
-- # Che cosa registra
--
-- Una riga per monitoraggio: con quale account d'ufficio lavora, e come si
-- chiamava l'account quando il monitoraggio e' nato. Con piu' account attivi
-- insieme, e' cio' che impedisce che un aggiornamento arrivato a un account
-- finisca nel monitoraggio di un altro, anche quando la chat e' la stessa.
--
-- # Perche' l'UUID e non l'identificativo della riga
--
-- L'UUID e' l'identita' stabile dell'account (migrazione 0009) e non e' un
-- segreto. Un riferimento alla riga di `telegram_accounts` impedirebbe di
-- rimuovere un account che ha lavorato, oppure cancellerebbe il ricordo di chi
-- ha acquisito: entrambe le cose sono peggiori di un testo che resta.
--
-- # Che cosa non si puo' fare
--
-- Il legame si scrive una volta, quando il monitoraggio nasce: non cambia e
-- non si cancella. Un monitoraggio non passa a un altro account (ADR-0173,
-- decisione 4).
--
-- # Additiva
--
-- Una tabella nuova; le sessioni non cambiano. Un monitoraggio senza riga e'
-- uno nato prima di questa migrazione, o dimostrativo: riceve aggiornamenti
-- soltanto quando e' aperto un account solo.

CREATE TABLE session_accounts (
    session_id    INTEGER PRIMARY KEY REFERENCES sessions (id) ON DELETE RESTRICT,
    account_uuid  TEXT NOT NULL
                      CHECK (length(account_uuid) = 32
                             AND account_uuid NOT GLOB '*[^0-9a-f]*'),
    account_label TEXT NOT NULL CHECK (length(trim(account_label)) > 0),
    bound_at      INTEGER NOT NULL
);

CREATE INDEX session_accounts_by_account ON session_accounts (account_uuid);

CREATE TRIGGER session_accounts_are_immutable
    BEFORE UPDATE ON session_accounts
BEGIN
    SELECT RAISE(ABORT, 'l''account di un monitoraggio non cambia');
END;

CREATE TRIGGER session_accounts_are_not_deleted
    BEFORE DELETE ON session_accounts
BEGIN
    SELECT RAISE(ABORT, 'l''account di un monitoraggio non si cancella');
END;

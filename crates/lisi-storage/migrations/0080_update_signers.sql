-- 0080 — I firmatari degli aggiornamenti (UPDATE-SIGN-01 parte 1, ADR-0183,
-- DEC-466).
--
-- # Che cosa registra
--
-- Le impronte SHA-256 dei certificati con cui il produttore firma il manifesto
-- degli aggiornamenti, ammesse dall'amministratore, ciascuna con un nome e uno
-- stato (ADR-0183, decisione 3). L'impronta e' l'identificativo della chiave;
-- piu' impronte ammesse insieme sono la finestra di una rotazione.
--
-- # Che cosa non si puo' fare
--
-- Un firmatario non si cancella: si ritira, e resta con chi l'ha ritirato e
-- quando. Un firmatario ritirato non torna ammesso: una chiave ritirata e' una
-- chiave di cui non ci si fida piu', e la si ammette di nuovo soltanto con un
-- certificato nuovo (ADR-0045, requisito 4). L'impronta e il nome non
-- cambiano.
--
-- # Additiva
--
-- Una tabella nuova; nient'altro cambia.

CREATE TABLE update_signers (
    fingerprint TEXT PRIMARY KEY
                    CHECK (length(fingerprint) = 64
                           AND fingerprint NOT GLOB '*[^0-9a-f]*'),
    name        TEXT NOT NULL
                    CHECK (length(trim(name)) > 0
                           AND length(name) <= 120
                           AND name NOT GLOB '*[' || char(10) || char(13) || ']*'),
    added_at    INTEGER NOT NULL,
    added_by    TEXT    NOT NULL CHECK (length(trim(added_by)) > 0),
    retired_at  INTEGER,
    retired_by  TEXT,
    -- Ritirato vuol dire con chi e quando, insieme.
    CHECK ((retired_at IS NULL) = (retired_by IS NULL)),
    CHECK (retired_by IS NULL OR length(trim(retired_by)) > 0)
);

CREATE TRIGGER update_signers_al_piu_otto_ammessi
BEFORE INSERT ON update_signers
WHEN (SELECT count(*) FROM update_signers WHERE retired_at IS NULL) >= 8
BEGIN
    SELECT RAISE(ABORT, 'i firmatari ammessi degli aggiornamenti sono al piu'' otto');
END;

CREATE TRIGGER update_signers_si_ritirano_e_basta
BEFORE UPDATE ON update_signers
WHEN NEW.fingerprint IS NOT OLD.fingerprint
  OR NEW.name IS NOT OLD.name
  OR NEW.added_at IS NOT OLD.added_at
  OR NEW.added_by IS NOT OLD.added_by
  OR OLD.retired_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'un firmatario degli aggiornamenti si ritira, e il resto non cambia');
END;

CREATE TRIGGER update_signers_non_si_cancellano
BEFORE DELETE ON update_signers
BEGIN
    SELECT RAISE(ABORT, 'un firmatario degli aggiornamenti non si cancella: si ritira');
END;

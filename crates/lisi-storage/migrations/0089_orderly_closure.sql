-- 0089 — La chiusura ordinata, e la finestra com'era (UX-FIX-03, ADR-0195,
-- DEC-483).
--
-- # Perche' esiste
--
-- Il collaudo (FULL-OPERATIONAL-VALIDATION-01) ha visto due cose che il
-- programma dimenticava chiudendosi:
--
-- - l'avviso dell'interruzione diceva «non stava piu' guardando dal 16:50:53
--   (l'ultimo contenuto acquisito)», mentre la postazione aveva guardato fino
--   alla chiusura delle 16:53:34 (OBS-RST-1): l'ultimo fatto in archivio non e'
--   la fine dell'osservazione;
-- - la finestra ingrandita si riapriva non ingrandita.
--
-- # La riga della chiusura
--
-- Una riga sola. `closed_at` si scrive quando il ciclo della finestra finisce
-- in modo ordinato, e il rilevamento delle interruzioni del primo avvio dopo la
-- LEGGE E LA SVUOTA: una chiusura vale soltanto per l'avvio che la segue. Dopo
-- un arresto anomalo la riga e' vuota, e l'inizio del buco resta l'ultimo
-- contenuto o l'avvio del monitoraggio, come prima.

CREATE TABLE orderly_closure (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- L'istante della chiusura ordinata non ancora letta da un avvio.
    closed_at INTEGER,
    -- Se la finestra era ingrandita alla chiusura.
    window_maximized INTEGER NOT NULL DEFAULT 0 CHECK (window_maximized IN (0, 1))
);

INSERT INTO orderly_closure (id, closed_at, window_maximized) VALUES (1, NULL, 0);

-- ------------------------------------------------- l'origine 'chiusura'
--
-- # Perche' si ricostruisce
--
-- SQLite non consente di cambiare un vincolo CHECK: la tabella si ricostruisce
-- come nella 0083, con le righe copiate tali e quali. La 0038 non si modifica.
--
-- # Che cosa cambia
--
-- L'inizio del buco ammette una terza origine, 'chiusura': la chiusura
-- ordinata del programma con il monitoraggio in corso.
--
-- # Che cosa resta com'era
--
-- Le colonne, la chiave, l'indice delle interruzioni aperte e i tre divieti: il
-- fatto non si riscrive, non si cancella, e si prende in carico una volta sola.
-- DROP TABLE non esegue i trigger della tabella che toglie.

CREATE TABLE session_interruptions_ricostruita (
    session_id INTEGER PRIMARY KEY REFERENCES sessions (id) ON DELETE RESTRICT,
    noticed_at INTEGER NOT NULL,
    gap_start_at INTEGER NOT NULL,
    -- 'ultimo_contenuto', 'avvio' oppure 'chiusura' (ADR-0195).
    gap_start_origin TEXT NOT NULL CHECK (
        gap_start_origin IN ('ultimo_contenuto', 'avvio', 'chiusura')
    ),
    acknowledged_at INTEGER
);

INSERT INTO session_interruptions_ricostruita (
    session_id, noticed_at, gap_start_at, gap_start_origin, acknowledged_at
)
SELECT session_id, noticed_at, gap_start_at, gap_start_origin, acknowledged_at
FROM session_interruptions;

DROP TABLE session_interruptions;

ALTER TABLE session_interruptions_ricostruita RENAME TO session_interruptions;

CREATE INDEX session_interruptions_open
    ON session_interruptions (acknowledged_at)
    WHERE acknowledged_at IS NULL;

CREATE TRIGGER session_interruptions_are_immutable
    BEFORE UPDATE OF session_id, noticed_at, gap_start_at, gap_start_origin
    ON session_interruptions
BEGIN
    SELECT RAISE(ABORT, 'un''interruzione registrata e'' immutabile');
END;

CREATE TRIGGER session_interruptions_are_not_deleted
    BEFORE DELETE ON session_interruptions
BEGIN
    SELECT RAISE(ABORT, 'un''interruzione registrata non si cancella');
END;

CREATE TRIGGER session_interruptions_are_acknowledged_once
    BEFORE UPDATE OF acknowledged_at ON session_interruptions
    WHEN OLD.acknowledged_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'un''interruzione gia'' presa in carico non si riprende');
END;

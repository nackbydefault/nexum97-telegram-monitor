-- Migrazione 0017 - per quanto tempo l'ufficio conserva cio' che ha acquisito.
--
-- Fino a qui l'archivio cresceva e basta. Nessuna politica di conservazione
-- significa due cose insieme, entrambe sbagliate: materiale di servizio che
-- resta indefinitamente senza che nessuno abbia deciso che debba restare, e un
-- archivio che diventa lento e ingombrante senza che nessuno se ne accorga
-- finche' non e' tardi.
--
-- Una riga sola, come per la cartella dei documenti (0016) e le impostazioni
-- delle notifiche (0008).
--
-- =============================================================================
-- NULL SIGNIFICA «SI CONSERVA TUTTO», ED E' IL VALORE PREDEFINITO.
-- =============================================================================
--
-- E' la scelta prudente, e non e' una scelta neutra: qualunque altro valore
-- predefinito CANCELLEREBBE DATI il giorno dell'aggiornamento, su archivi
-- esistenti, senza che nessuno lo abbia chiesto.
--
-- Un prodotto che si porta via del materiale di servizio perche' «era la
-- politica predefinita» ha fatto un danno che nessuna configurazione
-- successiva ripara. Chi vuole una conservazione limitata la sceglie.
--
-- =============================================================================
-- CHE COSA QUESTA POLITICA NON TOCCHERA' MAI
-- =============================================================================
--
-- Non e' materia di questa migrazione ma del servizio che la applica, ed e'
-- scritto qui perche' chi legge lo schema lo sappia senza cercare:
--
--   * l'AUDIT. E' la traccia di cio' che e' successo, compresa la
--     conservazione stessa. Un archivio che potesse cancellare la propria
--     traccia non sarebbe piu' una traccia.
--
--   * le FOTOGRAFIE DEI RAPPORTI (report_content_snapshots e parenti). Un
--     documento gia' consegnato deve restare spiegabile: cancellare cio' che
--     lo giustifica renderebbe l'atto inverificabile.
--
--   * i CONTENUTI CITATI da un pacchetto prodotto, a prescindere dall'eta'.
--     Sono le prove di un documento firmato.
--
--   * dizionari, fonti, account, credenziali e configurazione. Non sono
--     materiale acquisito: sono come il prodotto e' stato impostato.
--
-- =============================================================================

CREATE TABLE retention_policy (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    -- Giorni di conservazione. NULL = si conserva tutto.
    --
    -- Il limite inferiore non e' pignoleria: una conservazione di zero giorni
    -- cancellerebbe cio' che si e' appena acquisito, e non e' una politica ma
    -- un guasto travestito da configurazione.
    keep_days  INTEGER CHECK (keep_days IS NULL OR keep_days >= 1),
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

-- La riga predefinita esiste da subito, cosi' chi legge non gestisce l'assenza.
-- `updated_by` dice 'sistema' perche' nessun operatore ha ancora scelto.
INSERT INTO retention_policy (id, keep_days, updated_at, updated_by)
VALUES (1, NULL, 0, 'sistema');

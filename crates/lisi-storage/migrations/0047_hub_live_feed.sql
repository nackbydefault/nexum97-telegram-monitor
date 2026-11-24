-- La proiezione locale del live condiviso, sulla postazione che segue un Hub.
--
-- Motivata in ADR-0093 e DEC-331 (TEAM-LIVE-01).
--
-- ===========================================================================
-- QUESTA NON E' LA STORIA DELL'HUB. E' CIO' CHE SI VEDE SULLO SCHERMO.
--
-- La storia autorevole sta sull'Hub (ADR-0086), e il punto raggiunto da questa
-- postazione sta nel cursore (ADR-0087). Qui c'e' soltanto cio' che serve a
-- mostrare le ultime righe: si pota, e potare non perde niente, perche' cio'
-- che conta - dove siamo arrivati - e' altrove.
--
-- Per la stessa ragione la tabella NON e' append-only come `hub_events`: la
-- potatura e' il suo funzionamento normale, non una manomissione.
--
-- ===========================================================================
-- IL NUMERO E' QUELLO DELL'HUB.
--
-- `sequence` non e' una chiave locale: e' il numero che l'Hub ha dato
-- all'evento. Riapplicare lo stesso evento - cosa che il recupero puo' fare
-- dopo un arresto a meta' (ADR-0087) - non deve produrre due righe, e la
-- chiave primaria lo impedisce senza che nessuno debba ricordarselo.
--
-- ===========================================================================
-- CHE COSA NON C'E' DENTRO.
--
-- Nessun testo di messaggio. Gli eventi del live portano fatti dell'attivita'
-- - quante cose sono arrivate, da quale fonte, con quale livello - e mai il
-- contenuto monitorato: un flusso che lo portasse sarebbe la copia
-- dell'archivio dell'Hub costruita un pezzo alla volta (freeze 7.10).

CREATE TABLE hub_live_feed (
    sequence    INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    subject     TEXT NOT NULL,
    detail      TEXT,
    recorded_at INTEGER NOT NULL,

    CHECK (sequence > 0)
);

-- Le letture della schermata sono sempre «le ultime N»: l'indice serve a
-- quelle, e alla potatura che cancella le piu' vecchie.
CREATE INDEX hub_live_feed_by_sequence ON hub_live_feed (sequence DESC);

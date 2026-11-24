-- Migrazione 0006 - idempotenza dell'acquisizione per costruzione.
--
-- La revisione di sicurezza del runtime di acquisizione ha trovato che la
-- ripresa dopo un crash poteva DUPLICARE una modifica o una cancellazione:
-- l'effetto e la conclusione della voce d'inbox erano istruzioni separate, e un
-- crash fra le due lasciava la voce in 'processing', poi riapplicata.
--
-- La correzione lega ogni effetto all'evento d'inbox che l'ha prodotto, cosi'
-- che la ri-applicazione della stessa voce sia un no-op per costruzione --
-- esattamente come gia' fa `insert_content` con ON CONFLICT sull'identita' del
-- messaggio. Nessun contenuto esistente ha queste tabelle (schema introdotto
-- nella stessa milestone, non ancora in esercizio): si aggiunge una colonna e
-- un indice unico, senza ricostruire nulla.

ALTER TABLE content_versions ADD COLUMN origin_inbox_id INTEGER;
ALTER TABLE content_deletions ADD COLUMN origin_inbox_id INTEGER;

-- Unico per costruzione: due applicazioni della stessa voce d'inbox non
-- possono produrre due effetti. I NULL sono ammessi e distinti in un indice
-- unico di SQLite: la versione originale seminata alla prima modifica non ha
-- un evento d'origine, e c'e' comunque un solo originale per contenuto (gia'
-- garantito da UNIQUE(content_id, version_number)).
CREATE UNIQUE INDEX content_versions_by_origin ON content_versions (origin_inbox_id);
CREATE UNIQUE INDEX content_deletions_by_origin ON content_deletions (origin_inbox_id);

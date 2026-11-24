-- Migrazione 0058 - due indici sulle chiavi esterne verso i contenuti
-- (FINAL-REVIEW-01, FR-006, DEC-379).
--
-- =============================================================================
-- PERCHE'
-- =============================================================================
--
-- `contents.duplicate_of_id` (0001) e `inbox.correlated_content_id` (0005)
-- puntano a `contents (id)` con `ON DELETE SET NULL`, e nessuno dei due aveva
-- un indice. Ogni contenuto tolto dalla conservazione obbligava SQLite a
-- percorrere per intero `contents` e `inbox` per trovare chi lo nominava:
-- su un archivio di prova, 1000 contenuti tolti su 4000 costavano 1384 ms
-- senza indici e 22 ms con; raddoppiando l'archivio, 6175 ms contro 59 ms.
-- La conservazione tiene il lucchetto di scrittura per tutto quel tempo, e
-- l'acquisizione, che aspetta al piu' cinque secondi, falliva.
--
-- =============================================================================
-- CHE COSA CAMBIA
-- =============================================================================
--
-- Solo due indici. Interi e non parziali: la ricerca che SQLite compie per una
-- chiave esterna e' interna al motore, e un indice intero e' quello che la
-- documentazione di SQLite raccomanda sulla colonna figlia, senza dipendere da
-- come il pianificatore deduca la condizione. Nessun dato si sposta, nessuna
-- colonna cambia.

CREATE INDEX contents_by_duplicate_of
    ON contents (duplicate_of_id);

CREATE INDEX inbox_by_correlated_content
    ON inbox (correlated_content_id);

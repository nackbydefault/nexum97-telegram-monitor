-- Versione del motore che ha prodotto il livello di un contenuto (ENGINE-01).
--
-- # Perche' NULL e non la versione corrente
--
-- I contenuti gia' archiviati furono analizzati da un motore di cui NON SI SA
-- quale fosse: la formula e' cambiata due volte in questo progetto, e nulla
-- registra quale delle due abbia prodotto un livello.
--
-- Scrivere qui la versione corrente sarebbe comodo e falso: direbbe che
-- qualcuno sa quale formula ha prodotto quei livelli, e nessuno lo sa. NULL
-- significa «non registrato», che e' esattamente cio' che il lettore deve
-- sapere — la stessa disciplina con cui la salute di una fonte mai verificata
-- resta Sconosciuta invece di diventare Operativa.
--
-- # Perche' una colonna e non una tabella
--
-- Perche' e' un attributo del contenuto quanto lo e' il suo livello, e vive
-- accanto a esso: sono stati prodotti dallo stesso atto, nello stesso istante,
-- e separarli permetterebbe di avere l'uno senza l'altro.
--
-- # Nessun backfill
--
-- Deliberato, e una prova di migrazione lo impone su un archivio popolato: i
-- contenuti di prima restano senza versione, per sempre. Non e' una lacuna da
-- colmare: e' un fatto della loro storia.

ALTER TABLE contents ADD COLUMN engine_version INTEGER;

-- L'indice serve a chi cerca «quali contenuti sono stati analizzati con il
-- motore N», che e' la domanda del replay: senza, la ricerca leggerebbe
-- l'intero archivio.
CREATE INDEX contents_by_engine ON contents (engine_version);

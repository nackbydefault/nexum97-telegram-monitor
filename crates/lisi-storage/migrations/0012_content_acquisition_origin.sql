-- Come il contenuto è entrato in archivio: osservato dal vivo, o recuperato
-- dopo leggendo la cronologia già pubblicata.
--
-- Perché non bastano i due istanti che ci sono già. `published_at` e
-- `acquired_at` sono colonne diverse, e la distanza fra loro *suggerisce* che
-- un contenuto sia stato recuperato. Suggerire non basta: chi rilegge dovrebbe
-- dedurlo da una differenza di orari, e una deduzione è ciò che un archivio con
-- valore probatorio non deve chiedere a chi lo consulta. Un monitoraggio
-- ripreso pochi secondi dopo un'interruzione produrrebbe una distanza minima e
-- sembrerebbe osservazione dal vivo.
--
-- Il valore predefinito è 'osservato', ed è il **vero** per ogni riga già in
-- archivio: fino a questa migrazione l'unico modo di entrare era essere visti
-- arrivare. Non è una comodità di scrittura, è un fatto.
--
-- Il vincolo `CHECK` sta nello schema e non solo nel dominio: la colonna
-- descrive che cosa l'archivio afferma di aver fatto, e un valore fuori
-- dall'insieme sarebbe un'affermazione che nessuno può interpretare.
ALTER TABLE contents
ADD COLUMN acquisition_origin TEXT NOT NULL DEFAULT 'osservato'
CHECK (acquisition_origin IN ('osservato', 'recuperato'));

-- Indice parziale sui soli recuperati: sono la minoranza, e la domanda che si
-- pone davvero è «che cosa non ho visto arrivare». Un indice completo
-- occuperebbe spazio per rispondere anche alla domanda che nessuno fa.
CREATE INDEX contents_recovered ON contents (session_id, acquisition_origin)
WHERE acquisition_origin = 'recuperato';

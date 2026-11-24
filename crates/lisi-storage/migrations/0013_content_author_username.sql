-- Username dell'autore, senza chiocciola, quando ne ha uno.
--
-- È il terzo campo che descrive chi ha scritto, e i tre non sono ridondanti:
--
--   author             il nome leggibile, quello che si scrive in un rapporto
--   author_username    come lo si ritrova su Telegram oggi
--   author_identifier  l'unico che regge nel tempo
--
-- Uno username **non è un'identità**: può essere rilasciato e preso da qualcun
-- altro, e fra un anno può indicare una persona diversa. Conservarlo serve a
-- ritrovare qualcuno adesso, non ad attribuirgli un messaggio in seguito. Chi
-- legge questa colonna in un'indagine deve saperlo, e per questo la ragione sta
-- qui e non solo nel codice.
--
-- Assente per i messaggi di canale, che non hanno un autore individuale, e per
-- gli utenti che semplicemente non hanno uno username: sono la maggioranza, e
-- l'assenza non è un difetto di acquisizione.
ALTER TABLE contents ADD COLUMN author_username TEXT;

-- Indice parziale: la domanda che si pone è «da chi», e chi non ha username non
-- risponde a quella domanda. Un indice completo occuperebbe spazio per le righe
-- che non verranno mai cercate così.
CREATE INDEX contents_by_author_username ON contents (author_username)
WHERE author_username IS NOT NULL;

-- Migrazione 0008 - impostazioni delle notifiche, per postazione.
--
-- Riservatezza, soglia, tetto per sessione e inclusione dell'URL con cui si
-- decide di notificare. Non sono segreti (la scelta di nascondere protegge da
-- una fuga sulla schermata bloccata, ma la scelta in se' non e' un segreto):
-- stanno nell'archivio, gia' ristretto al profilo, non in un file protetto.
--
-- Una riga sola. Con una riga predefinita sempre presente, "non ancora
-- impostato" e "impostazioni predefinite" sono la stessa cosa: chi legge non
-- gestisce l'assenza. I valori qui sotto sono gli stessi del Default di Rust, e
-- un test lo verifica.

CREATE TABLE notification_settings (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    privacy         TEXT NOT NULL CHECK (privacy IN ('full', 'reduced', 'confidential')),
    minimum_level   INTEGER NOT NULL CHECK (minimum_level BETWEEN 1 AND 4),
    max_per_session INTEGER NOT NULL CHECK (max_per_session BETWEEN 0 AND 1000),
    include_url     INTEGER NOT NULL CHECK (include_url IN (0, 1))
);

-- La riga predefinita: riservatezza ridotta, soglia al livello 1, tetto 50,
-- nessun URL. Prudente, e allineata al Default del dominio.
INSERT INTO notification_settings (id, privacy, minimum_level, max_per_session, include_url)
VALUES (1, 'reduced', 1, 50, 0);

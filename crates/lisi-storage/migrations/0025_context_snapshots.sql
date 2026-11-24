-- Fotografie del contesto (CTX-06).
--
-- # Che cosa e' una fotografia, e che cosa NON e'
--
-- E' cio' che una persona ha visto attorno a un messaggio, in un istante
-- preciso, e ha deciso di conservare dicendo perche'. NON e' una prova
-- acquisita: la prova sta in `contents`, e' stata acquisita dal monitoraggio
-- con la sua disciplina, e non cambia.
--
-- Il congelamento lo scrive: «scorrere la vista NON trasforma cio' che si vede
-- in prova operativa». Il modo di non tradirlo non e' scriverlo da qualche
-- parte: e' che il salvataggio sia un ATTO SEPARATO, con un nome, una ragione e
-- un istante — e che avvenga in una tabella diversa da quella dei contenuti,
-- senza alcun percorso che porti dall'una all'altra.
--
-- # Perche' due tabelle e non una
--
-- Perche' una fotografia e' UNA cosa — un atto, con un autore e una ragione — e
-- contiene MOLTE righe. Metterle insieme obbligherebbe a ripetere l'autore e la
-- ragione su ogni riga, e righe che si ripetono sono righe che prima o poi
-- divergono.
--
-- # Perche' la ragione e' NOT NULL
--
-- Perche' conservare cio' che si vede su Telegram e' un atto di cui qualcuno
-- risponde, e un atto senza ragione non e' documentato: e' soltanto avvenuto.
-- E' la stessa disciplina delle revisioni che contraddicono il motore, dove una
-- decisione senza motivo viene rifiutata.
--
-- Una colonna che ammettesse NULL renderebbe la ragione una cortesia. NOT NULL
-- la rende una condizione.
--
-- # Perche' l'integrita' e' una colonna e non un calcolo di chi legge
--
-- Perche' serve a rispondere a «questa fotografia e' quella che fu presa?», e
-- la risposta va confrontata con qualcosa di registrato ALLORA. L'impronta
-- copre l'atto e tutte le sue righe, e si ricalcola per verificarla.
--
-- # Perche' il confronto e' conservato e non ricalcolato
--
-- Perche' era un'osservazione DATATA. Ricalcolarlo domani, sui testi di domani,
-- direbbe che quel giorno si era osservato qualcosa che non si era osservato.
-- Le colonne restano NULL quando il confronto non fu fatto: NULL dice «non
-- confrontato», che non e' «i testi coincidevano».

CREATE TABLE context_snapshots (
    id INTEGER PRIMARY KEY,
    -- Il contenuto dell'archivio attorno a cui si guardava: la prova.
    content_id INTEGER NOT NULL REFERENCES contents (id) ON DELETE RESTRICT,
    -- La fonte da cui il contenuto proviene. Ridondante rispetto al contenuto,
    -- e conservata perche' una fotografia deve restare leggibile per se': dire
    -- da dove veniva senza dover risalire a un'altra tabella e' cio' che il
    -- congelamento chiede con la parola «provenienza».
    source_id INTEGER NOT NULL REFERENCES sources (id) ON DELETE RESTRICT,
    -- Chi l'ha presa. Un atto di cui qualcuno risponde ha un nome.
    taken_by TEXT NOT NULL,
    -- Perche'. NOT NULL: vedere sopra.
    reason TEXT NOT NULL,
    -- Quando e' stata presa, cioe' quando la persona ha deciso di conservare.
    taken_at INTEGER NOT NULL,
    -- Quando il contorno era stato LETTO da Telegram. E' un istante diverso, e
    -- puo' precedere di minuti: chi guarda una vista aperta da un quarto d'ora
    -- conserva cio' che si vedeva un quarto d'ora fa.
    observed_at INTEGER NOT NULL,
    -- L'identificativo remoto del messaggio scelto, come stringa: e' cio' che
    -- il congelamento chiede con «identificativi dei messaggi».
    anchor_remote_message_id TEXT NOT NULL,
    -- L'impronta del testo ACQUISITO, cioe' della prova, al momento della
    -- fotografia. Serve a riconoscere, domani, se la fotografia riguardi lo
    -- stesso testo che l'archivio conserva ancora.
    anchor_digest TEXT NOT NULL,
    -- Il confronto come fu osservato ALLORA. NULL quando non fu fatto.
    comparison_change TEXT,
    comparison_divergence TEXT,
    -- L'istante che Telegram dichiarava come modifica, quando lo dichiarava.
    declared_edit_at INTEGER,
    -- Impronta dell'atto e di tutte le sue righe.
    integrity TEXT NOT NULL
);

-- Le righe del contorno, nell'ordine in cui furono viste.
--
-- # Perche' il testo si conserva
--
-- Perche' una fotografia che conservasse i soli identificativi non sarebbe
-- rileggibile: domani quei messaggi possono non esserci piu', ed e' proprio il
-- caso in cui una fotografia serve.
--
-- # Perche' questo testo NON e' una prova
--
-- Perche' fu letto adesso, non acquisito. Sta in una tabella diversa da
-- `contents`, e nessun percorso porta da qui a la': non esiste una funzione che
-- trasformi una riga di fotografia in un contenuto, e una prova lo verifica.
CREATE TABLE context_snapshot_messages (
    snapshot_id INTEGER NOT NULL REFERENCES context_snapshots (id) ON DELETE CASCADE,
    -- Posizione nell'ordine in cui furono viste, dal piu' vecchio al piu'
    -- recente. Conservare l'ordine e' conservare il discorso.
    position INTEGER NOT NULL,
    remote_message_id TEXT NOT NULL,
    published_at INTEGER NOT NULL,
    body TEXT NOT NULL,
    -- La frase su chi ha scritto, composta dal servizio (CTX-04) e conservata
    -- COSI' COM'ERA: ricomporla domani, con il codice di domani, direbbe che
    -- quel giorno si era letta una frase che non si era letta.
    author_sentence TEXT NOT NULL,
    relations_sentence TEXT,
    is_anchor INTEGER NOT NULL,
    PRIMARY KEY (snapshot_id, position)
);

-- L'indice serve a «quali fotografie sono state prese di questo contenuto»,
-- che e' la domanda che si pone aprendone il pannello.
CREATE INDEX context_snapshots_by_content ON context_snapshots (content_id, taken_at);

-- UNA FOTOGRAFIA E' IMMUTABILE PER COSTRUZIONE.
--
-- Non e' una convenzione da ricordare: e' l'archivio che rifiuta. Una
-- fotografia modificabile non documenterebbe nulla — direbbe cio' che si vuole
-- che dica oggi, e l'impronta registrata non varrebbe piu' niente.
CREATE TRIGGER context_snapshots_are_immutable
    BEFORE UPDATE ON context_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia del contesto e'' immutabile');
END;

CREATE TRIGGER context_snapshots_are_not_deleted
    BEFORE DELETE ON context_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia del contesto non si cancella');
END;

CREATE TRIGGER context_snapshot_messages_are_immutable
    BEFORE UPDATE ON context_snapshot_messages
BEGIN
    SELECT RAISE(ABORT, 'le righe di una fotografia sono immutabili');
END;

CREATE TRIGGER context_snapshot_messages_are_not_deleted
    BEFORE DELETE ON context_snapshot_messages
BEGIN
    SELECT RAISE(ABORT, 'le righe di una fotografia non si cancellano');
END;

-- Migrazione 0023 - le verifiche di salute di una fonte.
--
-- ---------------------------------------------------------------------------
-- PERCHE' SERVE UNA TABELLA, QUANDO QUASI MAI SERVE
--
-- HEALTH-01 deve distinguere una fonte SILENZIOSA da una fonte GUASTA. Con i
-- dati che l'archivio conservava prima di questa migrazione la distinzione
-- NON era ricostruibile:
--
--   contents.acquired_at   dice quando e' arrivato l'ultimo messaggio. Su un
--                          canale che non pubblica da un mese vale come su un
--                          canale a cui l'account ha perso l'accesso: in
--                          entrambi i casi, nulla.
--   faults                 registra soltanto i fallimenti. Il silenzio di
--                          faults non e' la prova che qualcosa funzioni.
--   inbox                  dichiara 'source_available' e 'source_unavailable'
--                          fra i propri event_kind, ma NESSUNA riga di codice
--                          li ha mai emessi: gli eventi di connessione e di
--                          errore nascono senza chat_id, quindi senza fonte.
--
-- Manca il fatto positivo: "a questo istante, questa fonte risultava
-- raggiungibile da questo account". Senza di esso una fonte silenziosa e una
-- fonte mai verificata sono indistinguibili, ed e' esattamente l'errore che
-- HEALTH-01 esiste per impedire. Non e' derivabile: va osservato e scritto.
--
-- ---------------------------------------------------------------------------
-- DA DOVE VIENE L'OSSERVAZIONE
--
-- Da `accessible_chats()`, l'operazione ufficiale gia' usata quando si aggiunge
-- una fonte: elenca le chat a cui l'account HA GIA' accesso. Non cerca, non fa
-- entrare in alcun gruppo, e una sola chiamata verifica TUTTE le fonti di un
-- account. Il costo verso Telegram non cresce con il numero di fonti.
--
-- ---------------------------------------------------------------------------
-- PERCHE' APPEND-ONLY
--
-- Perche' e' evidenza. "Perche' questa fonte risulta in errore?" si risponde
-- nominando l'osservazione che lo ha stabilito e il suo istante (PROV-01,
-- ADR-0052). Una riga che si potesse riscrivere non potrebbe piu' rispondere.

CREATE TABLE source_health_checks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id  INTEGER NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    -- Quale account ha osservato. Annullabile perche' una fonte puo' non essere
    -- associata ad alcun account (le fonti anteriori al multi-account), e
    -- perche' la cancellazione di un account non deve cancellare la storia di
    -- cio' che quell'account aveva osservato.
    account_id INTEGER REFERENCES telegram_accounts (id) ON DELETE SET NULL,
    -- Che cosa la verifica ha appreso DELLA FONTE.
    --
    -- 'check_failed' e' l'unico esito NON conclusivo: dice che il prodotto ha
    -- provato e non ci e' riuscito, e quindi non ha appreso nulla. Si registra
    -- lo stesso, perche' "non ho potuto guardare" e "nessuno ha mai guardato"
    -- sono due cose diverse.
    outcome    TEXT NOT NULL CHECK (outcome IN (
        'reachable', 'history_unreadable', 'not_accessible', 'check_failed')),
    -- Classe dell'errore, quando la verifica non e' riuscita, o precisazione
    -- dell'esito. COSTANTE DEL PRODOTTO: mai il testo di un errore remoto.
    detail     TEXT,
    observed_at INTEGER NOT NULL
);

-- La lettura che serve e' sempre la stessa: le ultime righe di una fonte, dalla
-- piu' recente. L'indice la copre per intero.
CREATE INDEX source_health_checks_by_source
    ON source_health_checks (source_id, observed_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- IMMUTABILITA'
--
-- Un'osservazione si aggiunge, non si cambia. E' la stessa regola delle
-- versioni di un contenuto (0005) e per la stessa ragione: in un archivio
-- probatorio il fatto che qualcosa sia stato osservato in un certo istante e'
-- spesso l'informazione piu' utile, e non deve poter sparire.

CREATE TRIGGER source_health_checks_are_immutable
    BEFORE UPDATE ON source_health_checks
BEGIN
    SELECT RAISE(ABORT, 'una verifica di salute e'' immutabile');
END;

CREATE TRIGGER source_health_checks_are_not_deleted
    BEFORE DELETE ON source_health_checks
BEGIN
    SELECT RAISE(ABORT, 'una verifica di salute non si cancella');
END;

-- ---------------------------------------------------------------------------
-- NESSUN BACKFILL
--
-- Le fonti gia' configurate NON ricevono alcuna riga. Restano "Sconosciute"
-- finche' una verifica reale non le osserva.
--
-- Inventare un'osservazione mai avvenuta - anche solo scrivendo "raggiungibile"
-- per le fonti che hanno prodotto contenuti - direbbe che qualcuno ha guardato
-- quando nessuno ha guardato. E' la falsa evidenza che questo prodotto rifiuta
-- ovunque, e qui costerebbe la fiducia nella schermata che deve dire proprio
-- quali fonti sono verificate.

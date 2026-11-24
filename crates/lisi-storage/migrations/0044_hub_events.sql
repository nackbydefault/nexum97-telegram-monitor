-- La sequenza autorevole degli eventi dell'Hub.
--
-- Motivata in ADR-0086 e DEC-324 (HUB-EVENT-01), attua ADR-0042 decisione 7.
--
-- ===========================================================================
-- IL NUMERO NON HA SALTI, E NON E' UN AUTOINCREMENT.
--
-- `sequence` e' «il piu' alto finora, piu' uno», calcolato dentro la stessa
-- transazione che scrive la riga. Un AUTOINCREMENT sarebbe piu' comodo e
-- lascerebbe BUCHI: SQLite non riusa i numeri, e una transazione annullata ne
-- consumerebbe uno.
--
-- I buchi non sono un dettaglio estetico. Un client che riceve il 41 dopo il 39
-- deve poter dire CON CERTEZZA che gli manca qualcosa: con i salti, «e' andato
-- perso» e «non e' mai esistito» diventano indistinguibili, e un buco nella
-- storia di un fascicolo non si recupera.
--
-- ===========================================================================
-- L'ORDINE E' IL NUMERO, MAI L'ORA.
--
-- `recorded_at` e' un fatto da mostrare. L'orologio di una postazione si
-- sposta - lo dice ADR-0083 a proposito della fiducia - e un ordinamento per
-- ora riordinerebbe a posteriori una storia gia' consegnata ai client.
--
-- ===========================================================================
-- APPEND-ONLY, COME L'AUDIT E PER LA STESSA RAGIONE.
--
-- Questi eventi sono cio' che i client hanno gia' visto. Riscriverne uno
-- significherebbe riscrivere una storia che qualcun altro possiede, e le due
-- copie divergerebbero in silenzio.

CREATE TABLE hub_events (
    sequence    INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    subject     TEXT NOT NULL,
    detail      TEXT,
    recorded_at INTEGER NOT NULL,

    CHECK (sequence > 0)
);

CREATE INDEX hub_events_by_kind ON hub_events (kind, sequence);

CREATE TRIGGER hub_events_refuses_update
BEFORE UPDATE ON hub_events
BEGIN
SELECT RAISE(ABORT, 'eventi dell''Hub append-only: la modifica non e'' ammessa');
END;

CREATE TRIGGER hub_events_refuses_delete
BEFORE DELETE ON hub_events
BEGIN
SELECT RAISE(ABORT, 'eventi dell''Hub append-only: la cancellazione non e'' ammessa');
END;

-- ---------------------------------------------------------------------------
-- IL NOME DEL FLUSSO
--
-- Un Hub reinstallato riparte dal numero uno. Un client che aveva visto il 500
-- chiederebbe «dopo il 500», riceverebbe niente, e leggerebbe quel niente come
-- «non e' successo nulla»: il modo peggiore di sbagliare, perche' sembra
-- normale.
--
-- Questa riga - una sola, garantita dal CHECK sulla chiave - da' un nome alla
-- storia. Un client presenta il nome insieme al numero, e se non coincide il
-- verdetto non e' «nulla di nuovo», e' «questa non e' la storia che seguivi».
--
-- Nasce alla prima richiesta, non all'installazione: una postazione che non fa
-- da Hub non ha un flusso, e la tabella resta vuota.

CREATE TABLE hub_event_stream (
    id         INTEGER PRIMARY KEY,
    stream_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL,

    CHECK (id = 1),
    CHECK (length(stream_id) = 32)
);

CREATE TRIGGER hub_event_stream_refuses_update
BEFORE UPDATE ON hub_event_stream
BEGIN
SELECT RAISE(ABORT, 'il flusso dell''Hub non si rinomina');
END;

CREATE TRIGGER hub_event_stream_refuses_delete
BEFORE DELETE ON hub_event_stream
BEGIN
SELECT RAISE(ABORT, 'il flusso dell''Hub non si cancella');
END;

-- Migrazione 0007 - notifiche emesse.
--
-- Registra che una segnalazione e' stata notificata all'operatore, per non
-- notificarla due volte: la stessa segnalazione a ogni riavvio o a ogni ripresa
-- dopo un crash sarebbe rumore. La deduplica e' un vincolo di schema -- una
-- notifica per contenuto -- come per il resto dell'archivio.
--
-- Il testo mostrato (che dipende dalla riservatezza) NON si conserva: qui sta
-- solo il fatto che la notifica c'e' stata, con quale livello di riservatezza e
-- per quale contenuto. Conservare il testo duplicherebbe il contenuto in una
-- forma in piu' senza scopo.

CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id INTEGER NOT NULL REFERENCES contents (id) ON DELETE RESTRICT,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    privacy    TEXT NOT NULL CHECK (privacy IN ('full', 'reduced', 'confidential')),
    level      INTEGER NOT NULL CHECK (level BETWEEN 0 AND 4),
    emitted_at INTEGER NOT NULL
);

-- Una notifica per contenuto: la deduplica non e' un controllo applicativo che
-- una corsa aggira, e' il vincolo stesso.
CREATE UNIQUE INDEX notifications_by_content ON notifications (content_id);
CREATE INDEX notifications_by_session ON notifications (session_id);

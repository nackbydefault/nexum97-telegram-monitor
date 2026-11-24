-- Migrazione 0016 - la cartella in cui l'ufficio conserva i documenti.
--
-- Fino a qui i rapporti in testo uscivano SEMPRE in
-- %LOCALAPPDATA%\<dati>\esportazioni, senza che nessuno potesse dire altrove.
-- Il pacchetto della schermata Report invece la cartella la faceva scegliere,
-- ma a ogni generazione e senza ricordarla: due comportamenti diversi per la
-- stessa domanda, e nessuno dei due era quello che serve a un ufficio, dove i
-- documenti vanno su un condiviso o in una cartella di servizio.
--
-- Una riga sola, come per le impostazioni delle notifiche (0008). Qui pero'
-- NULL ha un significato ed e' quello giusto: «la cartella predefinita della
-- postazione». A differenza del profilo documentale (0015), dove l'assenza di
-- riga distingueva «mai chiesto» da «rifiutato», qui non c'e' niente da
-- distinguere: chi non ha scelto usa la predefinita, ed e' la stessa cosa.
--
-- Il percorso NON e' un segreto e sta in chiaro. E' pero' un ingresso di cui
-- non ci si fida al momento della RILETTURA: il dominio lo riconvalida
-- (assoluto, senza risalite), perche' un archivio modificato a mano potrebbe
-- farci scrivere dove non dobbiamo.

CREATE TABLE export_destination (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    -- NULL = cartella predefinita della postazione.
    path       TEXT,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

-- La riga predefinita esiste da subito, cosi' chi legge non gestisce l'assenza.
-- `updated_by` dice 'sistema' perche' nessun operatore ha ancora scelto: il
-- primo che sceglie lascera' il proprio nome.
INSERT INTO export_destination (id, path, updated_at, updated_by)
VALUES (1, NULL, 0, 'sistema');

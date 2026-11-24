-- Migrazione 0021 - l'arruolamento dei dispositivi presso un Hub.
--
-- ---------------------------------------------------------------------------
-- PERCHE' QUESTE TABELLE STANNO NELL'ARCHIVIO DELLA POSTAZIONE
--
-- Perche' l'Hub NON e' un'altra macchina: ADR-0042 decisione 4 lo dice per
-- intero. «Nel modello dell'Hub non c'e' alcuna postazione che sorvegli
-- qualcosa per conto proprio: l'Hub E' la postazione.» E' questo prodotto, in
-- una modalita' diversa.
--
-- Su una postazione che non fa da Hub queste tabelle restano vuote, e costano
-- lo spazio di tre definizioni. L'alternativa - un archivio separato - avrebbe
-- richiesto una seconda connessione, un secondo percorso da proteggere e una
-- seconda migrazione da tenere allineata, per non risparmiare nulla.
--
-- ---------------------------------------------------------------------------
-- IL CODICE NON SI CONSERVA: SE NE CONSERVA L'IMPRONTA
--
-- Chi legge l'archivio di un Hub non deve trovarci autorizzazioni vive. Un
-- codice non ancora usato E' un'autorizzazione: chi lo leggesse potrebbe
-- arruolare un dispositivo proprio.
--
-- L'impronta NON e' salata, a differenza delle parole di sblocco. La ragione e'
-- scritta accanto al tipo: una parola scelta da una persona sta in un
-- dizionario, ottanta bit del generatore crittografico no. Contro un ingresso
-- senza dizionario il sale aggiungerebbe una colonna e nessuna protezione, e
-- una protezione apparente e' peggio di nessuna.
--
-- ---------------------------------------------------------------------------
-- IL VINCOLO UNICO **E'** L'USO UNICO
--
-- Stesso meccanismo gia' usato per la deduplica delle notifiche, e per la
-- stessa ragione: fra una lettura e la scrittura che ne consegue c'e' una
-- finestra, e in quella finestra due richieste possono decidere entrambe che il
-- codice e' libero.
--
-- Qui la finestra sarebbe grave: due dispositivi entrerebbero con
-- un'autorizzazione sola, e chi l'ha emessa ne conterebbe uno.
--
-- La chiusura non e' il vincolo unico su `code_hash` - quello impedisce due
-- codici uguali, non due usi dello stesso - ma la CLAUSOLA `consumed_by IS
-- NULL` nell'aggiornamento che lo consuma: chi scrive legge quante righe ha
-- toccato, e chi ne tocca zero ha perso la corsa. Il codice applicativo non si
-- fida del controllo che precede la scrittura.

CREATE TABLE enrollment_codes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    -- SHA-256 del codice in forma canonica. Mai il codice.
    code_hash      TEXT NOT NULL UNIQUE,
    -- Chi lo ha emesso. E' un attore dell'audit, non un dispositivo.
    issued_by      TEXT NOT NULL,
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    -- L'identificativo del dispositivo che lo ha usato, e quando.
    --
    -- Restano dopo l'uso invece di essere cancellati: mesi dopo, chi indaga su
    -- un dispositivo deve poter risalire a QUALE autorizzazione lo ha fatto
    -- entrare e CHI l'aveva emessa. Un codice cancellato dopo l'uso spezzerebbe
    -- quella catena proprio dove serve.
    consumed_by    TEXT,
    consumed_at    INTEGER,

    CHECK (expires_at > issued_at),
    -- Consumato vuol dire entrambe le cose, o nessuna: una riga con l'istante e
    -- senza il dispositivo direbbe che qualcuno e' entrato senza dire chi.
    CHECK ((consumed_by IS NULL) = (consumed_at IS NULL))
);

CREATE INDEX idx_enrollment_codes_scadenza
    ON enrollment_codes (expires_at);

-- ---------------------------------------------------------------------------
-- I DISPOSITIVI AMMESSI
--
-- `token_verifier` e' l'impronta del gettone, non il gettone. L'Hub puo'
-- VERIFICARE chi si presenta e non puo' PRESENTARSI al posto suo: chi rubasse
-- questa tabella non otterrebbe credenziali utilizzabili.
--
-- Il sale NON e' qui. Lo conserva il dispositivo, che e' l'unico che ne ha
-- bisogno per ricalcolare il proprio gettone. Conservarlo anche qui sarebbe una
-- seconda copia di un dato che l'Hub non usa mai.
--
-- ---------------------------------------------------------------------------
-- LA REVOCA STA QUI, ED E' QUESTA CHE CONTA
--
-- ADR-0046 decisione 4 lo aveva gia' dichiarato dal lato del client: lo stato
-- di ritiro conservato sulla postazione e' una copia che spiega, non una
-- difesa, perche' chi prende la macchina riscrive il file.
--
-- Questa riga e' l'altra meta': la revoca che ferma davvero un dispositivo e'
-- quella scritta qui, sull'Hub, dove il dispositivo non arriva.
--
-- La riga NON si cancella. Un dispositivo ritirato deve restare leggibile:
-- cancellarlo renderebbe indistinguibile «non e' mai entrato» da «e' entrato ed
-- e' stato ritirato», che sono due fatti diversi per chi indaga.

CREATE TABLE enrolled_devices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      TEXT NOT NULL UNIQUE,
    label          TEXT NOT NULL,
    -- SHA-256 del gettone. Mai il gettone.
    token_verifier TEXT NOT NULL,
    enrolled_at    INTEGER NOT NULL,
    -- Con quale autorizzazione e' entrato. La catena verso chi l'ha emessa.
    enrolled_with  INTEGER NOT NULL REFERENCES enrollment_codes (id),
    revoked_at     INTEGER,
    revoked_reason TEXT,

    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

CREATE INDEX idx_enrolled_devices_arruolamento
    ON enrolled_devices (enrolled_at DESC);

-- ---------------------------------------------------------------------------
-- I TENTATIVI A VUOTO
--
-- Ottanta bit non si indovinano. Ma un Hub che accettasse tentativi senza
-- limite lascerebbe provare per sempre, e «non si indovina» diventerebbe una
-- promessa fondata su un solo numero.
--
-- Questa tabella conserva SOLO l'istante e la ragione. Non il codice tentato,
-- nemmeno in impronta: un tentativo e' un'azione, e l'audit documenta le azioni
-- e non i dati su cui insistono. Un archivio che conservasse i codici tentati
-- sarebbe un elenco di cose che qualcuno ha creduto potessero funzionare.
--
-- ---------------------------------------------------------------------------
-- IL COMPROMESSO, DICHIARATO
--
-- Il blocco e' dell'HUB e del SOLO ARRUOLAMENTO, non del dispositivo: chi tenta
-- non sa quale dispositivo sta bloccando, e non puo' quindi prendere di mira
-- qualcuno.
--
-- Il rovescio e' che chi tenta puo' impedire un arruolamento legittimo per la
-- durata della finestra. E' accettabile perche' l'arruolamento e' un atto raro
-- e programmato: chi lo trova bloccato aspetta un quarto d'ora, e intanto ha
-- imparato che qualcuno sta tentando - che senza il blocco non saprebbe.

CREATE TABLE enrollment_failures (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    -- La ragione breve del rifiuto. Mai il codice tentato.
    reason         TEXT NOT NULL,
    happened_at    INTEGER NOT NULL
);

CREATE INDEX idx_enrollment_failures_quando
    ON enrollment_failures (happened_at DESC);

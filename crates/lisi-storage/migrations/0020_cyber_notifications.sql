-- Migrazione 0020 - notifiche degli eventi cyber, e le loro soglie.
--
-- ---------------------------------------------------------------------------
-- PERCHE' UNA TABELLA SEPARATA DA `notifications`
--
-- Una notifica ordinaria riguarda UN CONTENUTO: la sua chiave e' il contenuto,
-- e la deduplica dice "questo messaggio e' gia' stato annunciato".
--
-- Una notifica cyber riguarda un GRAPPOLO, che non e' una riga di archivio: e'
-- il risultato di una correlazione, e la sua identita' e' la coppia
-- (indicatore, valore) dentro una sessione. Non esiste un `cyber_event_id` da
-- mettere in chiave esterna, perche' i grappoli si ricalcolano a ogni lettura
-- (DEC-221): conservarli sarebbe una seconda verita' da tenere allineata.
--
-- Mettere le due cose nella stessa tabella avrebbe richiesto una colonna nulla
-- per meta' delle righe e una chiave che significa due cose diverse a seconda
-- di quale colonna e' piena.
--
-- ---------------------------------------------------------------------------
-- IL VINCOLO UNICO **E'** LA DEDUPLICA
--
-- E' lo stesso meccanismo di `notifications`, e per la stessa ragione: una
-- lettura seguita da una scrittura lascia una finestra fra le due, e in quella
-- finestra due valutazioni possono decidere entrambe di notificare. Il vincolo
-- la chiude, e il codice legge l'esito dell'inserimento invece di fidarsi del
-- controllo che lo precede.
--
-- La conseguenza voluta: **un grappolo si annuncia UNA VOLTA SOLA**, per tutta
-- la vita della sessione. Un grappolo che cresce non produce altri avvisi.
--
-- L'alternativa considerata e scartata: riannunciare quando il grappolo
-- raddoppia. Sarebbe stata limitata - al piu' log2(n) avvisi - e comunque
-- sbagliata. Il mestiere di una notifica e' far guardare qualcuno; una volta
-- che ha guardato, ridirglielo non aggiunge nulla che non veda aprendo la
-- schermata, e un secondo avviso sullo stesso gruppo insegna a ignorare il
-- primo. La crescita si vede in Cyber Watch, che e' il posto per guardarla.

CREATE TABLE cyber_notifications (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    -- Il genere e il valore dell'indicatore che tiene insieme il grappolo.
    -- Sono la sua identita': non c'e' altro che lo identifichi in modo stabile.
    indicator_kind  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    -- Quanto era grande il grappolo QUANDO e' stato annunciato.
    --
    -- Non e' una curiosita': permette di rileggere, mesi dopo, che cosa
    -- l'operatore aveva davanti nel momento in cui il prodotto ha chiesto la
    -- sua attenzione. Un grappolo che oggi ha ottanta contenuti puo' essere
    -- stato annunciato quando ne aveva due.
    contents_at_emission        INTEGER NOT NULL CHECK (contents_at_emission >= 0),
    distinct_sources_at_emission INTEGER NOT NULL CHECK (distinct_sources_at_emission >= 0),
    -- La riservatezza con cui e' stato annunciato, come per le notifiche
    -- ordinarie: dice quanto l'avviso ha rivelato, non che cosa diceva.
    privacy        TEXT NOT NULL CHECK (privacy IN ('full', 'reduced', 'confidential')),
    emitted_at     INTEGER NOT NULL,

    UNIQUE (session_id, indicator_kind, indicator_value)
);

CREATE INDEX idx_cyber_notifications_session
    ON cyber_notifications (session_id, emitted_at DESC);

-- ---------------------------------------------------------------------------
-- LE SOGLIE
--
-- Due, e non una, perche' rispondono a due domande diverse:
--
--   - QUANTI CONTENUTI: quante volte la cosa e' stata detta;
--   - QUANTE FONTI DISTINTE: da quante voci diverse.
--
-- Un grappolo di venti messaggi da una sola fonte e uno di tre messaggi da tre
-- fonti sono due situazioni diverse, e un ufficio puo' volerne sorvegliare una
-- e non l'altra. Una soglia sola avrebbe costretto a sceglierne una.
--
-- **Fonti distinte non sono conferme indipendenti**, e alzare questa soglia non
-- rende cio' che passa piu' attendibile: rende soltanto piu' raro cio' che
-- viene annunciato.
--
-- I predefiniti sono prudenti: tre contenuti da due fonti distinte. Un
-- grappolo esiste gia' con due contenuti, e annunciarlo li' significherebbe un
-- avviso per ogni ripetizione.
ALTER TABLE notification_settings
    ADD COLUMN cyber_minimum_contents INTEGER NOT NULL DEFAULT 3
    CHECK (cyber_minimum_contents BETWEEN 2 AND 100);

ALTER TABLE notification_settings
    ADD COLUMN cyber_minimum_sources INTEGER NOT NULL DEFAULT 2
    CHECK (cyber_minimum_sources BETWEEN 1 AND 100);

-- Spenta per difetto.
--
-- Una capacita' nuova che si accende da sola cambia il comportamento di una
-- postazione gia' in esercizio senza che nessuno lo abbia chiesto. Chi la
-- vuole la accende dalle Impostazioni, e cosi' la prima notifica cyber che
-- arriva e' attesa invece che sorprendente.
ALTER TABLE notification_settings
    ADD COLUMN cyber_enabled INTEGER NOT NULL DEFAULT 0
    CHECK (cyber_enabled IN (0, 1));

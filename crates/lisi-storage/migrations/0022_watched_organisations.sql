-- Migrazione 0022 - le organizzazioni sorvegliate, e il settore che ne deriva.
--
-- ---------------------------------------------------------------------------
-- PERCHE' L'ELENCO STA QUI E NON NEL SORGENTE
--
-- Lo aveva gia' deciso PD6_SECTOR_TAXONOMY.md il 2026-08-18:
--
--   «Nel prodotto non si scrive alcun elenco di enti "critici". Un elenco di
--   organizzazioni inciso nel codice sarebbe una lista arbitraria che nessuno
--   ha approvato, che invecchia il giorno dopo, e che - distribuita su ogni
--   postazione - dice a chiunque la legga quali enti l'ufficio considera
--   bersagli.»
--
-- Il prodotto porta la TASSONOMIA dei diciotto settori NIS2, che viene da una
-- fonte ufficiale. L'ELENCO DELLE ORGANIZZAZIONI lo dichiara chi amministra la
-- postazione, e vive qui.
--
-- ---------------------------------------------------------------------------
-- LA REGOLA CHE DEC-235 CHIEDEVA
--
-- DEC-235 aveva lasciato `Sector` deliberatamente scollegato: «collegarla
-- richiede una regola che assegni un settore a un contenuto, e nessuna regola
-- verificata esiste».
--
-- La regola e' questa, e non la inventa il prodotto:
--
--   un contenuto ricade in un settore PERCHE' un amministratore ha dichiarato
--   che quella organizzazione appartiene a quel settore, e il contenuto la
--   nomina.
--
-- E' verificabile in ogni passaggio, ed e' per questo che queste tabelle
-- conservano CHI ha dichiarato e QUANDO: un'attribuzione senza provenienza
-- sarebbe l'attribuzione inventata che DEC-235 esisteva per impedire.
--
-- ---------------------------------------------------------------------------
-- PERCHE' SI DISATTIVA INVECE DI CANCELLARE
--
-- Un monitoraggio gia' svolto ha prodotto riscontri che nominano queste
-- organizzazioni. Cancellarne una renderebbe inspiegabile un riscontro gia'
-- registrato: chi rileggesse un vecchio alert troverebbe un settore e nessuna
-- ragione.
--
-- `active` a 0 ferma i riscontri futuri e lascia leggibili quelli passati. La
-- cancellazione vera esiste comunque, per chi ha dichiarato per errore
-- qualcosa che non ha ancora prodotto nulla, ed e' un atto distinto.
--
-- ---------------------------------------------------------------------------
-- ALIAS E DOMINI IN TABELLE PROPRIE
--
-- Si sarebbero potuti scrivere come JSON in una colonna. Non e' stato fatto per
-- due ragioni:
--
--   - un vincolo di unicita' su un JSON non esiste, e due alias identici
--     dentro la stessa organizzazione sarebbero passati;
--   - cercare «quale organizzazione ha dichiarato questo dominio» su un JSON
--     richiede di leggerli tutti.
--
-- Il costo e' due tabelle in piu'. Il guadagno e' che il motore, e non una
-- convenzione di codice, impedisce il doppione.

CREATE TABLE watched_organisations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Il nome con cui l'operatore la riconosce.
    name         TEXT NOT NULL,
    -- L'etichetta stabile del settore NIS2, da `Sector::as_str`. Non un
    -- numero: un numero d'ordine cambierebbe significato il giorno in cui la
    -- direttiva aggiunge un settore in mezzo.
    sector       TEXT NOT NULL,
    note         TEXT,
    -- 1 = partecipa al riscontro.
    active       INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    -- La provenienza della dichiarazione. Senza, un'attribuzione non si
    -- potrebbe contestare.
    declared_by  TEXT NOT NULL,
    declared_at  INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,

    -- Due organizzazioni con lo stesso nome sarebbero indistinguibili
    -- nell'elenco che l'amministratore rilegge.
    UNIQUE (name)
);

CREATE INDEX idx_watched_organisations_attive
    ON watched_organisations (active, name);

-- ---------------------------------------------------------------------------
-- I NOMI CON CUI L'ORGANIZZAZIONE PUO' COMPARIRE
--
-- `written` e' la forma che l'amministratore ha scritto, ed e' cio' che legge
-- chi rilegge la dichiarazione. `normalised` e' la forma con cui si confronta
-- il testo.
--
-- Tenerle separate evita il difetto in cui la forma mostrata e la forma cercata
-- divergono senza che nessuno se ne accorga: e' lo stesso motivo per cui i
-- termini di dizionario conservano entrambe.

CREATE TABLE watched_organisation_aliases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_id INTEGER NOT NULL
                    REFERENCES watched_organisations (id) ON DELETE CASCADE,
    written         TEXT NOT NULL,
    normalised      TEXT NOT NULL,

    -- Lo stesso alias due volte nella stessa organizzazione produrrebbe due
    -- riscontri per un fatto solo.
    UNIQUE (organisation_id, normalised)
);

CREATE INDEX idx_watched_aliases_per_organizzazione
    ON watched_organisation_aliases (organisation_id);

-- ---------------------------------------------------------------------------
-- I DOMINI DICHIARATI
--
-- Il dominio e' l'ancora piu' solida: un nome puo' essere ambiguo o omonimo,
-- mentre chi registra un dominio e' uno solo.
--
-- Il vincolo di unicita' e' GLOBALE e non per organizzazione: lo stesso dominio
-- dichiarato per due organizzazioni diverse produrrebbe due settori per lo
-- stesso fatto, e nessuno dei due sarebbe contestabile piu' dell'altro. Se due
-- organizzazioni condividono davvero un dominio, e' una che va dichiarata.

CREATE TABLE watched_organisation_domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_id INTEGER NOT NULL
                    REFERENCES watched_organisations (id) ON DELETE CASCADE,
    -- Gia' normalizzato in minuscolo e senza punto finale.
    domain          TEXT NOT NULL,

    UNIQUE (domain)
);

CREATE INDEX idx_watched_domains_per_organizzazione
    ON watched_organisation_domains (organisation_id);

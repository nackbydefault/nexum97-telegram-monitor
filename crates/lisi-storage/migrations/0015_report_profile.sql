-- Il profilo documentale dell'ufficio, conservato.
--
-- Motivata in ADR-0031 Decisione 15 e DEC-180. Chiude il debito che DEC-172
-- aveva dichiarato: fino a qui i dati dell'ufficio si compilavano a ogni
-- relazione e non venivano conservati, e `template_version` restava 0 in ogni
-- pacchetto.
--
-- ===========================================================================
-- PERCHE' UNA RIGA SOLA, E COME LO SI IMPONE.
--
-- Il profilo e' uno: quello dell'ufficio che usa questa postazione. `CHECK (id
-- = 1)` lo rende vero **nello schema** invece che in una convenzione che
-- qualcuno prima o poi non rispetta. Un secondo profilo non si puo' scrivere
-- nemmeno per errore.
--
-- ===========================================================================
-- PERCHE' LA PRESENZA DELLA RIGA E' UN'INFORMAZIONE.
--
-- Nessuna riga = **all'operatore non e' ancora stata posta la domanda**. Una
-- riga con tutti i campi vuoti = gliela si e' posta e ha scelto di non
-- rispondere, il che e' una risposta legittima e va ricordata: senza questa
-- distinzione il prodotto richiederebbe gli stessi dati a ogni avvio a chi ha
-- gia' detto di no.
--
-- ===========================================================================
-- PERCHE' `version` CRESCE.
--
-- La fotografia di un report registra con quale versione del profilo e' stato
-- prodotto (`report_packages.template_version`). Senza un numero che cresce,
-- un profilo modificato renderebbe inspiegabile un report vecchio: si vedrebbe
-- l'intestazione di oggi su un documento di sei mesi fa e non ci sarebbe modo
-- di accorgersene.
CREATE TABLE report_profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- Cresce a ogni salvataggio. Parte da 1: la versione 0 significa «nessun
    -- profilo conservato», e appartiene all'assenza della riga.
    version INTEGER NOT NULL CHECK (version >= 1),

    -- I campi del profilo. Tutti facoltativi: un ufficio puo' compilarne
    -- nessuno, alcuni o tutti, e il documento dichiara gli spazi rimasti da
    -- compilare invece di inventarli (DEC-179).
    organisation TEXT,
    office TEXT,
    header_line TEXT,
    recipient TEXT,
    recipient_cc TEXT,
    place TEXT,
    signer_role TEXT,
    signer_name TEXT,
    footer_line TEXT,
    subject_base TEXT,

    -- Lo stemma, come byte di un PNG gia' validato (DEC-178).
    --
    -- Sta qui e non come percorso a un file: un percorso si rompe quando
    -- qualcuno sposta l'immagine, e il documento prodotto sei mesi dopo
    -- perderebbe lo stemma senza che nessuno lo abbia deciso.
    emblem BLOB,

    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

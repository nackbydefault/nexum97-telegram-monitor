-- Dominio Persona persistito (PERS-01).
--
-- # LA GUARDIA DELLA FASE 6, SCRITTA NELLO SCHEMA
--
-- Il congelamento dice: «nessun profilo creato automaticamente per ogni utente
-- che compare in una fonte monitorata».
--
-- Questa tabella non si riempie da sola. Non ha una chiave verso `contents`,
-- non ha un identificativo Telegram, e nessun percorso di acquisizione la
-- nomina: un soggetto ci finisce **perche' una persona ha deciso di aprirlo**,
-- e ha scritto perche'.
--
-- # NON E' L'ELENCO DEI PARTECIPANTI, ED E' LA DISTINZIONE PIU' IMPORTANTE
--
-- «Persone» esiste gia', ed e' DERIVATA: chi ha scritto durante un
-- monitoraggio, ricavato dai messaggi acquisiti. E' un'OSSERVAZIONE, e non
-- afferma niente su nessuno.
--
-- Un soggetto e' un'altra cosa: e' qualcuno su cui l'ufficio ha deciso di
-- aprire un fascicolo investigativo. Confonderli significherebbe che chiunque
-- abbia scritto una volta in un gruppo monitorato diventa un soggetto — che e'
-- esattamente cio' che il congelamento vieta.
--
-- Le due cose restano due, e nessuna riga passa dall'una all'altra da sola.
--
-- # SERVE UNA RAGIONE, E STA QUI
--
-- «Serve una ragione operativa documentata prima di usare le funzioni
-- investigative»: la ragione non e' un'impostazione che si riscrive, e' una
-- colonna di questa riga, protetta da un trigger.
--
-- E' distinta dalla ragione dei partecipanti (ADR-0024), che vale UNA VOLTA e
-- riguarda l'ufficio: «perche' componiamo elenchi di persone». Quella non
-- autorizza ad aprire un fascicolo su un nome, e trattarle come la stessa cosa
-- lascerebbe che una frase scritta un anno fa giustifichi ogni soggetto aperto
-- da allora.
--
-- La regola su che cosa sia una ragione e' UNA SOLA, e vive in
-- `lisi_core::model::reason`. Qui c'e' il vincolo che la fa valere anche per
-- chi scrivesse un secondo servizio domani.
--
-- # NESSUN PUNTEGGIO, E NESSUNA COLONNA IN CUI POSSA STARE
--
-- Il congelamento e' esplicito: «mai una percentuale di pericolosita'»,
-- «nessuna attribuzione automatica di responsabilita'», «nessuna
-- classificazione automatica di una persona come criminale o estremista».
--
-- Il modo di rispettarlo non e' ricordarsene: QUI NON C'E' UNA COLONNA
-- NUMERICA in cui un punteggio possa stare. Non un livello, non un rischio,
-- non una probabilita'. La valutazione umana arrivera' con PERS-05, avra'
-- quattro stati con un nome, e sara' un atto di un operatore con motivo e
-- audit — mai un numero.
CREATE TABLE persons (
    -- L'IDENTIFICATIVO INTERNO STABILE, che il piano chiede.
    --
    -- E' dell'archivio, non della piattaforma: una persona NON e' un account
    -- Telegram. Le identita' osservate arriveranno con PERS-02 e staranno in
    -- un'altra tabella, perche' una persona puo' averne piu' d'una e nessuna
    -- di esse la definisce.
    id INTEGER PRIMARY KEY,

    -- Come l'ufficio chiama questo soggetto.
    --
    -- E' un'etichetta scelta da chi apre, non un dato osservato: il nome che
    -- Telegram mostra puo' cambiare, e non e' il nome di nessuno.
    label TEXT NOT NULL,

    -- PERCHE' E' STATO APERTO. Almeno venti caratteri, come per gli elenchi di
    -- persone: non rende buona una ragione, rende visibile chi non ne scrive
    -- una.
    reason TEXT NOT NULL CHECK (length(trim(reason)) >= 20),

    opened_by TEXT NOT NULL,
    opened_at INTEGER NOT NULL,

    -- LA CHIUSURA: chi, quando, e perche'. I tre valori vanno INSIEME.
    --
    -- Chiudere un soggetto e' un atto quanto aprirlo, e richiede la stessa
    -- ragione: un fascicolo chiuso senza motivo non dice se sia stato chiuso
    -- perche' non c'era niente o perche' nessuno se ne occupava piu'.
    closed_by TEXT,
    closed_at INTEGER,
    closure_reason TEXT CHECK (
        closure_reason IS NULL OR length(trim(closure_reason)) >= 20
    ),

    CHECK (length(trim(label)) > 0),
    CHECK (
        (closed_by IS NULL AND closed_at IS NULL AND closure_reason IS NULL)
        OR (closed_by IS NOT NULL AND closed_at IS NOT NULL
            AND closure_reason IS NOT NULL)
    )
);

CREATE INDEX persons_by_label ON persons (label);

-- CIO' CHE E' STATO SCRITTO ALL'APERTURA NON SI RISCRIVE.
--
-- Il soggetto porta chi lo ha aperto, quando e perche'. Se la ragione potesse
-- cambiare, quei tre valori direbbero che quella persona ha aperto QUEL
-- fascicolo per QUEL motivo quel giorno, e sarebbe falso.
--
-- E' la disciplina delle note (NOTE-01), delle ricerche salvate (SEARCH-01) e
-- dei modelli (TEMPLATE-01) — qui applicata alla cosa che ne ha piu' bisogno.
--
-- L'etichetta e' protetta insieme al resto: rinominare un soggetto dopo averlo
-- aperto per una ragione che nominava il nome vecchio renderebbe la ragione
-- illeggibile.
CREATE TRIGGER persons_opening_is_written_once
    BEFORE UPDATE OF label, reason, opened_by, opened_at ON persons
    WHEN OLD.label <> NEW.label
        OR OLD.reason <> NEW.reason
        OR OLD.opened_by <> NEW.opened_by
        OR OLD.opened_at <> NEW.opened_at
BEGIN
    SELECT RAISE(ABORT, 'cio'' che e'' stato scritto aprendo un soggetto non si riscrive');
END;

-- UN SOGGETTO CHIUSO NON SI RIAPRE.
--
-- Riaprirlo renderebbe la chiusura una parentesi invece che un fatto, e chi
-- avesse letto «chiuso» non avrebbe modo di sapere che adesso non lo e' piu'.
-- Se il lavoro riprende, si apre un soggetto nuovo — con la sua ragione, che
-- e' quella che serve sapere.
--
-- E' la stessa forma del workspace che non si riapre (WS-01).
CREATE TRIGGER persons_closure_stays
    BEFORE UPDATE ON persons
    WHEN OLD.closed_at IS NOT NULL AND NEW.closed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'un soggetto chiuso non si riapre: se il lavoro riprende, se ne apre uno nuovo');
END;

-- Le scoperte pubbliche: che cosa e' stato chiesto, che cosa NON e' stato
-- chiesto, e su quali limiti poggiava.
--
-- Motivata in ADR-0076 e DEC-312.
--
-- ===========================================================================
-- PERCHE' TABELLE PROPRIE, E PERCHE' `contents` NON SI TOCCA.
--
-- ADR-0035 decisione 13 lo dice in una riga: «come e' stato acquisito un
-- contenuto» e «come e' stata scoperta una fonte» sono DUE STORIE DIVERSE, e un
-- candidato non e' un contenuto.
--
-- Aggiungere 'scoperto' accanto a 'osservato' e 'recuperato' in
-- `contents.acquisition_origin` metterebbe la storia di come una FONTE e' stata
-- trovata dentro la colonna che racconta come un CONTENUTO e' arrivato: due
-- domande diverse nella stessa risposta, e da quel momento nessuna delle due si
-- potrebbe piu' porre con precisione.
--
-- ===========================================================================
-- E PERCHE' SI CONSERVA CIO' CHE NON E' STATO CHIESTO.
--
-- Il pianificatore dichiara che cosa ha tagliato. Se l'archivio conservasse solo
-- le domande POSTE, quella dichiarazione vivrebbe per il tempo di una schermata
-- e sparirebbe nel momento esatto in cui serve: quando qualcuno rilegge una
-- scoperta di sei mesi fa.
--
-- Un archivio che conserva solo cio' che e' stato chiesto trasforma
-- automaticamente ogni «non cercato» in un «non trovato», e lo fa in silenzio.

-- ---------------------------------------------------------------------------
-- L'esecuzione, con i limiti su cui poggiava.
--
-- I limiti stanno QUI, non accanto e non altrove: una scoperta senza la misura
-- su cui e' stata fatta e' una scoperta di cui, fra sei mesi, non si puo' dire
-- niente - ne' se il tetto fosse stretto, ne' se i limiti di allora fossero
-- quelli di oggi. E i limiti cambiano: e' l'unica cosa certa di un servizio di
-- qualcun altro.
CREATE TABLE discovery_runs (
    id                  INTEGER PRIMARY KEY,
    started_at          INTEGER NOT NULL,
    -- Dove si e' guardato. Il vincolo sta nello schema perche' un ambito
    -- inventato sarebbe una provenienza che nessuno puo' interpretare.
    scope               TEXT    NOT NULL CHECK (scope IN (
                            'fonti_selezionate',
                            'chat_dell_account',
                            'post_pubblici',
                            'chat_pubbliche_individuate',
                            'esteso'
                        )),

    -- I tetti che venivano dalla POLITICA VALIDATA, cioe' da limiti osservati.
    max_distinct_queries    INTEGER NOT NULL CHECK (max_distinct_queries > 0),
    max_results_per_query   INTEGER NOT NULL CHECK (max_results_per_query > 0),

    -- I tetti NOSTRI, e il nome lo dice: Telegram non li dichiara, li abbiamo
    -- scelti noi (ADR-0075, decisione 6).
    our_page_cap            INTEGER NOT NULL CHECK (our_page_cap > 0),
    our_wait_seconds        INTEGER NOT NULL CHECK (our_wait_seconds > 0),
    our_consecutive_errors  INTEGER NOT NULL CHECK (our_consecutive_errors > 0),

    -- Il ritardo che TELEGRAM dichiarava. Non e' un tetto nostro.
    declared_backoff_seconds INTEGER NOT NULL CHECK (declared_backoff_seconds >= 0),

    -- La misura su cui la politica poggiava, com'era.
    limits_free_per_day     INTEGER NOT NULL CHECK (limits_free_per_day >= 0),
    limits_remaining_free   INTEGER NOT NULL CHECK (limits_remaining_free >= 0),
    limits_observed_at      INTEGER NOT NULL,
    -- Da quale misura vengono quei numeri. Non puo' essere vuota: un numero
    -- senza provenienza non si distingue da uno inventato (ADR-0074).
    limits_origin           TEXT    NOT NULL CHECK (length(trim(limits_origin)) > 0)
);

-- ---------------------------------------------------------------------------
-- Le domande poste, nell'ordine in cui sono state poste.
CREATE TABLE discovery_queries (
    run_id   INTEGER NOT NULL REFERENCES discovery_runs(id),
    position INTEGER NOT NULL CHECK (position >= 0),
    -- Il testo e' gia' normalizzato dal dominio: qui si vieta solo il vuoto,
    -- perche' interrogare il vuoto consuma una quota vera.
    query    TEXT    NOT NULL CHECK (length(trim(query)) > 0),
    PRIMARY KEY (run_id, position)
);

-- ---------------------------------------------------------------------------
-- CIO' CHE NON E' STATO CHIESTO, e perche'.
--
-- E' la tabella che tiene in piedi la differenza fra «non trovato» e «non
-- cercato». I motivi sono tre e distinti perche' portano a tre azioni diverse:
-- correggere il termine, non preoccuparsi, oppure alzare il tetto.
CREATE TABLE discovery_omissions (
    run_id   INTEGER NOT NULL REFERENCES discovery_runs(id),
    position INTEGER NOT NULL CHECK (position >= 0),
    -- Il termine come era stato scritto: e' cio' che l'operatore riconosce.
    term     TEXT    NOT NULL,
    reason   TEXT    NOT NULL CHECK (reason IN (
                 'non_e_un_interrogazione',
                 'gia_chiesta',
                 'tetto_esaurito'
             )),
    PRIMARY KEY (run_id, position)
);

-- ---------------------------------------------------------------------------
-- Cio' che e' stato restituito, con da dove viene.
--
-- L'ambito sta QUI e non solo nell'esecuzione: un'esecuzione estesa mescola
-- risultati che vengono da superfici diverse, e sapere che «questa esecuzione
-- era estesa» non direbbe, di QUESTO risultato, da dove viene (ADR-0074).
CREATE TABLE discovery_results (
    id          INTEGER PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES discovery_runs(id),
    -- Quale domanda lo ha restituito.
    query       TEXT    NOT NULL CHECK (length(trim(query)) > 0),
    scope       TEXT    NOT NULL CHECK (scope IN (
                    'fonti_selezionate',
                    'chat_dell_account',
                    'post_pubblici',
                    'chat_pubbliche_individuate',
                    'esteso'
                )),
    -- IL NOME PUBBLICO ARRIVA DA FUORI e si conserva com'e': l'archivio non lo
    -- interpreta, e chi lo mostra lo tratta come testo non fidato.
    public_name TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- Perche' un risultato e' stato suggerito come fonte.
--
-- Un risultato CON almeno un motivo e' un candidato; uno senza e' solo un
-- risultato. La regola del dominio - un candidato non si costruisce senza un
-- motivo - qui diventa: nessuna riga, nessun candidato.
CREATE TABLE discovery_result_reasons (
    result_id INTEGER NOT NULL REFERENCES discovery_results(id),
    position  INTEGER NOT NULL CHECK (position >= 0),
    reason    TEXT    NOT NULL CHECK (length(trim(reason)) > 0),
    PRIMARY KEY (result_id, position)
);

CREATE INDEX discovery_queries_per_esecuzione ON discovery_queries (run_id);
CREATE INDEX discovery_omissions_per_esecuzione ON discovery_omissions (run_id);
CREATE INDEX discovery_results_per_esecuzione ON discovery_results (run_id);

-- ---------------------------------------------------------------------------
-- UNA SCOPERTA E' UN FATTO AVVENUTO, E NON SI RISCRIVE.
--
-- Non e' uno stato che evolve: e' cio' che e' stato chiesto quel giorno con quei
-- limiti. Correggerla dopo significherebbe riscrivere che cosa si sapeva quando
-- qualcuno ha deciso qualcosa.
CREATE TRIGGER discovery_runs_non_si_modificano
BEFORE UPDATE ON discovery_runs
BEGIN
    SELECT RAISE(ABORT, 'una scoperta gia registrata non si modifica');
END;

CREATE TRIGGER discovery_runs_non_si_cancellano
BEFORE DELETE ON discovery_runs
BEGIN
    SELECT RAISE(ABORT, 'una scoperta gia registrata non si cancella');
END;

CREATE TRIGGER discovery_queries_non_si_modificano
BEFORE UPDATE ON discovery_queries
BEGIN
    SELECT RAISE(ABORT, 'le domande di una scoperta non si modificano');
END;

CREATE TRIGGER discovery_queries_non_si_cancellano
BEFORE DELETE ON discovery_queries
BEGIN
    SELECT RAISE(ABORT, 'le domande di una scoperta non si cancellano');
END;

-- Le omissioni sono la parte che qualcuno sarebbe tentato di togliere, perche'
-- sono molte e sembrano rumore. Sono la differenza fra «non cercato» e «non
-- trovato», e si difendono come le domande.
CREATE TRIGGER discovery_omissions_non_si_modificano
BEFORE UPDATE ON discovery_omissions
BEGIN
    SELECT RAISE(ABORT, 'cio che non e stato chiesto non si modifica');
END;

CREATE TRIGGER discovery_omissions_non_si_cancellano
BEFORE DELETE ON discovery_omissions
BEGIN
    SELECT RAISE(ABORT, 'cio che non e stato chiesto non si cancella');
END;

CREATE TRIGGER discovery_results_non_si_modificano
BEFORE UPDATE ON discovery_results
BEGIN
    SELECT RAISE(ABORT, 'un risultato gia registrato non si modifica');
END;

CREATE TRIGGER discovery_results_non_si_cancellano
BEFORE DELETE ON discovery_results
BEGIN
    SELECT RAISE(ABORT, 'un risultato gia registrato non si cancella');
END;

CREATE TRIGGER discovery_result_reasons_non_si_modificano
BEFORE UPDATE ON discovery_result_reasons
BEGIN
    SELECT RAISE(ABORT, 'il motivo di un suggerimento non si modifica');
END;

CREATE TRIGGER discovery_result_reasons_non_si_cancellano
BEFORE DELETE ON discovery_result_reasons
BEGIN
    SELECT RAISE(ABORT, 'il motivo di un suggerimento non si cancella');
END;

-- Ricerche salvate (SEARCH-01).
--
-- # Che cos'e' una ricerca salvata
--
-- Una ricerca che qualcuno ha gia' fatto e vuole rifare. Porta CHI l'ha
-- salvata e QUANDO, e la query esattamente com'era.
--
-- # UNA SOLA NOZIONE DI RICERCA
--
-- Cercare nello storico esiste da prima di questa milestone: e' il filtro
-- della schermata Storico — testo, livello minimo, solo cio' che attende una
-- decisione — applicato a un ambito. Questa tabella conserva QUEL filtro, e
-- non ne inventa un secondo.
--
-- Il rischio era concreto e dichiarato da NOTE-01: «costruire qui una ricerca
-- sarebbe la seconda nozione di ricerca del prodotto». Le colonne qui sotto
-- sono i campi del filtro, uno per uno, e una prova conta i campi delle due
-- parti: un campo di filtro che non si potesse salvare sarebbe una ricerca che
-- non si puo' rifare.
--
-- # LA CONFIGURAZIONE IN FORZA, E PERCHE'
--
-- Rifare la stessa ricerca sei mesi dopo NON riproduce lo stesso risultato, e
-- non solo perche' e' arrivato materiale nuovo.
--
-- I livelli non si ricalcolano a ogni lettura: sono stati prodotti
-- dall'analisi al momento dell'acquisizione, da UNA VERSIONE DEL MOTORE. Se
-- quella versione cambia, una ricerca «livello almeno 3» rifatta oggi mette
-- insieme righe valutate da motori diversi — e nulla, senza questa colonna, lo
-- direbbe.
--
-- Perche' NOT NULL: al momento del salvataggio la versione in forza SI SA
-- sempre, ed e' quella del programma che sta girando. E' diverso dal caso di
-- ENGINE-01, dove i contenuti gia' archiviati erano stati valutati da un
-- motore che nessuno aveva registrato: li' NULL significa «non registrato», e
-- resta.
--
-- # NON SI CONSERVANO I RISULTATI
--
-- Solo la domanda. Conservare le righe trovate darebbe una fotografia che
-- invecchia e che, riaperta, sembrerebbe attuale: e' la stessa ragione per cui
-- workspace e segnalibri riferiscono senza copiare.
CREATE TABLE saved_searches (
    id INTEGER PRIMARY KEY,
    -- Il nome con cui la si ritrova. Unico: due ricerche omonime sono una
    -- trappola, e qui non c'e' un ciclo di vita che ne liberi il nome.
    name TEXT NOT NULL UNIQUE,

    -- I CAMPI DEL FILTRO, uno per uno.
    --
    -- Il testo cercato. Puo' essere vuoto: una ricerca «tutto cio' che attende
    -- una decisione» non ha parole, ed e' una ricerca legittima.
    query TEXT NOT NULL,
    -- Livello minimo mostrato; 0 non esclude nulla.
    minimum_level INTEGER NOT NULL CHECK (minimum_level BETWEEN 0 AND 4),
    only_pending INTEGER NOT NULL CHECK (only_pending IN (0, 1)),
    -- L'ambito: una sessione, oppure NULL per tutte.
    --
    -- Senza CASCADE: se la sessione sparisce, la ricerca salvata resta e
    -- dichiara che il suo ambito non e' piu' nell'archivio. Farla sparire
    -- direbbe che nessuno l'aveva mai salvata.
    session_id INTEGER,

    -- LA CONFIGURAZIONE IN FORZA AL SALVATAGGIO.
    engine_version INTEGER NOT NULL,

    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,

    -- Una ricerca che non chiede niente non e' una ricerca: nessun testo,
    -- nessun livello minimo, nessuna attesa di decisione: restituirebbe tutto,
    -- che e' cio' che lo Storico mostra gia' senza salvare nulla.
    CHECK (
        length(trim(query)) > 0
        OR minimum_level > 0
        OR only_pending = 1
    )
);

CREATE INDEX saved_searches_by_name ON saved_searches (name);

-- UNA RICERCA SALVATA NON SI RISCRIVE.
--
-- Porta chi l'ha salvata e quando: se la query potesse cambiare dopo, quei due
-- valori direbbero che quella persona ha salvato QUELLA domanda quel giorno, e
-- sarebbe falso. E' la stessa disciplina delle note (NOTE-01).
--
-- Il nome e' protetto insieme al resto: un trigger che difendesse tre colonne
-- su quattro inviterebbe la domanda «perche' non la quarta».
--
-- Per cambiarla se ne salva un'altra, e si cancella questa: cancellare E'
-- ammesso, perche' una ricerca salvata e' uno STRUMENTO, non l'affermazione di
-- una persona su un fatto. Nessuna decisione poggia sulla sua esistenza, e
-- l'audit registra comunque che c'era.
CREATE TRIGGER saved_searches_are_written_once
    BEFORE UPDATE ON saved_searches
BEGIN
    SELECT RAISE(ABORT, 'una ricerca salvata non si modifica: se ne salva un''altra');
END;

-- Associazione manuale fra un'identita' osservata e un soggetto (PERS-06).
--
-- # La porta che quattro milestone hanno tenuto chiusa
--
-- PERS-02, PERS-03, PERS-04 e PERS-05 hanno tutte rifiutato di collegare
-- un'identita' osservata a un fascicolo. Questa tabella e' l'unico posto in cui
-- quel legame puo' esistere, e ci finisce SOLO perche' qualcuno lo ha deciso.
--
-- Il divieto non e' stato tolto: le quattro guardie restano dove sono. Il
-- collegamento manuale e' un'altra strada, non un permesso.
--
-- # Mai per somiglianza di nome
--
-- Si collega un IDENTIFICATIVO, non un nome. Il nome non regge nel tempo e non
-- e' unico: due persone possono chiamarsi allo stesso modo, e una puo' cambiare
-- nome. E' la decisione di PERS-02, e qui sbagliare collegherebbe a un fascicolo
-- la persona sbagliata.
--
-- Non esiste una colonna «somiglianza», «confidenza» o «candidato»: il legame o
-- c'e' perche' qualcuno lo ha deciso, o non c'e'.
--
-- # Una riga per ogni atto, e sciogliere non cancella
--
-- Sciogliere un legame e' un ATTO, non una cancellazione. Se qualcuno ha
-- lavorato su un fascicolo mentre un'identita' vi era collegata, togliere la
-- riga renderebbe illeggibile quel lavoro: sembrerebbe che nessuno avesse mai
-- collegato niente.
--
-- I legami in essere si ricavano dall'atto piu' recente per ogni identificativo.
--
-- # Che cosa questa tabella NON ha
--
-- Una colonna numerica oltre agli identificativi e all'istante. Un numero
-- accanto a un legame fra una persona e un fascicolo e' la stessa cosa di un
-- numero accanto a una persona.

CREATE TABLE identity_links (
    id INTEGER PRIMARY KEY,
    -- Quale soggetto. Con chiave esterna: un legame senza il suo fascicolo non
    -- significa niente, e non deve poter restare appeso.
    person_id INTEGER NOT NULL REFERENCES persons (id) ON DELETE RESTRICT,
    -- Quale identita' osservata, per identificativo presso la piattaforma.
    --
    -- SENZA chiave esterna, e la ragione e' che non c'e' una tabella a cui
    -- puntare: le identita' osservate sono DERIVATE dai contenuti (PERS-02), e
    -- costruirne una qui creerebbe la copia che PERS-02 ha deciso di non fare.
    --
    -- Il costo e' dichiarato: si puo' collegare un identificativo che nessun
    -- contenuto ha ancora mostrato. E' voluto — un'identita' puo' essere nota
    -- all'ufficio prima che compaia in un monitoraggio — e chi legge vede
    -- l'identificativo, non una riga che sparisce.
    identifier TEXT NOT NULL CHECK (length(trim(identifier)) > 0),
    -- Che cosa e' stato fatto.
    act TEXT NOT NULL CHECK (act IN ('collegata', 'sciolta')),
    -- Perche'. OBBLIGATORIO PER ENTRAMBI GLI ATTI.
    --
    -- Un legame sciolto in silenzio non dice se sia stato sciolto perche' era
    -- sbagliato o perche' e' diventato scomodo.
    reason TEXT NOT NULL CHECK (length(trim(reason)) >= 20),
    -- Chi.
    linked_by TEXT NOT NULL,
    -- Quando.
    linked_at INTEGER NOT NULL
);

CREATE INDEX identity_links_by_person ON identity_links (person_id, linked_at);
CREATE INDEX identity_links_by_identifier ON identity_links (identifier);

-- UN ATTO NON SI RISCRIVE.
--
-- Porta un nome, un motivo e un istante: cambiarne uno li farebbe mentire tutti
-- e tre insieme.
CREATE TRIGGER identity_links_are_written_once
    BEFORE UPDATE ON identity_links
BEGIN
    SELECT RAISE(ABORT, 'un atto su un legame non si riscrive: se il legame cambia, se ne registra uno nuovo');
END;

-- E NON SI CANCELLA.
--
-- Cancellare l'atto con cui qualcuno ha collegato un'identita', lasciando quello
-- con cui l'ha sciolta, riscriverebbe la storia di un fascicolo.
CREATE TRIGGER identity_links_are_never_deleted
    BEFORE DELETE ON identity_links
BEGIN
    SELECT RAISE(ABORT, 'un atto su un legame non si cancella: sciogliere e'' un atto, non una cancellazione');
END;

-- NON SI COLLEGA A UN SOGGETTO CHIUSO.
--
-- Un fascicolo chiuso e' un lavoro concluso: collegarvi un'identita' dopo la
-- chiusura significherebbe che qualcuno ha continuato a lavorarci senza che il
-- fascicolo lo dicesse. Se il lavoro riprende, PERS-01 dice che se ne apre uno
-- nuovo.
CREATE TRIGGER identity_links_not_on_closed_subjects
    BEFORE INSERT ON identity_links
    WHEN EXISTS (
        SELECT 1 FROM persons WHERE id = NEW.person_id AND closed_at IS NOT NULL
    )
BEGIN
    SELECT RAISE(ABORT, 'un soggetto chiuso non si collega: se il lavoro riprende, se ne apre uno nuovo');
END;

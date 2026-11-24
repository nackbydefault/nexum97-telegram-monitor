-- Valutazione umana di un soggetto (PERS-05).
--
-- # Che cos'e' questa tabella, e perche' e' la piu' delicata dell'archivio
--
-- E' il posto in cui una persona scrive un giudizio su un'altra persona.
--
-- Tutto cio' che il prodotto tiene fuori altrove — l'attribuzione, il punteggio,
-- l'inferenza — qui non sparisce: diventa una DECISIONE UMANA, con un nome, un
-- motivo, un istante e una traccia. La differenza fra le due cose e' l'intero
-- senso della Fase 6.
--
-- # Una riga per ogni atto, e nessun campo sul soggetto
--
-- La valutazione corrente NON e' una colonna di `persons`: e' l'atto piu'
-- recente di questa tabella.
--
-- Una colonna si sovrascrive, e la valutazione precedente sparirebbe. Chi
-- rilegge un fascicolo deve poter vedere COME si e' arrivati alla valutazione di
-- oggi: se qualcuno l'ha alzata, chi e perche'; se qualcuno l'ha ritirata,
-- altrettanto. E' la disciplina di NOTE-01 applicata alla cosa che ne ha piu'
-- bisogno.
--
-- # Che cosa questa tabella NON ha, e non avra' mai
--
-- Una colonna numerica. Non un punteggio, non una probabilita', non un peso, non
-- una percentuale di pericolosita' — che il congelamento vieta con queste
-- parole, e i requisiti di sicurezza ribadiscono: «in nessuna forma e nemmeno
-- spento».
--
-- Le sole colonne di questa tabella sono: quale soggetto, che atto, perche',
-- chi, quando. Nessuna di esse e' una misura.
--
-- # E non ha una colonna «suggerito dal programma»
--
-- Perche' una valutazione proposta dal programma sarebbe una valutazione
-- automatica, comunque la si chiamasse — «suggerimento», «bozza», «default». Il
-- livello arriva da chi lo ha deciso, o non arriva.

CREATE TABLE subject_assessments (
    id INTEGER PRIMARY KEY,
    -- Quale soggetto. Con chiave esterna, a differenza dei riferimenti
    -- polimorfici altrove: una valutazione senza il suo fascicolo non
    -- significa niente, e non deve poter restare appesa.
    person_id INTEGER NOT NULL REFERENCES persons (id) ON DELETE RESTRICT,
    -- Che cosa e' stato fatto.
    --
    -- I tre livelli sono quelli del congelamento; 'ritirata' riporta a NON
    -- VALUTATO. 'non_valutato' NON e' un valore ammesso: non e' un giudizio, e
    -- ammetterlo permetterebbe di registrare un atto che non dice niente.
    act TEXT NOT NULL CHECK (
        act IN ('da_approfondire', 'di_interesse', 'priorita_alta', 'ritirata')
    ),
    -- Perche'. OBBLIGATORIO PER OGNI ATTO, ritiro compreso.
    --
    -- Una valutazione ritirata in silenzio non dice se sia stata ritirata
    -- perche' sbagliata o perche' scomoda, e sono due cose molto diverse per chi
    -- rilegge. La soglia e' quella condivisa dei venti caratteri: sotto, non e'
    -- una ragione, e' una spunta.
    reason TEXT NOT NULL CHECK (length(trim(reason)) >= 20),
    -- Chi.
    assessed_by TEXT NOT NULL,
    -- Quando.
    assessed_at INTEGER NOT NULL
);

CREATE INDEX subject_assessments_by_person
    ON subject_assessments (person_id, assessed_at);

-- UN ATTO DI VALUTAZIONE NON SI RISCRIVE.
--
-- Porta un nome, un motivo e un istante: cambiarne uno li farebbe mentire tutti
-- e tre insieme. Chi ha valutato quel giorno per quel motivo lo ha fatto, e
-- resta scritto.
--
-- Se il giudizio cambia, si registra un ATTO NUOVO — che e' esattamente cio' che
-- chi rilegge deve poter vedere.
CREATE TRIGGER subject_assessments_are_written_once
    BEFORE UPDATE ON subject_assessments
BEGIN
    SELECT RAISE(ABORT, 'un atto di valutazione non si riscrive: se il giudizio cambia, se ne registra uno nuovo');
END;

-- E NON SI CANCELLA.
--
-- Cancellare l'atto con cui qualcuno ha alzato una valutazione, lasciando quello
-- con cui l'ha ritirata, riscriverebbe la storia di un fascicolo — ed e' il
-- genere di cosa per cui una traccia esiste.
CREATE TRIGGER subject_assessments_are_never_deleted
    BEFORE DELETE ON subject_assessments
BEGIN
    SELECT RAISE(ABORT, 'un atto di valutazione non si cancella: la storia di un fascicolo non si riscrive');
END;

-- NON SI VALUTA UN SOGGETTO CHIUSO.
--
-- Un fascicolo chiuso e' un lavoro concluso: aggiungere un giudizio dopo la
-- chiusura significherebbe che qualcuno ha continuato a lavorarci senza che il
-- fascicolo lo dicesse. Se il lavoro riprende, PERS-01 dice che si apre un
-- soggetto nuovo.
CREATE TRIGGER subject_assessments_not_on_closed_subjects
    BEFORE INSERT ON subject_assessments
    WHEN EXISTS (
        SELECT 1 FROM persons WHERE id = NEW.person_id AND closed_at IS NOT NULL
    )
BEGIN
    SELECT RAISE(ABORT, 'un soggetto chiuso non si valuta: se il lavoro riprende, se ne apre uno nuovo');
END;

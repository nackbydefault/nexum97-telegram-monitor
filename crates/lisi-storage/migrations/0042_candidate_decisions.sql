-- Che cosa una persona ha deciso di un candidato, e l'indirizzo pubblico che
-- rende possibile deciderlo.
--
-- Motivata in ADR-0080 e DEC-316.
--
-- ===========================================================================
-- «LEGITTIMAMENTE ACCESSIBILE» LO DICE UNA PERSONA.
--
-- Il piano chiede: «Aggiungi se legittimamente accessibile». Il prodotto non
-- puo' verificarlo: per saperlo dovrebbe PROVARE ad accedervi, e provare e'
-- esattamente la cosa che non fa - nessun ingresso in gruppi, nessuna richiesta
-- di adesione, nessuna partecipazione.
--
-- Quindi non lo verifica: lo fa DICHIARARE, con un motivo, e la dichiarazione
-- porta il nome di chi l'ha firmata. E' la stessa regola per cui `sources` ha
-- da sempre un `authorized_by`.

-- ---------------------------------------------------------------------------
-- L'INDIRIZZO PUBBLICO, che rende possibile aprire e aggiungere.
--
-- Non e' un identificatore di fonte: un identificatore di fonte e' una cosa che
-- questo prodotto assegna quando qualcuno decide di sorvegliare qualcosa.
-- Questo e' un nome che esisteva prima, che chiunque puo' leggere, e che non
-- impegna nessuno a niente.
--
-- Puo' mancare: non tutto cio' che una ricerca restituisce ha un nome utente
-- pubblico. Un risultato senza indirizzo non si puo' ne' aprire ne' aggiungere,
-- e la ragione si dice invece di lasciare un comando che non funziona.
ALTER TABLE discovery_results ADD COLUMN public_address TEXT;

-- ---------------------------------------------------------------------------
-- LE DECISIONI SONO FATTI, NON UNO STATO.
--
-- Non esiste un campo «stato del candidato» che si sovrascrive. Qualcuno puo'
-- cambiare idea - ignorare oggi e aggiungere fra un mese, quando un'indagine lo
-- rende pertinente - e allora RESTANO VERE ENTRAMBE LE COSE: che quel giorno si
-- era detto di no, e che l'altro giorno si e' detto di si'.
--
-- Uno stato sovrascritto cancellerebbe la prima, che e' quella che spiega
-- perche' nessuno l'aveva aggiunto prima.
CREATE TABLE discovery_decisions (
    id          INTEGER PRIMARY KEY,
    result_id   INTEGER NOT NULL REFERENCES discovery_results(id),
    -- Le tre azioni del piano, e nessun'altra. «Cancellato» non c'e': ignorare
    -- non cancella.
    decision    TEXT    NOT NULL CHECK (decision IN (
                    'aperto',
                    'aggiunto',
                    'ignorato'
                )),
    -- Chi l'ha decisa. Non puo' essere vuoto: una decisione senza un nome non e'
    -- una decisione di nessuno, ed e' esattamente cio' che non deve succedere
    -- quando la decisione fa nascere una fonte sorvegliata.
    actor       TEXT    NOT NULL CHECK (length(trim(actor)) > 0),
    -- PERCHE'. Obbligatorio, e non per formalita': un motivo per candidato e' la
    -- difesa piu' semplice contro il gesto - non si scrive un motivo dieci volte
    -- per distrazione. E' cosi' che «mai adesione automatica» resta vero anche
    -- quando a premere e' una persona.
    reason      TEXT    NOT NULL CHECK (length(trim(reason)) > 0),
    decided_at  INTEGER NOT NULL,
    -- La fonte nata da questa decisione, quando ne e' nata una.
    --
    -- Sta QUI perche' la decisione e la fonte si scrivono nella stessa
    -- transazione: una fonte senza la decisione che l'ha creata e' una fonte
    -- comparsa dal nulla, e una decisione che dichiara una fonte inesistente e'
    -- una bugia in archivio.
    source_id   INTEGER REFERENCES sources(id),

    -- Una fonte nasce solo da «aggiunto», e «aggiunto» fa nascere una fonte.
    -- Il vincolo sta nello schema perche' e' l'affermazione che questa tabella
    -- esiste per difendere.
    CHECK (
        (decision = 'aggiunto' AND source_id IS NOT NULL)
        OR (decision <> 'aggiunto' AND source_id IS NULL)
    )
);

CREATE INDEX discovery_decisions_per_risultato ON discovery_decisions (result_id);

-- ---------------------------------------------------------------------------
-- UNA DECISIONE PRESA E' UNA DECISIONE PRESA.
--
-- Non si modifica e non si cancella: cambiare idea si fa DECIDENDO DI NUOVO, e
-- le due decisioni restano entrambe. Riscrivere la prima significherebbe
-- riscrivere che cosa si sapeva quando qualcuno ha deciso qualcosa.
CREATE TRIGGER discovery_decisions_non_si_modificano
BEFORE UPDATE ON discovery_decisions
BEGIN
    SELECT RAISE(ABORT, 'una decisione presa non si modifica: si decide di nuovo');
END;

CREATE TRIGGER discovery_decisions_non_si_cancellano
BEFORE DELETE ON discovery_decisions
BEGIN
    SELECT RAISE(ABORT, 'una decisione presa non si cancella');
END;

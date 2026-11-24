-- Note dell'operatore (NOTE-01).
--
-- # Che cos'e' una nota, e che cosa NON e'
--
-- E' cio' che una persona ha scritto a proposito di qualcosa che sta
-- nell'archivio: un contenuto, una fonte, un rapporto, un workspace. Porta
-- CHI l'ha scritta e QUANDO, perche' senza quelle due cose e' una frase
-- anonima che nessuno puo' pesare.
--
-- NON E' UNA REVISIONE. Una revisione (`reviews`) ha un campo `note`, e quella
-- e' la MOTIVAZIONE DI UNA DECISIONE: esiste perche' una decisione e' stata
-- presa, ed e' legata al passaggio di stato. Una nota non ha occasione: si
-- scrive quando si vuole, anche su cose che non hanno alcuna revisione — una
-- fonte, un workspace. E' la differenza fra «perche' ho deciso cosi'» e
-- «annoto questo».
--
-- # LA NOTA NON TOCCA LA PROVA
--
-- Il congelamento lo scrive con queste parole: «non modificano mai la prova
-- originale». Il modo di rispettarlo non e' ricordarsene.
--
-- Questa tabella e' SEPARATA, e non ha alcuna chiave esterna verso `contents`:
-- il riferimento e' polimorfico, come per workspace e segnalibri. Nessuna
-- istruzione di questo modulo scrive su `contents` o `content_versions`, e una
-- guardia del servizio lo verifica cercando quelle parole nel sorgente.
--
-- # IL TESTO DI UNA NOTA NON SI RISCRIVE
--
-- Una nota porta un autore e un istante. Se il testo potesse cambiare dopo,
-- l'autore e l'istante MENTIREBBERO: direbbero che quella persona ha scritto
-- quella frase quel giorno, e non sarebbe piu' vero.
--
-- Percio' non esiste un modo di modificarla. Una nota sbagliata si RITIRA — e
-- il ritiro porta a sua volta chi e quando — e se ne scrive un'altra. La nota
-- ritirata RESTA VISIBILE: qualcuno puo' averci lavorato sopra, e farla
-- sparire riscriverebbe che cosa quella persona aveva davanti.
--
-- E' la stessa disciplina del workspace che non si riapre e dell'audit che non
-- si cancella: cio' che e' stato non torna a non essere stato.
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    -- Su che cosa. 'segnalibro' NON e' ammesso: un segnalibro e' esso stesso un
    -- riferimento, e una nota su di lui sarebbe una nota sul dito invece che
    -- sulla cosa indicata. Chi vuole annotare cio' che ha segnato annota
    -- QUELLO.
    kind TEXT NOT NULL CHECK (
        kind IN ('fonte', 'contenuto', 'rapporto', 'workspace')
    ),
    -- Quale. Senza chiave esterna: il riferimento e' polimorfico, e il costo e'
    -- lo stesso dei workspace — un riferimento puo' restare appeso, e chi legge
    -- riceve la dichiarazione invece del silenzio.
    target_id INTEGER NOT NULL,
    -- Le parole. NON VUOTE: una nota senza parole non e' una nota, e una riga
    -- vuota con un autore e un istante direbbe che qualcuno ha annotato
    -- qualcosa senza dire niente.
    body TEXT NOT NULL CHECK (length(trim(body)) > 0),
    author TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    -- Il ritiro: chi e quando, oppure nulla. I due valori vanno INSIEME — una
    -- nota ritirata da nessuno, o ritirata in nessun istante, sarebbe un ritiro
    -- a meta'.
    withdrawn_by TEXT,
    withdrawn_at INTEGER,

    CHECK (
        (withdrawn_by IS NULL AND withdrawn_at IS NULL)
        OR (withdrawn_by IS NOT NULL AND withdrawn_at IS NOT NULL)
    )
);

CREATE INDEX notes_by_target ON notes (kind, target_id);

-- IL TESTO DI UNA NOTA NON SI RISCRIVE.
--
-- Il vincolo non e' una precauzione contro la malafede: e' contro la cosa
-- normale, cioe' qualcuno che «corregge un refuso» e senza volerlo fa dire
-- all'autore e all'istante una cosa falsa.
CREATE TRIGGER notes_text_is_written_once
    BEFORE UPDATE OF body, kind, target_id, author, created_at ON notes
    WHEN OLD.body <> NEW.body
        OR OLD.kind <> NEW.kind
        OR OLD.target_id <> NEW.target_id
        OR OLD.author <> NEW.author
        OR OLD.created_at <> NEW.created_at
BEGIN
    SELECT RAISE(ABORT, 'una nota non si riscrive: si ritira e se ne scrive un''altra');
END;

-- UN RITIRO NON SI ANNULLA.
--
-- Rimettere in piedi una nota ritirata farebbe del ritiro una parentesi invece
-- che un fatto, e chi avesse letto «ritirata» non avrebbe modo di sapere che
-- adesso non lo e' piu'.
CREATE TRIGGER notes_withdrawal_stays
    BEFORE UPDATE ON notes
    WHEN OLD.withdrawn_at IS NOT NULL AND NEW.withdrawn_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'un ritiro non si annulla: se la nota serve ancora, se ne scrive una nuova');
END;

-- UNA NOTA NON SI CANCELLA.
--
-- Qualcuno puo' averci lavorato sopra. Farla sparire riscriverebbe che cosa
-- quella persona aveva davanti quando ha deciso, ed e' esattamente cio' che
-- l'audit di questo prodotto esiste per impedire.
--
-- Il ritiro c'e' apposta: dice che non vale piu', e lascia vedere che c'era.
CREATE TRIGGER notes_are_never_deleted
    BEFORE DELETE ON notes
BEGIN
    SELECT RAISE(ABORT, 'una nota non si cancella: si ritira, e resta visibile come ritirata');
END;

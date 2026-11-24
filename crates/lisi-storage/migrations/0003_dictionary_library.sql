-- Migrazione 0003 - libreria multi-dizionario.
--
-- Introduce dizionari, versioni, termini, profili e le tabelle che legano una
-- sessione alla configurazione con cui e' stata condotta.
--
-- Le migrazioni 0001 e 0002 NON sono toccate: un database esistente non le
-- rieseguirebbe e divergerebbe in silenzio da uno nuovo.
--
-- I vincoli che contano stanno qui e non nel codice applicativo, per la stessa
-- ragione gia' adottata dalla Milestone 1: un vincolo scritto solo nel codice
-- viene aggirato dal primo percorso che dimentica di controllarlo.
--
-- Vedere docs/adr/ADR-0012-DICTIONARY-LIBRARY.md e
-- docs/adr/ADR-0013-RESOLUTION-AND-SNAPSHOT.md.

-- ---------------------------------------------------------------- dizionari

CREATE TABLE dictionaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (
        scope IN ('global', 'country', 'region', 'province', 'municipality', 'thematic', 'custom')
    ),
    origin TEXT NOT NULL CHECK (
        origin IN ('system', 'administrator', 'operator', 'imported')
    ),
    visibility TEXT NOT NULL CHECK (visibility IN ('built_in', 'shared', 'personal')),
    status TEXT NOT NULL CHECK (
        status IN ('draft', 'active', 'inactive', 'superseded', 'archived')
    ),
    created_by TEXT NOT NULL,
    -- Dizionario da cui questo deriva, quando e' una duplicazione. Se
    -- l'originale sparisce il legame si perde ma la copia resta: e' una
    -- informazione di provenienza, non una dipendenza.
    derived_from INTEGER REFERENCES dictionaries (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    -- Due operatori possono avere ciascuno un dizionario con lo stesso nome:
    -- l'unicita' e' per autore, non globale.
    UNIQUE (name, created_by)
);

CREATE INDEX dictionaries_by_scope ON dictionaries (scope, status);
CREATE INDEX dictionaries_by_visibility ON dictionaries (visibility, status);

-- ----------------------------------------------------------------- versioni

CREATE TABLE dictionary_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dictionary_id INTEGER NOT NULL REFERENCES dictionaries (id) ON DELETE CASCADE,
    number INTEGER NOT NULL CHECK (number >= 1),
    note TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    -- Assente finche' la versione e' in bozza. Una volta valorizzato, la
    -- versione non si modifica piu': e' cio' che rende ripetibile una
    -- sessione conclusa.
    published_at INTEGER,
    UNIQUE (dictionary_id, number)
);

CREATE INDEX dictionary_versions_by_dictionary ON dictionary_versions (dictionary_id, number);

-- ------------------------------------------------------------------ termini

CREATE TABLE dictionary_terms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES dictionary_versions (id) ON DELETE CASCADE,
    -- Testo come lo ha scritto chi ha compilato il dizionario.
    text TEXT NOT NULL,
    -- Testo normalizzato, usato per il confronto e per l'unicita'.
    normalised TEXT NOT NULL,
    category TEXT NOT NULL,
    language TEXT NOT NULL,
    match_mode TEXT NOT NULL CHECK (
        match_mode IN ('exact_word', 'phrase', 'normalized_word')
    ),
    -- Suggerimento di chi ha compilato il dizionario, NON l'esito
    -- dell'analisi. Il valore negativo serve alle negazioni e al contesto
    -- riduttivo, che devono poter abbassare il peso di un riscontro.
    suggested_level INTEGER NOT NULL CHECK (suggested_level BETWEEN -4 AND 4),
    note TEXT NOT NULL,
    -- La stessa parola cercata come parola esatta e come frase sono due cose
    -- diverse: l'unicita' comprende la modalita'.
    UNIQUE (version_id, normalised, match_mode)
);

CREATE INDEX dictionary_terms_by_version ON dictionary_terms (version_id);
CREATE INDEX dictionary_terms_by_category ON dictionary_terms (category);

-- ------------------------------------------------------------------ profili

CREATE TABLE dictionary_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    created_by TEXT NOT NULL,
    shared INTEGER NOT NULL CHECK (shared IN (0, 1)),
    created_at INTEGER NOT NULL,
    UNIQUE (name, created_by)
);

-- Un profilo riferisce DIZIONARI, non versioni: alla risoluzione si sceglie la
-- versione pubblicata piu' recente. Un profilo che congelasse le versioni
-- diventerebbe obsoleto in silenzio.
CREATE TABLE dictionary_profile_items (
    profile_id INTEGER NOT NULL REFERENCES dictionary_profiles (id) ON DELETE CASCADE,
    dictionary_id INTEGER NOT NULL REFERENCES dictionaries (id) ON DELETE CASCADE,
    PRIMARY KEY (profile_id, dictionary_id)
);

-- ------------------------------------------------- configurazione di sessione

-- Impronta della configurazione con cui la sessione e' stata condotta.
-- Aggiunta come colonna perche' ALTER TABLE ADD COLUMN non riscrive la tabella
-- e non mette a rischio i dati esistenti.
ALTER TABLE sessions ADD COLUMN dictionary_digest TEXT;

-- Quali dizionari, e soprattutto in QUALE VERSIONE. La versione e' cio' che
-- rende ripetibile la sessione: il dizionario evolve, la versione no.
CREATE TABLE session_dictionary_selections (
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    dictionary_id INTEGER NOT NULL REFERENCES dictionaries (id) ON DELETE RESTRICT,
    version_id INTEGER NOT NULL REFERENCES dictionary_versions (id) ON DELETE RESTRICT,
    selected_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, dictionary_id)
);

-- Parole aggiunte per la singola sessione.
CREATE TABLE session_custom_terms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    normalised TEXT NOT NULL,
    match_mode TEXT NOT NULL CHECK (
        match_mode IN ('exact_word', 'phrase', 'normalized_word')
    ),
    added_at INTEGER NOT NULL,
    UNIQUE (session_id, normalised, match_mode)
);

-- Fotografia immutabile dei termini risolti. La sessione guarda questa, non i
-- dizionari: se un dizionario cambia durante una sessione lunga, la sessione
-- continua con i termini di prima.
CREATE TABLE session_resolved_terms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    normalised TEXT NOT NULL,
    original TEXT NOT NULL,
    category TEXT NOT NULL,
    language TEXT NOT NULL,
    match_mode TEXT NOT NULL CHECK (
        match_mode IN ('exact_word', 'phrase', 'normalized_word')
    ),
    suggested_level INTEGER NOT NULL CHECK (suggested_level BETWEEN -4 AND 4),
    -- Provenienze in forma canonica: e' cio' che permette di rispondere alla
    -- domanda "perche' questo contenuto e' stato segnalato" nominando i
    -- dizionari, e non solo il termine.
    provenances TEXT NOT NULL,
    UNIQUE (session_id, normalised, match_mode)
);

CREATE INDEX session_resolved_terms_by_session ON session_resolved_terms (session_id);

-- ----------------------------------------------------------------- immutabilita

-- Una versione pubblicata non si modifica piu'. Il trigger non impedisce di
-- pubblicare una bozza: impedisce di toccare cio' che e' gia' pubblicato.
CREATE TRIGGER dictionary_versions_published_are_immutable
BEFORE UPDATE ON dictionary_versions
WHEN OLD.published_at IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'una versione pubblicata non puo'' essere modificata');
END;

CREATE TRIGGER dictionary_versions_published_are_not_deletable
BEFORE DELETE ON dictionary_versions
WHEN OLD.published_at IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'una versione pubblicata non puo'' essere cancellata');
END;

-- I termini di una versione pubblicata sono altrettanto immutabili: modificare
-- il contenuto senza toccare la riga della versione aggirerebbe il vincolo.
CREATE TRIGGER dictionary_terms_of_published_versions_are_not_insertable
BEFORE INSERT ON dictionary_terms
WHEN (
    SELECT published_at FROM dictionary_versions WHERE id = NEW.version_id
) IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'non si aggiungono termini a una versione pubblicata');
END;

CREATE TRIGGER dictionary_terms_of_published_versions_are_immutable
BEFORE UPDATE ON dictionary_terms
WHEN (
    SELECT published_at FROM dictionary_versions WHERE id = OLD.version_id
) IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'non si modificano i termini di una versione pubblicata');
END;

CREATE TRIGGER dictionary_terms_of_published_versions_are_not_deletable
BEFORE DELETE ON dictionary_terms
WHEN (
    SELECT published_at FROM dictionary_versions WHERE id = OLD.version_id
) IS NOT NULL
BEGIN
SELECT RAISE(ABORT, 'non si cancellano i termini di una versione pubblicata');
END;

-- I dizionari di sistema si duplicano, non si modificano. Lo stato puo'
-- cambiare, perche' un seed piu' recente puo' rendere superata una versione
-- precedente; l'identita' no.
CREATE TRIGGER dictionaries_built_in_identity_is_read_only
BEFORE UPDATE ON dictionaries
WHEN OLD.visibility = 'built_in'
    AND (
        NEW.name <> OLD.name
        OR NEW.description <> OLD.description
        OR NEW.scope <> OLD.scope
        OR NEW.origin <> OLD.origin
        OR NEW.visibility <> OLD.visibility
    )
BEGIN
SELECT RAISE(ABORT, 'un dizionario di sistema non si modifica: va duplicato');
END;

CREATE TRIGGER dictionaries_built_in_are_not_deletable
BEFORE DELETE ON dictionaries
WHEN OLD.visibility = 'built_in'
BEGIN
SELECT RAISE(ABORT, 'un dizionario di sistema non puo'' essere cancellato');
END;

-- La fotografia dei termini di una sessione e' immutabile: e' cio' che
-- permette di dimostrare a posteriori con quali termini la sessione e' stata
-- condotta.
--
-- CONSEGUENZA VOLUTA, non effetto collaterale: poiche' la tabella dipende da
-- sessions con ON DELETE CASCADE, il trigger sulla cancellazione rende
-- impossibile cancellare una sessione che abbia gia' una configurazione
-- risolta. E' coerente con il resto del prodotto - l'audit e' append-only e
-- una fonte gia' usata non si cancella - ed e' verificato da un test, cosi'
-- che nessuno lo scopra per caso mentre cerca di capire perche' una
-- cancellazione fallisce.
CREATE TRIGGER session_resolved_terms_are_immutable
BEFORE UPDATE ON session_resolved_terms
BEGIN
SELECT RAISE(ABORT, 'la configurazione risolta di una sessione non si modifica');
END;

CREATE TRIGGER session_resolved_terms_are_not_deletable
BEFORE DELETE ON session_resolved_terms
BEGIN
SELECT RAISE(ABORT, 'la configurazione risolta di una sessione non si cancella');
END;

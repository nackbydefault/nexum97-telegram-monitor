-- Le persone dell'ufficio, sull'Hub.
--
-- Motivata in ADR-0097 e DEC-335 (TEAM-ASSIGN-01).
--
-- ===========================================================================
-- QUESTA TABELLA STA SULL'HUB, E SOLO SULL'HUB.
--
-- L'identita' la tiene l'autorita' dell'ufficio (ADR-0097, decisione 1). Una
-- postazione che tenesse le persone per conto proprio farebbe
-- un'affermazione su se' stessa, che e' esattamente cio' che il segnaposto
-- `operatore.locale` e' oggi.
--
-- La migrazione gira su ogni archivio perche' lo schema e' uno solo: la
-- tabella resta vuota dove nessuno apre la porta.
--
-- ===========================================================================
-- QUI NON C'E' UNA FRASE.
--
-- `verifier` e' un PHC string di Argon2id: algoritmo, versione, parametri,
-- sale e impronta. Non e' la frase e non la contiene, e dai parametri scritti
-- accanto all'impronta dipende la possibilita' di alzarli domani senza
-- rendere illeggibile cio' che c'e' oggi (ADR-0097, decisione 3).
--
-- Una frase in chiaro qui resterebbe su un disco per sempre.
--
-- ===========================================================================
-- SOSPENDERE NON E' CANCELLARE.
--
-- Una persona sospesa non entra piu', ma gli atti che ha compiuto restano
-- suoi: il passato non si riscrive (ADR-0097, decisione 7). Per questo non
-- c'e' alcuna cancellazione, e lo stato e' una colonna.

CREATE TABLE hub_people (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Come si chiama negli atti: `persona.<person_id>`.
    person_id   TEXT NOT NULL UNIQUE,
    -- Come la chiama l'ufficio.
    label       TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('operatore', 'amministratore')),
    state       TEXT NOT NULL CHECK (state IN ('attiva', 'sospesa')),
    -- PHC string di Argon2id. Mai la frase.
    verifier    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    -- Chi l'ha creata: una persona o una postazione, secondo chi c'era.
    created_by  TEXT NOT NULL,

    CHECK (length(person_id) >= 3),
    CHECK (length(label) > 0),
    CHECK (verifier LIKE '$argon2id$%')
);

-- L'accesso cerca per identificativo, ed e' l'unica lettura calda.
CREATE UNIQUE INDEX hub_people_by_person ON hub_people (person_id);

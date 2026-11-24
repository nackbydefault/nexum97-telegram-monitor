-- L'associazione fra un termine e una tecnica ATT&CK, dichiarata da una persona.
--
-- Motivata in ADR-0059 e DEC-294.
--
-- ===========================================================================
-- PERCHE' LA CHIAVE E' LA COPPIA TERMINE-CATEGORIA, E NON UN `dictionary_term_id`.
--
-- Un riscontro (`matches`) registra due cose: il termine NORMALIZZATO
-- (`rule_id`) e la sua CATEGORIA (`rule_category`). Non registra da quale riga
-- di quale versione di dizionario venga.
--
-- L'associazione usa quella stessa coppia perche' e' l'unico modo di far
-- combaciare le due cose SENZA INDOVINARE. Associare un `dictionary_term_id`
-- obbligherebbe, per rispondere a «quali tecniche riguardano questo contenuto»,
-- a ricostruire da quale riga venga un riscontro - e la ricostruzione sarebbe
-- ambigua, perche' lo stesso termine vive in piu' versioni e in piu' dizionari.
-- Un'ambiguita' in mezzo a una catena di provenienza e' una seconda verita'.
--
-- La categoria fa parte della chiave e non e' un dettaglio: la stessa parola in
-- due categorie diverse e' due termini diversi.
--
-- Ne segue una proprieta' utile e non cercata: l'associazione sopravvive a una
-- nuova versione di dizionario, perche' non e' appesa a una riga che quella
-- versione sostituisce.

-- ---------------------------------------------------------------------------
-- L'atto di dichiarare.
--
-- NON C'E' UNA COLONNA «RITIRATA».
--
-- Ritirare e' un atto, non una modifica: sta nella tabella qui sotto, con il
-- proprio motivo, il proprio operatore e il proprio istante. Una colonna
-- renderebbe il ritiro una riscrittura, e chi rilegge non saprebbe piu' se un
-- legame fu sciolto perche' sbagliato o perche' scomodo (la lezione di
-- PERS-06).
CREATE TABLE attack_term_associations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Il termine normalizzato, nella forma in cui `matches.rule_id` lo scrive.
    term_normalised TEXT NOT NULL CHECK (length(trim(term_normalised)) > 0),
    -- La categoria, nella forma in cui `matches.rule_category` la scrive.
    term_category TEXT NOT NULL CHECK (length(trim(term_category)) > 0),
    -- LA FOTOGRAFIA FA PARTE DELL'ASSOCIAZIONE.
    --
    -- Una tecnica significa cio' che significa nella propria versione: la 20.0
    -- puo' deprecarla o riscriverne il nome. Una fotografia nuova NON porta con
    -- se' le associazioni vecchie, perche' farle migrare significherebbe
    -- dichiarare, al posto di chi le ha fatte, che valgono anche li'.
    snapshot_id INTEGER NOT NULL REFERENCES attack_snapshots (id) ON DELETE RESTRICT,
    technique_id TEXT NOT NULL,
    -- IL MOTIVO NON E' FACOLTATIVO.
    --
    -- Un riferimento tassonomico dentro un atto e' forte quanto la base su cui
    -- poggia, e la base qui e' una persona. Senza motivo, l'associazione non e'
    -- documentata: e' soltanto avvenuta.
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    declared_by TEXT NOT NULL,
    declared_at INTEGER NOT NULL,
    -- La tecnica deve esistere DENTRO quella fotografia. Lo dice l'archivio, non
    -- una convenzione.
    FOREIGN KEY (snapshot_id, technique_id)
    REFERENCES attack_techniques (snapshot_id, technique_id) ON DELETE RESTRICT
);

CREATE INDEX attack_term_associations_by_term
ON attack_term_associations (term_normalised, term_category);

CREATE INDEX attack_term_associations_by_technique
ON attack_term_associations (snapshot_id, technique_id);

-- ---------------------------------------------------------------------------
-- L'atto di ritirare.
--
-- Una riga per associazione ritirata: si ritira una volta sola, e la chiave
-- primaria lo impone.
CREATE TABLE attack_association_withdrawals (
    association_id INTEGER PRIMARY KEY
    REFERENCES attack_term_associations (id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    withdrawn_by TEXT NOT NULL,
    withdrawn_at INTEGER NOT NULL
);

-- ---------------------------------------------------------------------------
-- Un atto non si modifica e non si cancella.
--
-- E' la stessa garanzia dell'audit e delle fotografie. Cancellare
-- un'associazione renderebbe illeggibile il lavoro fatto mentre esisteva,
-- compresi i rapporti che la citavano.
CREATE TRIGGER attack_term_associations_are_immutable
    BEFORE UPDATE ON attack_term_associations
BEGIN
    SELECT RAISE(ABORT, 'un''associazione con una tecnica e'' un atto: non si modifica');
END;

CREATE TRIGGER attack_term_associations_are_not_deleted
    BEFORE DELETE ON attack_term_associations
BEGIN
    SELECT RAISE(ABORT, 'un''associazione con una tecnica si ritira, non si cancella');
END;

CREATE TRIGGER attack_association_withdrawals_are_immutable
    BEFORE UPDATE ON attack_association_withdrawals
BEGIN
    SELECT RAISE(ABORT, 'il ritiro di un''associazione e'' un atto: non si modifica');
END;

CREATE TRIGGER attack_association_withdrawals_are_not_deleted
    BEFORE DELETE ON attack_association_withdrawals
BEGIN
    SELECT RAISE(ABORT, 'il ritiro di un''associazione non si cancella');
END;

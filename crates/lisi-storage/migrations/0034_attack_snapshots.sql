-- La fotografia locale di MITRE ATT&CK: tecniche e tattiche, e nient'altro.
--
-- Motivata in ADR-0058 e DEC-293. Apre la Fase 8 lato archivio.
--
-- ===========================================================================
-- CHE COSA NON C'E' QUI DENTRO, E PERCHE'.
--
-- Il pacchetto ATT&CK Enterprise contiene anche 191 `intrusion-set`, 56
-- `campaign`, 733 `malware` e 95 `tool`: gruppi di attaccanti con i loro nomi,
-- le loro campagne e i loro strumenti.
--
-- NEXUM NON LI IMPORTA, e non esiste una tabella in cui metterli.
--
-- Le tecniche sono un vocabolario di COMPORTAMENTI: «esecuzione di comandi
-- tramite interprete» e' una descrizione, e nominarla non dice nulla su
-- nessuno. Un `intrusion-set` e' un ATTORE, con un nome e una storia di
-- attribuzioni fatte da qualcun altro. Importarlo metterebbe dentro questo
-- prodotto un vocabolario di attribuzione, e la mappatura di ATTACK-02 - che
-- deve dire «termine associato alla tecnica X» - avrebbe a un passo di
-- distanza il modo di dire «e la tecnica X e' del gruppo Y».
--
-- Cio' che non entra nell'archivio non puo' essere mostrato per errore.

-- ---------------------------------------------------------------------------
-- La fotografia.
--
-- `attribution` e `license_text` NON sono facoltativi, e non e' una scelta di
-- stile: la licenza di MITRE concede l'uso a condizione che ogni copia
-- riproduca la designazione di copyright e la licenza stessa. Un obbligo di
-- conformita' deve poter essere verificato, ed e' la stessa disciplina di
-- ADR-0005 per Slint.
--
-- Viaggiano DENTRO la riga e non accanto in un file, perche' un file accanto
-- e' un file che qualcuno puo' dimenticare di copiare.
CREATE TABLE attack_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Il dominio ATT&CK: 'enterprise-attack' oggi, e non se ne presume un altro.
    domain TEXT NOT NULL CHECK (length(trim(domain)) > 0),
    -- La versione di ATT&CK, per esempio '19.2'. NON e' la versione dei singoli
    -- oggetti, che ne hanno una propria: confonderle darebbe risposte sbagliate
    -- a chi chiede «di quando e' questo dato».
    attack_version TEXT NOT NULL CHECK (length(trim(attack_version)) > 0),
    -- La versione della specifica ATT&CK con cui il pacchetto e' scritto.
    spec_version TEXT NOT NULL CHECK (length(trim(spec_version)) > 0),
    -- L'impronta del file da cui la fotografia e' stata importata. E' cio' che
    -- permette di rispondere fra due anni a «con quali dati e' stato prodotto
    -- quel riferimento?».
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
    attribution TEXT NOT NULL CHECK (length(trim(attribution)) > 0),
    license_text TEXT NOT NULL CHECK (length(trim(license_text)) > 0),
    imported_by TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    technique_count INTEGER NOT NULL CHECK (technique_count >= 0),
    tactic_count INTEGER NOT NULL CHECK (tactic_count >= 0),
    -- LA STESSA VERSIONE NON SI IMPORTA DUE VOLTE.
    --
    -- Non e' un errore innocuo: due fotografie della stessa versione
    -- renderebbero ambiguo a quale delle due si riferisca un documento.
    UNIQUE (domain, attack_version)
);

-- ---------------------------------------------------------------------------
-- Le tattiche: quindici, e sono i capitoli sotto cui le tecniche stanno.
--
-- `shortname` e' la chiave con cui le tecniche le nominano dentro il pacchetto
-- (`privilege-escalation`), e non coincide con il nome leggibile
-- («Privilege Escalation») ne' con l'identificativo (`TA0004`). Si conservano
-- tutti e tre perche' servono a tre cose diverse: il primo per collegare, il
-- secondo per mostrare, il terzo per citare.
CREATE TABLE attack_tactics (
    snapshot_id INTEGER NOT NULL REFERENCES attack_snapshots (id) ON DELETE RESTRICT,
    tactic_id TEXT NOT NULL CHECK (length(trim(tactic_id)) > 0),
    shortname TEXT NOT NULL CHECK (length(trim(shortname)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    description TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, tactic_id)
);

CREATE UNIQUE INDEX attack_tactics_by_shortname
ON attack_tactics (snapshot_id, shortname);

-- ---------------------------------------------------------------------------
-- Le tecniche.
--
-- `deprecated` e `revoked` si CONSERVANO invece di far saltare la riga: ATT&CK
-- marca cio' che deprecò o revoco' invece di toglierlo, e un documento vecchio
-- che cita una tecnica poi deprecata deve restare leggibile. Mostrarla senza
-- dirlo sarebbe un difetto, e appartiene a chi la mostra.
--
-- `object_version` e' la versione dell'OGGETTO, non della fotografia.
CREATE TABLE attack_techniques (
    snapshot_id INTEGER NOT NULL REFERENCES attack_snapshots (id) ON DELETE RESTRICT,
    -- 'T1059' oppure 'T1059.001'.
    technique_id TEXT NOT NULL CHECK (length(trim(technique_id)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    -- Testo di terze parti, troncato a una misura dichiarata dal dominio e non
    -- interpretato: contiene Markdown e citazioni, e renderlo e' una decisione
    -- di chi lo mostra.
    description TEXT NOT NULL,
    -- Una sottotecnica ha la forma 'T1059.001' e un genitore che esiste nella
    -- stessa fotografia.
    is_subtechnique INTEGER NOT NULL CHECK (is_subtechnique IN (0, 1)),
    deprecated INTEGER NOT NULL CHECK (deprecated IN (0, 1)),
    revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
    object_version TEXT NOT NULL,
    -- L'indirizzo della pagina ufficiale. Si conserva perche' e' cio' che una
    -- persona apre per leggere la tecnica per esteso; NON viene aperto dal
    -- programma senza un gesto (ADR-0018).
    url TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, technique_id)
);

CREATE INDEX attack_techniques_by_snapshot
ON attack_techniques (snapshot_id, technique_id);

-- ---------------------------------------------------------------------------
-- A quali tattiche appartiene una tecnica.
--
-- Una tabella e non una colonna con un elenco dentro: un elenco in una colonna
-- e' un elenco che nessuna interrogazione sa interrogare, e prima o poi
-- qualcuno lo interroga. E' la stessa ragione della migrazione 0014.
--
-- Il riferimento e' allo `shortname`, che e' il modo in cui il pacchetto stesso
-- collega le due cose.
CREATE TABLE attack_technique_tactics (
    snapshot_id INTEGER NOT NULL REFERENCES attack_snapshots (id) ON DELETE RESTRICT,
    technique_id TEXT NOT NULL,
    tactic_shortname TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, technique_id, tactic_shortname),
    FOREIGN KEY (snapshot_id, technique_id)
    REFERENCES attack_techniques (snapshot_id, technique_id) ON DELETE RESTRICT,
    FOREIGN KEY (snapshot_id, tactic_shortname)
    REFERENCES attack_tactics (snapshot_id, shortname) ON DELETE RESTRICT
);

CREATE INDEX attack_technique_tactics_by_tactic
ON attack_technique_tactics (snapshot_id, tactic_shortname);

-- ---------------------------------------------------------------------------
-- Una fotografia non si modifica, e non si sovrascrive.
--
-- E' la stessa garanzia delle fotografie del contesto (migrazione 0025) e per
-- la stessa ragione: cio' che documenta un momento non deve poter cambiare
-- dopo. E cancellarla renderebbe illeggibile un documento che la cita.
--
-- DUE VERSIONI CONVIVONO. Importare la 20.0 non toglie la 19.2: un atto
-- prodotto sei mesi fa cita una tecnica come la conosceva QUELLA versione.
CREATE TRIGGER attack_snapshots_are_immutable
    BEFORE UPDATE ON attack_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia ATT&CK e'' immutabile');
END;

CREATE TRIGGER attack_snapshots_are_not_deleted
    BEFORE DELETE ON attack_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia ATT&CK non si cancella');
END;

CREATE TRIGGER attack_tactics_are_immutable
    BEFORE UPDATE ON attack_tactics
BEGIN
    SELECT RAISE(ABORT, 'una tattica di una fotografia ATT&CK e'' immutabile');
END;

CREATE TRIGGER attack_tactics_are_not_deleted
    BEFORE DELETE ON attack_tactics
BEGIN
    SELECT RAISE(ABORT, 'una tattica di una fotografia ATT&CK non si cancella');
END;

CREATE TRIGGER attack_techniques_are_immutable
    BEFORE UPDATE ON attack_techniques
BEGIN
    SELECT RAISE(ABORT, 'una tecnica di una fotografia ATT&CK e'' immutabile');
END;

CREATE TRIGGER attack_techniques_are_not_deleted
    BEFORE DELETE ON attack_techniques
BEGIN
    SELECT RAISE(ABORT, 'una tecnica di una fotografia ATT&CK non si cancella');
END;

CREATE TRIGGER attack_technique_tactics_are_immutable
    BEFORE UPDATE ON attack_technique_tactics
BEGIN
    SELECT RAISE(ABORT, 'l''appartenenza di una tecnica a una tattica e'' immutabile');
END;

CREATE TRIGGER attack_technique_tactics_are_not_deleted
    BEFORE DELETE ON attack_technique_tactics
BEGIN
    SELECT RAISE(ABORT, 'l''appartenenza di una tecnica a una tattica non si cancella');
END;

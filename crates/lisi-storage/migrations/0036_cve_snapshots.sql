-- La fotografia locale del catalogo CVE, e cio' che NON copre.
--
-- Motivata in ADR-0060 e DEC-295.
--
-- ===========================================================================
-- PERCHE' LA COPERTURA E' UNA TABELLA, E NON UN COMMENTO.
--
-- Ogni fotografia locale ha un confine. Il pericolo non e' il confine: e' non
-- dirlo. Un operatore che chiede che cosa sia `CVE-2026-1234` e riceve
-- «sconosciuta» conclude una cosa sola: che l'identificativo sia inventato.
--
-- La copertura sta qui dentro perche' la risoluzione possa distinguere «non lo
-- so» da «NVD non ha una CVE con questo numero». Una distinzione che vivesse in
-- un commento non arriverebbe a chi legge il risultato.
--
-- ===========================================================================
-- CHE COSA NON C'E' QUI DENTRO.
--
-- Il punteggio CVSS. Riprodurlo sarebbe lecito - la licenza lo consente - ma un
-- NUMERO SEMBRA OGGETTIVO, e questo prodotto mette i propri risultati accanto a
-- contenuti scritti da persone: un «9.8 CRITICAL» stampato di fianco a un
-- messaggio monitorato viene letto come «questo messaggio e' critico».
--
-- Non e' un no definitivo: e' un no PER ORA, con la sua ragione scritta.
-- Aggiungere una colonna dopo e' una migrazione; toglierla dopo che qualcuno
-- l'ha letta dentro un atto, no.
--
-- Restano fuori per proporzione anche le configurazioni CPE, le debolezze CWE e
-- l'elenco dei riferimenti: il prodotto deve RISOLVERE UN IDENTIFICATIVO, non
-- possedere l'inventario del software del mondo.

-- ---------------------------------------------------------------------------
-- La fotografia.
--
-- NON PORTA CONTEGGI.
--
-- Un conteggio scritto qui andrebbe aggiornato dopo aver inserito i record, e
-- una fotografia che si aggiorna non e' immutabile. I conteggi si contano.
CREATE TABLE cve_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Lo schema della fonte, per esempio 'NVD_CVE 2.0'.
    source TEXT NOT NULL CHECK (length(trim(source)) > 0),
    -- La designazione di copyright che ogni copia deve riprodurre.
    --
    -- La licenza CVE concede l'uso «provided that you reproduce MITRE's
    -- copyright designation and this license in any such copy». Un obbligo di
    -- conformita' deve poter essere verificato: viaggia DENTRO la riga, non
    -- accanto in un file che qualcuno puo' dimenticare di copiare.
    attribution TEXT NOT NULL CHECK (length(trim(attribution)) > 0),
    imported_by TEXT NOT NULL,
    imported_at INTEGER NOT NULL
);

-- ---------------------------------------------------------------------------
-- Che cosa questa fotografia copre.
--
-- Una riga per anno, con l'impronta che NVD dichiarava per quell'anno al
-- momento dell'acquisizione. NON e' un valore da riconfrontare per sempre: le
-- fotografie annuali di NVD sono file VIVI e cambiano nella notte. E'
-- l'identita' di CIO' CHE E' STATO ACQUISITO, in quel momento.
CREATE TABLE cve_snapshot_years (
    snapshot_id INTEGER NOT NULL REFERENCES cve_snapshots (id) ON DELETE RESTRICT,
    year INTEGER NOT NULL,
    -- La SHA-256 del file DECOMPRESSO, dichiarata dal `.meta` di NVD.
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
    -- L'istante che NVD dichiarava come ultima modifica di quell'anno, nella
    -- forma in cui lo scrive. Non e' un istante del dominio: vedere il commento
    -- di `cve_records`.
    source_last_modified TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, year)
);

-- ---------------------------------------------------------------------------
-- Le voci del catalogo.
--
-- LA DESCRIZIONE SI CONSERVA INTERA.
--
-- I termini di NVD dicono che «if you modify the content accessed through the
-- API, you may not attribute the source as the NVD». Troncare una descrizione e
-- continuare a dire «fonte: NVD» sarebbe attribuire a NVD un testo che NVD non
-- ha scritto. Il tetto esiste nel dominio e NON tronca: un record che lo supera
-- viene omesso con il proprio motivo.
--
-- GLI ISTANTI SONO TESTO, e non millisecondi come ovunque nel prodotto.
-- NVD li scrive SENZA FUSO ORARIO - `2026-06-16T22:01:26.443` - e trasformarli
-- in un istante richiederebbe sceglierne uno. Sceglierlo significherebbe
-- inventarlo, e in un prodotto che mette date accanto a fatti e' precisamente
-- cio' che non si fa.
CREATE TABLE cve_records (
    snapshot_id INTEGER NOT NULL REFERENCES cve_snapshots (id) ON DELETE RESTRICT,
    cve_id TEXT NOT NULL,
    description TEXT NOT NULL CHECK (length(trim(description)) > 0),
    published TEXT NOT NULL,
    last_modified TEXT NOT NULL,
    -- Lo stato dichiarato da NVD, riprodotto com'e'. NVD ne ha sette e puo'
    -- aggiungerne: rifiutare una fotografia perche' una voce porta un'etichetta
    -- nuova sarebbe una guardia che punisce la cosa sbagliata. Il prodotto ne
    -- riconosce esattamente uno, 'Rejected', perche' e' il solo che cambia il
    -- significato del record.
    status TEXT NOT NULL CHECK (length(trim(status)) > 0),
    PRIMARY KEY (snapshot_id, cve_id)
);

-- La domanda per cui la tabella esiste: «che cos'e' questo identificativo».
CREATE INDEX cve_records_by_id ON cve_records (cve_id);

-- ---------------------------------------------------------------------------
-- Una fotografia non si modifica, e non si sovrascrive.
--
-- Stessa garanzia delle fotografie del contesto e di quelle ATT&CK, e per la
-- stessa ragione: cio' che documenta un momento non deve poter cambiare dopo, e
-- cancellarlo renderebbe illeggibile un atto che lo cita.
CREATE TRIGGER cve_snapshots_are_immutable
    BEFORE UPDATE ON cve_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia CVE e'' immutabile');
END;

CREATE TRIGGER cve_snapshots_are_not_deleted
    BEFORE DELETE ON cve_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia CVE non si cancella');
END;

CREATE TRIGGER cve_snapshot_years_are_immutable
    BEFORE UPDATE ON cve_snapshot_years
BEGIN
    SELECT RAISE(ABORT, 'la copertura di una fotografia CVE e'' immutabile');
END;

CREATE TRIGGER cve_snapshot_years_are_not_deleted
    BEFORE DELETE ON cve_snapshot_years
BEGIN
    SELECT RAISE(ABORT, 'la copertura di una fotografia CVE non si cancella');
END;

CREATE TRIGGER cve_records_are_immutable
    BEFORE UPDATE ON cve_records
BEGIN
    SELECT RAISE(ABORT, 'una voce di una fotografia CVE e'' immutabile');
END;

CREATE TRIGGER cve_records_are_not_deleted
    BEFORE DELETE ON cve_records
BEGIN
    SELECT RAISE(ABORT, 'una voce di una fotografia CVE non si cancella');
END;

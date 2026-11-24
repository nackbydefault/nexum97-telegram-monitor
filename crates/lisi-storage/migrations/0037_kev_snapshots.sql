-- Il catalogo CISA KEV, e cio' che la sua assenza NON dice.
--
-- Motivata in ADR-0061 e DEC-296.
--
-- ===========================================================================
-- PERCHE' QUI NON C'E' UNA COPERTURA, A DIFFERENZA DELLA FOTOGRAFIA CVE.
--
-- La fotografia CVE ha una copertura PER ANNO, e quella tabella esiste perche'
-- permette di distinguere «non lo so» da «NVD non ha una CVE con questo
-- numero».
--
-- KEV non ha un confine per anno: contiene tutto lo spazio degli
-- identificativi, fino al momento del proprio rilascio. Da dentro la
-- fotografia, «CISA non l'ha mai elencata» e «CISA l'ha elencata dopo questo
-- rilascio» hanno ESATTAMENTE LO STESSO ASPETTO.
--
-- Il confine e' dunque UNO SOLO, ed e' il TEMPO: la versione del catalogo e
-- l'istante in cui CISA lo ha rilasciato. Stanno nella riga della fotografia
-- perche' l'esito negativo della risoluzione non e' raccontabile senza.
--
-- ===========================================================================
-- CHE COSA NON C'E' QUI DENTRO.
--
-- `requiredAction`, `dueDate` e `forensicTriage`. NON SONO FATTI SULLA
-- VULNERABILITA': sono un ORDINE rivolto a qualcun altro - le agenzie federali
-- civili statunitensi, per una direttiva operativa vincolante.
--
-- Mostrarli senza dirlo suggerirebbe un obbligo che non esiste. Mostrarli
-- dicendolo richiederebbe un'avvertenza che viaggi per sempre, in ogni
-- schermata e in ogni rapporto, e un'avvertenza che deve viaggiare per sempre
-- prima o poi resta indietro.
--
-- Non entrano, e NON ESISTE UNA COLONNA IN CUI METTERLI: cio' che non entra non
-- puo' essere mostrato per errore. Aggiungere una colonna dopo e' una
-- migrazione; toglierla dopo che qualcuno l'ha letta dentro un atto, no.
--
-- Restano fuori per proporzione anche `cwes` e `notes`.

-- ---------------------------------------------------------------------------
-- La fotografia.
--
-- PERCHE' QUI CI SONO DEI CONTEGGI, A DIFFERENZA DELLA FOTOGRAFIA CVE.
--
-- Nella fotografia CVE un conteggio scritto nella riga andrebbe aggiornato dopo
-- aver inserito le voci, e una fotografia che si aggiorna non e' immutabile.
--
-- Qui la riga e le voci si scrivono NELLA STESSA TRANSAZIONE - il catalogo ha
-- millesettecento voci, non centomila - e i conteggi sono noti PRIMA di
-- scrivere. Non si aggiornano mai, e rendono la completezza VERIFICABILE:
--
--   expected_entries + omitted_count = declared_count
--
-- ed e' un CHECK, non una speranza. Serve perche' una fotografia incompleta
-- risponderebbe «non elencata» a una domanda a cui CISA risponde di si', ed e'
-- l'unica risposta che questa fotografia non deve mai sbagliare.
--
-- `declared_count` NON e' un conteggio nostro: e' il numero che IL CATALOGO
-- DICHIARA DI SE', ed e' l'unica integrita' che la fonte offre.
CREATE TABLE kev_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- La versione dichiarata dal catalogo, per esempio '2026.09.10'.
    catalog_version TEXT NOT NULL CHECK (length(trim(catalog_version)) > 0),
    -- L'istante di rilascio, NELLA FORMA IN CUI LA FONTE LO SCRIVE. Non e' un
    -- istante del dominio: interpretarlo richiederebbe di inventare cio' che
    -- manca, ed e' la stessa ragione di `cve_records`.
    date_released TEXT NOT NULL CHECK (length(trim(date_released)) > 0),
    -- Quante voci il catalogo dichiara di avere.
    declared_count INTEGER NOT NULL CHECK (declared_count >= 0),
    -- Quante voci sono state ACCETTATE, e quante lasciate fuori con il proprio
    -- motivo. Note prima di scrivere, scritte insieme alle voci, mai aggiornate.
    expected_entries INTEGER NOT NULL CHECK (expected_entries >= 0),
    omitted_count INTEGER NOT NULL CHECK (omitted_count >= 0),
    -- L'impronta di CIO' CHE E' STATO ACQUISITO.
    --
    -- ATTENZIONE, E NON E' UNA FORMALITA': QUESTA IMPRONTA NON VIENE DALLA
    -- FONTE. CISA non ne pubblica alcuna - la pagina dei download offre CSV,
    -- JSON, schema, vista di stampa e licenza, nient'altro.
    --
    -- L'ha calcolata scripts/fetch-kev.ps1 al momento dell'acquisizione, e dice
    -- UNA COSA SOLA: che il file non e' cambiato da quando e' stato preso. Non
    -- dice che sia quello che CISA ha pubblicato. La colonna si chiama
    -- `acquired_sha256` e non `source_sha256` proprio per questo.
    acquired_sha256 TEXT NOT NULL CHECK (length(acquired_sha256) = 64),
    -- La fonte, registrata perche' la frase che il prodotto compone deve poter
    -- nominare CHI AFFERMA. La licenza e' CC0 e non lo richiederebbe: qui
    -- l'attribuzione serve alla verita' della frase, non alla licenza.
    attribution TEXT NOT NULL CHECK (length(trim(attribution)) > 0),
    imported_by TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    -- OGNI VOCE DEL CATALOGO O E' ENTRATA O E' STATA OMESSA CON IL PROPRIO
    -- MOTIVO. Una fotografia che non torna non e' rappresentabile.
    CHECK (expected_entries + omitted_count = declared_count)
);

-- ---------------------------------------------------------------------------
-- Le voci del catalogo.
--
-- LA DESCRIZIONE SI CONSERVA INTERA: troncarla cambierebbe cio' che CISA ha
-- scritto, e la frase che il prodotto compone attribuisce quel testo a CISA.
--
-- `ransomware_use` CONSERVA LA DICHIARAZIONE COM'E', e non e' un booleano.
-- 'Unknown' significa «CISA NON LO SA», non «non e' avvenuto»: un booleano
-- trasformerebbe un'ignoranza dichiarata in una constatazione negativa.
CREATE TABLE kev_entries (
    snapshot_id INTEGER NOT NULL REFERENCES kev_snapshots (id) ON DELETE RESTRICT,
    cve_id TEXT NOT NULL,
    vendor_project TEXT NOT NULL CHECK (length(trim(vendor_project)) > 0),
    product TEXT NOT NULL CHECK (length(trim(product)) > 0),
    vulnerability_name TEXT NOT NULL CHECK (length(trim(vulnerability_name)) > 0),
    date_added TEXT NOT NULL CHECK (length(trim(date_added)) > 0),
    short_description TEXT NOT NULL CHECK (length(trim(short_description)) > 0),
    ransomware_use TEXT NOT NULL CHECK (length(trim(ransomware_use)) > 0),
    PRIMARY KEY (snapshot_id, cve_id)
);

-- La domanda per cui la tabella esiste: «CISA elenca questo identificativo».
CREATE INDEX kev_entries_by_cve ON kev_entries (cve_id);

-- ---------------------------------------------------------------------------
-- Una fotografia non si modifica, e non si sovrascrive.
--
-- Stessa garanzia delle fotografie del contesto, di ATT&CK e di CVE, e per la
-- stessa ragione: cio' che documenta un momento non deve poter cambiare dopo, e
-- cancellarlo renderebbe illeggibile un atto che lo cita.
CREATE TRIGGER kev_snapshots_are_immutable
    BEFORE UPDATE ON kev_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia KEV e'' immutabile');
END;

CREATE TRIGGER kev_snapshots_are_not_deleted
    BEFORE DELETE ON kev_snapshots
BEGIN
    SELECT RAISE(ABORT, 'una fotografia KEV non si cancella');
END;

CREATE TRIGGER kev_entries_are_immutable
    BEFORE UPDATE ON kev_entries
BEGIN
    SELECT RAISE(ABORT, 'una voce di una fotografia KEV e'' immutabile');
END;

CREATE TRIGGER kev_entries_are_not_deleted
    BEFORE DELETE ON kev_entries
BEGIN
    SELECT RAISE(ABORT, 'una voce di una fotografia KEV non si cancella');
END;

-- Pacchetti di report, artefatti e fotografia dei dati che li hanno prodotti.
--
-- Motivata in ADR-0031 e DEC-153. Apre la Milestone 18.
--
-- ===========================================================================
-- PERCHE' NON SI ESTENDE `exports`.
--
-- La tabella `exports` esiste dalla migrazione 0001 e ha due limiti che qui
-- diventano bloccanti:
--
--   1. `CHECK (format IN ('pdf', 'txt', 'xlsx'))` — non ammette 'docx';
--   2. una riga per file e **nessun identificativo di pacchetto** — non c'e'
--      modo di dire che cinque file appartengono alla stessa generazione.
--
-- Un `CHECK` in SQLite non si modifica con `ALTER TABLE`: si riscrive la
-- tabella. Riscrivere `exports` significherebbe toccare una struttura che
-- contiene gia' i rapporti prodotti dall'ufficio, per aggiungerle un concetto
-- — il pacchetto — che non le appartiene: `exports` registra **un file**,
-- questa milestone produce **un insieme di file con una fotografia dei dati che
-- li ha generati**.
--
-- `exports` percio' RESTA COM'E' e continua a registrare il TXT prodotto dallo
-- Storico. Il reporting professionale vive nelle tabelle nuove qui sotto. Le
-- due strade coesistono finche' l'ufficio non decide di abbandonare la prima,
-- e quel giorno sara' una decisione dichiarata, non un effetto collaterale di
-- una migrazione.

-- ---------------------------------------------------------------------------
-- Il pacchetto.
--
-- `report_id` e' l'identificativo CITABILE, quello che compare dentro i
-- documenti (forma `R-<anno>-<progressivo a sei cifre>`). E' distinto da `id`,
-- che e' l'identificatore della riga: il primo lo legge una persona, il secondo
-- lo usa il database, e confonderli produrrebbe documenti che citano un numero
-- che nessuno ritrova.
CREATE TABLE report_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL UNIQUE,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE RESTRICT,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('prepared', 'generating', 'completed', 'failed')
    ),
    -- Versione del profilo di template che ha prodotto i documenti. Senza,
    -- un template modificato renderebbe inspiegabile un report vecchio.
    template_version INTEGER NOT NULL,
    requested_at INTEGER NOT NULL,
    -- Valorizzato solo quando il pacchetto e' completo. Un pacchetto senza
    -- questo istante e con stato diverso da 'completed' e' un pacchetto che
    -- non si consegna.
    completed_at INTEGER,
    CHECK (
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status <> 'completed' AND completed_at IS NULL)
    )
);

CREATE INDEX report_packages_by_session ON report_packages (session_id, requested_at);

-- ---------------------------------------------------------------------------
-- Gli artefatti prodotti dentro un pacchetto.
--
-- `kind` e' il GENERE del documento, non il formato: 'relazione_pdf' e
-- 'allegato_tecnico_pdf' sono due PDF e due documenti diversi, e distinguerli
-- qui evita di dover indovinare dal nome del file quale sia quale.
--
-- L'insieme e' chiuso da un CHECK e corrisponde a `ReportArtifactKind` nel
-- dominio. Aggiungere un genere richiede una migrazione: e' voluto — un
-- artefatto che il dominio conosce e il database no produrrebbe un pacchetto
-- che non si riesce a rileggere.
CREATE TABLE report_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL REFERENCES report_packages (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (
        kind IN (
            'relazione_docx', 'relazione_pdf', 'allegato_tecnico_pdf',
            'registro_xlsx', 'rapporto_txt', 'manifest_txt'
        )
    ),
    file_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    created_at INTEGER NOT NULL,
    -- Un pacchetto non contiene due volte lo stesso genere di documento.
    UNIQUE (package_id, kind)
);

CREATE INDEX report_artifacts_by_package ON report_artifacts (package_id);

-- ---------------------------------------------------------------------------
-- La fotografia: come stava ogni contenuto al momento della generazione.
--
-- E' cio' che permette di rispondere fra sei mesi alla domanda «con quali dati
-- e' stato prodotto quel documento?», quando gli stati di revisione saranno
-- cambiati e i dizionari aggiornati.
--
-- NON E' UNA COPIA DEI CONTENUTI. Si conserva l'impronta del corpo, non il
-- corpo: duplicare i testi monitorati moltiplicherebbe i luoghi da proteggere
-- (THREAT_MODEL_REPORTING, R-03 e R-06).
--
-- Il prezzo, dichiarato: se un contenuto venisse cancellato dall'archivio, da
-- qui si sapra' che c'era, con quale livello, con quale stato di revisione e
-- con quale impronta — non che cosa diceva.
CREATE TABLE report_content_snapshots (
    package_id INTEGER NOT NULL REFERENCES report_packages (id) ON DELETE CASCADE,
    -- Intero grezzo e non foreign key: la fotografia deve sopravvivere alla
    -- cancellazione di cio' che descrive, come gia' fa l'audit.
    content_id INTEGER NOT NULL,
    analysis_level INTEGER NOT NULL CHECK (analysis_level BETWEEN 0 AND 4),
    -- Stato della revisione al momento della generazione, quando ce n'era una.
    review_state TEXT CHECK (
        review_state IS NULL OR review_state IN (
            'new', 'in_review', 'relevant', 'not_relevant',
            'duplicate', 'archived', 'reported'
        )
    ),
    body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64),
    -- Se l'operatore ha scelto di rappresentare questo contenuto nella
    -- relazione. E' la selezione, persistita: senza, non si potrebbe piu' dire
    -- se un elemento e' stato escluso o non e' mai esistito.
    selected INTEGER NOT NULL CHECK (selected IN (0, 1)),
    PRIMARY KEY (package_id, content_id)
);

CREATE INDEX report_content_snapshots_selected
ON report_content_snapshots (package_id, selected);

-- ---------------------------------------------------------------------------
-- Le fonti e le versioni di dizionario in vigore al momento della generazione.
--
-- Due tabelle piccole invece di due colonne con un elenco dentro: un elenco in
-- una colonna e' un elenco che nessuna query sa interrogare, e prima o poi
-- qualcuno lo interroga.
CREATE TABLE report_snapshot_sources (
    package_id INTEGER NOT NULL REFERENCES report_packages (id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL,
    PRIMARY KEY (package_id, source_id)
);

CREATE TABLE report_snapshot_dictionary_versions (
    package_id INTEGER NOT NULL REFERENCES report_packages (id) ON DELETE CASCADE,
    dictionary_version_id INTEGER NOT NULL,
    PRIMARY KEY (package_id, dictionary_version_id)
);

-- ---------------------------------------------------------------------------
-- Append-only sulla fotografia, realizzato dal motore.
--
-- Una fotografia che si potesse modificare non sarebbe una fotografia: il suo
-- unico mestiere e' dire come stavano le cose allora, e un aggiornamento
-- successivo lo distruggerebbe in silenzio.
--
-- Come per l'audit (migrazione 0001), la garanzia vale contro l'applicazione,
-- non contro chi abbia accesso diretto al file con strumenti esterni. Il
-- rischio residuo e' dichiarato in THREAT_MODEL_REPORTING, R-07.
CREATE TRIGGER report_content_snapshots_refuse_update
BEFORE UPDATE ON report_content_snapshots
BEGIN
SELECT RAISE(ABORT, 'fotografia del report append-only: la modifica non e'' ammessa');
END;

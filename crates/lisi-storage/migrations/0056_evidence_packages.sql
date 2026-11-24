-- PR-11, ADR-0127: il registro dei pacchetti di evidenze.
--
-- IN SOLA AGGIUNTA. Risponde a «che cosa e' uscito da qui, e quando» (HVQ-60):
-- quale pacchetto, da quale workspace, chi, perche', quando, quanti contenuti,
-- e l'impronta del manifest che lo chiude. Le righe non si modificano e non si
-- cancellano: un pacchetto consegnato non si ritira, e il registro non finge
-- che si possa.
--
-- Nessun testo dei contenuti sta qui: il pacchetto lo porta con se', e
-- l'archivio lo conserva gia'.
CREATE TABLE evidence_packages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- L'identificativo del pacchetto, che e' anche il nome della sua cartella:
    -- «PE-» e l'istante UTC in cifre, e nient'altro.
    package_ref     TEXT NOT NULL UNIQUE CHECK (
        length(package_ref) = 18 AND package_ref GLOB 'PE-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]'
    ),
    workspace_id    INTEGER NOT NULL REFERENCES workspaces (id) ON DELETE RESTRICT,
    produced_by     TEXT NOT NULL CHECK (length(trim(produced_by)) > 0),
    reason          TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    produced_at     INTEGER NOT NULL,
    contents_count  INTEGER NOT NULL CHECK (contents_count BETWEEN 1 AND 500),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64)
);

CREATE INDEX evidence_packages_by_workspace ON evidence_packages (workspace_id, produced_at);

CREATE TRIGGER evidence_packages_are_immutable
    BEFORE UPDATE ON evidence_packages
BEGIN
    SELECT RAISE(ABORT, 'un pacchetto di evidenze registrato e'' immutabile');
END;

CREATE TRIGGER evidence_packages_are_not_deleted
    BEFORE DELETE ON evidence_packages
BEGIN
    SELECT RAISE(ABORT, 'un pacchetto di evidenze consegnato non si cancella dal registro');
END;

-- Migrazione 0057 - lo stato di «Scopri NEXUM», il tour guidato (TOUR-01,
-- ADR-0134, DEC-378).
--
-- =============================================================================
-- CHE COSA E', E CHE COSA NON E'
-- =============================================================================
--
-- Una PREFERENZA DI INTERFACCIA: se il tour e' stato proposto, saltato,
-- interrotto a un passo, completato. Non e' una prova, non e' un contenuto,
-- non e' un atto: non entra nell'audit, non porta un attore, non porta testo
-- libero. Nessun segreto puo' finire qui, perche' nessuna colonna lo
-- ammetterebbe.
--
-- =============================================================================
-- PERCHE' UNA RIGA SOLA, E PERCHE' L'ASSENZA CONTA
-- =============================================================================
--
-- Come per il profilo documentale (migrazione 0015): `CHECK (id = 1)` rende
-- impossibile una seconda riga, e **l'assenza della riga e' un'informazione**:
-- il tour non e' MAI stato proposto. Una riga predefinita la cancellerebbe.
--
-- =============================================================================
-- PERCHE' IL PASSO E' UNA CHIAVE E NON UN NUMERO
-- =============================================================================
--
-- Un numero si sposta il giorno in cui si aggiunge un passo, e chi aveva
-- interrotto al quinto si ritroverebbe al quinto di un altro elenco. La
-- chiave (`fonti`, `storico`...) resta. Una chiave che non esiste piu' fa
-- ricominciare il tour dall'inizio: lo decide il servizio, non lo schema.
--
-- =============================================================================
-- LE CONFIGURAZIONI CHE ESISTEVANO GIA'
-- =============================================================================
--
-- Un aggiornamento del prodotto non deve diventare un tour obbligatorio. Su un
-- archivio dove la domanda del primo avvio ha gia' una risposta (esiste la
-- riga di `report_profile`), la riga si scrive QUI come 'proposto': nessuna
-- finestra si apre da sola, e accanto alla voce compare «Nuovo». Su un
-- archivio nuovo `report_profile` e' vuota, la riga non si scrive, e il tour
-- si proporra' dopo la prima risposta.
--
-- Nessun dato esistente viene letto oltre l'esistenza di quella riga, e
-- nessuno viene riscritto.

CREATE TABLE tour_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),

    -- 'proposto' | 'saltato' | 'in_corso' | 'completato'.
    state TEXT NOT NULL
        CHECK (state IN ('proposto', 'saltato', 'in_corso', 'completato')),

    -- La versione del tour a cui lo stato si riferisce.
    tour_version INTEGER NOT NULL CHECK (tour_version >= 1),

    -- La chiave dell'ultimo passo raggiunto. Solo per un tour in corso: una
    -- chiave e' fatta di lettere minuscole e trattini bassi, e non e' mai
    -- testo libero.
    last_step TEXT
        CHECK (last_step IS NULL OR (
            length(last_step) BETWEEN 1 AND 64
            AND last_step NOT GLOB '*[^a-z_]*'
        )),

    -- L'ultima versione del tour completata per intero, se c'e'.
    completed_version INTEGER CHECK (completed_version IS NULL OR completed_version >= 1),

    updated_at INTEGER NOT NULL,

    CHECK (state = 'in_corso' OR last_step IS NULL),
    CHECK (state <> 'completato' OR completed_version IS NOT NULL)
);

INSERT INTO tour_state (id, state, tour_version, last_step, completed_version, updated_at)
SELECT 1, 'proposto', 1, NULL, NULL, 0
WHERE EXISTS (SELECT 1 FROM report_profile);
